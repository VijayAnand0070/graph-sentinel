"""Durable record of every response dispatch, and the approvals still waiting.

Two implementations with one contract: in-memory for tests and ephemeral
deployments, SQLite (WAL) for anything that must survive a restart. The record
is the executor's :class:`ExecutionRecord`, stored as JSON with the fields the
coordinator needs on reload -- the target, so an approval can be dispatched
against exactly what was planned, and the idempotency key, so a restart does
not re-fire an action that already ran.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from threading import RLock
from typing import Protocol, cast

from graphsentinel.response.connectors import Command, Target
from graphsentinel.response.executor import ExecutionRecord, Outcome

#: Outcomes that mean "this action was carried out or planned"; a later
#: dispatch of the same key is a duplicate.
SETTLED: frozenset[Outcome] = frozenset({"dry_run", "executed"})
#: Reverts are recorded against the original (alert, action) key.
REVERTED: frozenset[Outcome] = frozenset({"reverted"})


def _serialise(record: ExecutionRecord) -> str:
    target = record.target
    return json.dumps(
        {
            **record.to_dict(),
            "target_fields": {
                "account": target.account,
                "host": target.host,
                "source_host": target.source_host,
                "destination_host": target.destination_host,
            },
        }
    )


def _command_from(payload: dict[str, object] | None) -> Command | None:
    if not payload:
        return None
    revert = payload.get("revert")
    return Command(
        kind=str(payload["kind"]),  # type: ignore[arg-type]
        text=str(payload["text"]),
        description=str(payload["description"]),
        revert=_command_from(revert) if isinstance(revert, dict) else None,
        limitations=tuple(str(x) for x in cast("list[object]", payload.get("limitations") or [])),
    )


def _deserialise(text: str) -> ExecutionRecord:
    payload = json.loads(text)
    fields = payload["target_fields"]
    return ExecutionRecord(
        alert_id=payload["alert_id"],
        action=payload["action"],
        target=Target(
            account=fields.get("account"),
            host=fields.get("host"),
            source_host=fields.get("source_host"),
            destination_host=fields.get("destination_host"),
        ),
        outcome=payload["outcome"],
        reversible=bool(payload["reversible"]),
        requires_approval=bool(payload["requires_approval"]),
        approved_by=payload.get("approved_by"),
        command=_command_from(payload.get("command")),
        output=payload.get("output", ""),
        error=payload.get("error", ""),
        timestamp=int(payload["timestamp"]),
        authority=payload.get("authority", "plan"),
    )


class ResponseStore(Protocol):
    def append(self, record: ExecutionRecord) -> None: ...

    def records(
        self, *, limit: int = 200, alert_id: str | None = None
    ) -> list[ExecutionRecord]: ...

    def all_records(self) -> Iterable[ExecutionRecord]: ...


class MemoryResponseStore:
    def __init__(self) -> None:
        self._records: list[ExecutionRecord] = []
        self._lock = RLock()

    def append(self, record: ExecutionRecord) -> None:
        with self._lock:
            self._records.append(record)

    def records(self, *, limit: int = 200, alert_id: str | None = None) -> list[ExecutionRecord]:
        with self._lock:
            selected = [r for r in self._records if alert_id is None or r.alert_id == alert_id]
        return list(reversed(selected))[:limit]

    def all_records(self) -> Iterable[ExecutionRecord]:
        with self._lock:
            return list(self._records)


class SQLiteResponseStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = RLock()
        self._connection = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA busy_timeout=30000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS response_executions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                outcome TEXT NOT NULL,
                recorded_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_response_exec_alert
                ON response_executions (alert_id, sequence DESC);
            CREATE INDEX IF NOT EXISTS idx_response_exec_time
                ON response_executions (recorded_at DESC);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def append(self, record: ExecutionRecord) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO response_executions(alert_id,action,outcome,recorded_at,payload_json) "
                "VALUES (?,?,?,?,?)",
                (
                    record.alert_id,
                    record.action,
                    record.outcome,
                    record.timestamp,
                    _serialise(record),
                ),
            )

    def records(self, *, limit: int = 200, alert_id: str | None = None) -> list[ExecutionRecord]:
        with self._lock:
            if alert_id is None:
                rows = self._connection.execute(
                    "SELECT payload_json FROM response_executions ORDER BY sequence DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT payload_json FROM response_executions WHERE alert_id=? "
                    "ORDER BY sequence DESC LIMIT ?",
                    (alert_id, limit),
                ).fetchall()
        return [_deserialise(row["payload_json"]) for row in rows]

    def all_records(self) -> Iterable[ExecutionRecord]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM response_executions ORDER BY sequence ASC"
            ).fetchall()
        return [_deserialise(row["payload_json"]) for row in rows]
