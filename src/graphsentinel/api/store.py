"""Thread-safe in-memory repository behind the academic service boundary."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from threading import RLock
from typing import Protocol

from graphsentinel.api.schemas import (
    AlertRecord,
    CaseNote,
    CaseRecord,
    PlaybookExecutionRecord,
    PlaybookStepEntry,
)
from graphsentinel.detection.path_ranker import SuspiciousPath
from graphsentinel.detection.playbooks import PlaybookExecution
from graphsentinel.explain.schemas import TriageReport

_VALID_CASE_STATUSES = {"open", "investigating", "closed"}


def _execution_record(execution_id: str, execution: PlaybookExecution) -> PlaybookExecutionRecord:
    return PlaybookExecutionRecord(
        execution_id=execution_id,
        playbook_name=execution.playbook_name,
        entity=execution.entity,
        entity_kind=execution.entity_kind,
        risk_at_trigger=execution.risk_at_trigger,
        steps=tuple(
            PlaybookStepEntry(action=s.action, status=s.status, detail=s.detail)
            for s in execution.steps
        ),
        triggered_at=execution.triggered_at,
    )


class AlertRepository(Protocol):
    def commit_detection_batch(
        self,
        *,
        scored_count: int,
        alerts: list[AlertRecord],
        paths: list[SuspiciousPath],
    ) -> None: ...

    def list_alerts(
        self, *, minimum_risk: float = 0.0, limit: int = 100
    ) -> tuple[AlertRecord, ...]: ...

    def get_alert(self, alert_id: str) -> AlertRecord | None: ...

    def attach_triage(self, alert_id: str, triage: TriageReport) -> AlertRecord: ...

    def update_status(self, alert_id: str, status: str) -> AlertRecord: ...

    def get_path(self, path_id: str) -> SuspiciousPath | None: ...

    def list_paths(self, *, limit: int = 100) -> tuple[SuspiciousPath, ...]: ...

    def metrics(self) -> dict[str, int | float]: ...


class AlertStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._alerts: dict[str, AlertRecord] = {}
        self._event_to_alert: dict[int, str] = {}
        self._paths: dict[str, SuspiciousPath] = {}
        self._scored_events = 0

    def note_scored(self, count: int = 1) -> None:
        if count < 0:
            raise ValueError("count cannot be negative")
        with self._lock:
            self._scored_events += count

    def put_alert(self, alert: AlertRecord) -> None:
        with self._lock:
            if alert.alert_id in self._alerts or alert.event_id in self._event_to_alert:
                raise ValueError("alert or event already exists")
            self._alerts[alert.alert_id] = alert
            self._event_to_alert[alert.event_id] = alert.alert_id

    def commit_detection_batch(
        self,
        *,
        scored_count: int,
        alerts: list[AlertRecord],
        paths: list[SuspiciousPath],
    ) -> None:
        """Validate and publish one detection result atomically under the repository lock."""

        if scored_count < 0:
            raise ValueError("scored_count cannot be negative")
        alert_ids = [alert.alert_id for alert in alerts]
        event_ids = [alert.event_id for alert in alerts]
        if len(alert_ids) != len(set(alert_ids)) or len(event_ids) != len(set(event_ids)):
            raise ValueError("batch contains duplicate alert or event IDs")
        with self._lock:
            if any(alert_id in self._alerts for alert_id in alert_ids) or any(
                event_id in self._event_to_alert for event_id in event_ids
            ):
                raise ValueError("alert or event already exists")
            self._scored_events += scored_count
            for alert in alerts:
                self._alerts[alert.alert_id] = alert
                self._event_to_alert[alert.event_id] = alert.alert_id
            for path in paths:
                self._paths[path.path_id] = path

    def list_alerts(
        self, *, minimum_risk: float = 0.0, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        with self._lock:
            selected = [alert for alert in self._alerts.values() if alert.risk >= minimum_risk]
            return tuple(sorted(selected, key=lambda alert: (-alert.risk, alert.timestamp))[:limit])

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        with self._lock:
            return self._alerts.get(alert_id)

    def attach_triage(self, alert_id: str, triage: TriageReport) -> AlertRecord:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise KeyError(alert_id)
            updated = alert.model_copy(update={"triage": triage})
            self._alerts[alert_id] = updated
            return updated

    def update_status(self, alert_id: str, status: str) -> AlertRecord:
        if status not in {"new", "reviewed", "closed"}:
            raise ValueError("invalid alert status")
        with self._lock:
            alert = self._alerts.get(alert_id)
            if alert is None:
                raise KeyError(alert_id)
            updated = alert.model_copy(update={"status": status})
            self._alerts[alert_id] = updated
            return updated

    def put_paths(self, paths: list[SuspiciousPath]) -> None:
        with self._lock:
            for path in paths:
                self._paths[path.path_id] = path

    def get_path(self, path_id: str) -> SuspiciousPath | None:
        with self._lock:
            return self._paths.get(path_id)

    def list_paths(self, *, limit: int = 100) -> tuple[SuspiciousPath, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            return tuple(
                sorted(
                    self._paths.values(),
                    key=lambda path: (-path.score, path.timestamps, path.event_ids),
                )[:limit]
            )

    def metrics(self) -> dict[str, int | float]:
        with self._lock:
            alert_count = len(self._alerts)
            return {
                "scored_events": self._scored_events,
                "alerts": alert_count,
                "paths": len(self._paths),
                "alert_rate": alert_count / self._scored_events if self._scored_events else 0.0,
            }


class SQLiteAlertStore:
    """Durable single-node repository with atomic batches and WAL journaling."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._lock = RLock()
        self._connection = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None, timeout=30
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._connection.execute("PRAGMA busy_timeout=30000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                event_id INTEGER NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                risk REAL NOT NULL CHECK (risk >= 0 AND risk <= 1),
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_risk_time
                ON alerts (risk DESC, timestamp ASC);
            CREATE TABLE IF NOT EXISTS paths (
                path_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS counters (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK (value >= 0)
            );
            INSERT OR IGNORE INTO counters (key, value) VALUES ('scored_events', 0);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def commit_detection_batch(
        self,
        *,
        scored_count: int,
        alerts: list[AlertRecord],
        paths: list[SuspiciousPath],
    ) -> None:
        if scored_count < 0:
            raise ValueError("scored_count cannot be negative")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.executemany(
                    "INSERT INTO alerts(alert_id,event_id,timestamp,risk,payload_json) "
                    "VALUES(?,?,?,?,?)",
                    [
                        (
                            alert.alert_id,
                            alert.event_id,
                            alert.timestamp,
                            alert.risk,
                            alert.model_dump_json(),
                        )
                        for alert in alerts
                    ],
                )
                self._connection.executemany(
                    "INSERT INTO paths(path_id,payload_json) VALUES(?,?) "
                    "ON CONFLICT(path_id) DO UPDATE SET payload_json=excluded.payload_json",
                    [(path.path_id, json.dumps(path.to_dict(), sort_keys=True)) for path in paths],
                )
                self._connection.execute(
                    "UPDATE counters SET value=value+? WHERE key='scored_events'",
                    (scored_count,),
                )
                self._connection.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                self._connection.execute("ROLLBACK")
                raise ValueError("alert or event already exists") from error
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def list_alerts(
        self, *, minimum_risk: float = 0.0, limit: int = 100
    ) -> tuple[AlertRecord, ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM alerts WHERE risk>=? "
                "ORDER BY risk DESC,timestamp ASC LIMIT ?",
                (minimum_risk, limit),
            ).fetchall()
        return tuple(AlertRecord.model_validate_json(row["payload_json"]) for row in rows)

    def get_alert(self, alert_id: str) -> AlertRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return AlertRecord.model_validate_json(row["payload_json"]) if row else None

    def attach_triage(self, alert_id: str, triage: TriageReport) -> AlertRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT payload_json FROM alerts WHERE alert_id=?", (alert_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(alert_id)
                alert = AlertRecord.model_validate_json(row["payload_json"])
                updated = alert.model_copy(update={"triage": triage})
                self._connection.execute(
                    "UPDATE alerts SET payload_json=? WHERE alert_id=?",
                    (updated.model_dump_json(), alert_id),
                )
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def update_status(self, alert_id: str, status: str) -> AlertRecord:
        if status not in {"new", "reviewed", "closed"}:
            raise ValueError("invalid alert status")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT payload_json FROM alerts WHERE alert_id=?", (alert_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(alert_id)
                alert = AlertRecord.model_validate_json(row["payload_json"])
                updated = alert.model_copy(update={"status": status})
                self._connection.execute(
                    "UPDATE alerts SET payload_json=? WHERE alert_id=?",
                    (updated.model_dump_json(), alert_id),
                )
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get_path(self, path_id: str) -> SuspiciousPath | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT payload_json FROM paths WHERE path_id=?", (path_id,)
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        for field in ("event_ids", "host_ids", "user_ids", "timestamps"):
            payload[field] = tuple(payload[field])
        return SuspiciousPath(**payload)

    def list_paths(self, *, limit: int = 100) -> tuple[SuspiciousPath, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM paths LIMIT ?", (limit,)
            ).fetchall()
        paths: list[SuspiciousPath] = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            for field in ("event_ids", "host_ids", "user_ids", "timestamps"):
                payload[field] = tuple(payload[field])
            paths.append(SuspiciousPath(**payload))
        return tuple(sorted(paths, key=lambda path: (-path.score, path.timestamps, path.event_ids)))

    def metrics(self) -> dict[str, int | float]:
        with self._lock:
            scored = int(
                self._connection.execute(
                    "SELECT value FROM counters WHERE key='scored_events'"
                ).fetchone()["value"]
            )
            alerts = int(
                self._connection.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
            )
            paths = int(self._connection.execute("SELECT COUNT(*) AS n FROM paths").fetchone()["n"])
        return {
            "scored_events": scored,
            "alerts": alerts,
            "paths": paths,
            "alert_rate": alerts / scored if scored else 0.0,
        }


class CaseStore:
    """In-memory analyst case tracker — groups alerts into a durable investigation record."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._cases: dict[str, CaseRecord] = {}
        self._next_id = 1

    def create_case(self, *, title: str, alert_ids: tuple[str, ...], now: int) -> CaseRecord:
        with self._lock:
            case_id = f"CASE-{self._next_id:08d}"
            self._next_id += 1
            case = CaseRecord(
                case_id=case_id, title=title, alert_ids=alert_ids, created_at=now, updated_at=now
            )
            self._cases[case_id] = case
            return case

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self._lock:
            return self._cases.get(case_id)

    def list_cases(self, *, status: str | None = None, limit: int = 100) -> tuple[CaseRecord, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            selected = [c for c in self._cases.values() if status is None or c.status == status]
            return tuple(sorted(selected, key=lambda c: -c.updated_at)[:limit])

    def update_status(
        self, case_id: str, status: str, *, closed_reason: str | None, now: int
    ) -> CaseRecord:
        if status not in _VALID_CASE_STATUSES:
            raise ValueError("invalid case status")
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise KeyError(case_id)
            updated = case.model_copy(
                update={
                    "status": status,
                    "closed_reason": closed_reason if status == "closed" else None,
                    "updated_at": now,
                }
            )
            self._cases[case_id] = updated
            return updated

    def add_note(self, case_id: str, *, author: str, text: str, now: int) -> CaseRecord:
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise KeyError(case_id)
            note = CaseNote(timestamp=now, author=author, text=text)
            updated = case.model_copy(update={"notes": (*case.notes, note), "updated_at": now})
            self._cases[case_id] = updated
            return updated

    def link_alerts(self, case_id: str, alert_ids: tuple[str, ...], *, now: int) -> CaseRecord:
        with self._lock:
            case = self._cases.get(case_id)
            if case is None:
                raise KeyError(case_id)
            merged = tuple(dict.fromkeys((*case.alert_ids, *alert_ids)))
            updated = case.model_copy(update={"alert_ids": merged, "updated_at": now})
            self._cases[case_id] = updated
            return updated


class SQLiteCaseStore:
    """Durable analyst case tracker, mirroring ``SQLiteAlertStore``'s connection style."""

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
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                updated_at INTEGER NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cases_updated ON cases (updated_at DESC);
            CREATE TABLE IF NOT EXISTS case_counters (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK (value >= 0)
            );
            INSERT OR IGNORE INTO case_counters (key, value) VALUES ('next_id', 1);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _read_case(self, case_id: str) -> CaseRecord | None:
        row = self._connection.execute(
            "SELECT payload_json FROM cases WHERE case_id=?", (case_id,)
        ).fetchone()
        return CaseRecord.model_validate_json(row["payload_json"]) if row else None

    def _write_case(self, case: CaseRecord) -> None:
        self._connection.execute(
            "INSERT INTO cases(case_id,updated_at,status,payload_json) VALUES(?,?,?,?) "
            "ON CONFLICT(case_id) DO UPDATE SET "
            "updated_at=excluded.updated_at, status=excluded.status, payload_json=excluded.payload_json",
            (case.case_id, case.updated_at, case.status, case.model_dump_json()),
        )

    def create_case(self, *, title: str, alert_ids: tuple[str, ...], now: int) -> CaseRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                next_id = self._connection.execute(
                    "SELECT value FROM case_counters WHERE key='next_id'"
                ).fetchone()["value"]
                self._connection.execute(
                    "UPDATE case_counters SET value=value+1 WHERE key='next_id'"
                )
                case = CaseRecord(
                    case_id=f"CASE-{next_id:08d}",
                    title=title,
                    alert_ids=alert_ids,
                    created_at=now,
                    updated_at=now,
                )
                self._write_case(case)
                self._connection.execute("COMMIT")
                return case
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self._lock:
            return self._read_case(case_id)

    def list_cases(self, *, status: str | None = None, limit: int = 100) -> tuple[CaseRecord, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            if status is None:
                rows = self._connection.execute(
                    "SELECT payload_json FROM cases ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
            else:
                rows = self._connection.execute(
                    "SELECT payload_json FROM cases WHERE status=? ORDER BY updated_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
        return tuple(CaseRecord.model_validate_json(row["payload_json"]) for row in rows)

    def update_status(
        self, case_id: str, status: str, *, closed_reason: str | None, now: int
    ) -> CaseRecord:
        if status not in _VALID_CASE_STATUSES:
            raise ValueError("invalid case status")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._read_case(case_id)
                if case is None:
                    raise KeyError(case_id)
                updated = case.model_copy(
                    update={
                        "status": status,
                        "closed_reason": closed_reason if status == "closed" else None,
                        "updated_at": now,
                    }
                )
                self._write_case(updated)
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def add_note(self, case_id: str, *, author: str, text: str, now: int) -> CaseRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._read_case(case_id)
                if case is None:
                    raise KeyError(case_id)
                note = CaseNote(timestamp=now, author=author, text=text)
                updated = case.model_copy(
                    update={"notes": (*case.notes, note), "updated_at": now}
                )
                self._write_case(updated)
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def link_alerts(self, case_id: str, alert_ids: tuple[str, ...], *, now: int) -> CaseRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                case = self._read_case(case_id)
                if case is None:
                    raise KeyError(case_id)
                merged = tuple(dict.fromkeys((*case.alert_ids, *alert_ids)))
                updated = case.model_copy(update={"alert_ids": merged, "updated_at": now})
                self._write_case(updated)
                self._connection.execute("COMMIT")
                return updated
            except Exception:
                self._connection.execute("ROLLBACK")
                raise


class PlaybookExecutionStore:
    """In-memory SOAR playbook execution audit log."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._executions: dict[str, PlaybookExecutionRecord] = {}
        self._next_id = 1

    def record(self, execution: PlaybookExecution) -> PlaybookExecutionRecord:
        with self._lock:
            execution_id = f"RUN-{self._next_id:08d}"
            self._next_id += 1
            record = _execution_record(execution_id, execution)
            self._executions[execution_id] = record
            return record

    def list_executions(self, *, limit: int = 100) -> tuple[PlaybookExecutionRecord, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            return tuple(
                sorted(self._executions.values(), key=lambda r: -r.triggered_at)[:limit]
            )


class SQLitePlaybookExecutionStore:
    """Durable SOAR playbook execution audit log."""

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
            CREATE TABLE IF NOT EXISTS playbook_executions (
                execution_id TEXT PRIMARY KEY,
                triggered_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_playbook_exec_time
                ON playbook_executions (triggered_at DESC);
            CREATE TABLE IF NOT EXISTS playbook_counters (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK (value >= 0)
            );
            INSERT OR IGNORE INTO playbook_counters (key, value) VALUES ('next_id', 1);
            """
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def record(self, execution: PlaybookExecution) -> PlaybookExecutionRecord:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                next_id = self._connection.execute(
                    "SELECT value FROM playbook_counters WHERE key='next_id'"
                ).fetchone()["value"]
                self._connection.execute(
                    "UPDATE playbook_counters SET value=value+1 WHERE key='next_id'"
                )
                execution_id = f"RUN-{next_id:08d}"
                record = _execution_record(execution_id, execution)
                self._connection.execute(
                    "INSERT INTO playbook_executions(execution_id,triggered_at,payload_json) "
                    "VALUES(?,?,?)",
                    (record.execution_id, record.triggered_at, record.model_dump_json()),
                )
                self._connection.execute("COMMIT")
                return record
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def list_executions(self, *, limit: int = 100) -> tuple[PlaybookExecutionRecord, ...]:
        if limit <= 0:
            raise ValueError("limit must be positive")
        with self._lock:
            rows = self._connection.execute(
                "SELECT payload_json FROM playbook_executions ORDER BY triggered_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return tuple(PlaybookExecutionRecord.model_validate_json(row["payload_json"]) for row in rows)
