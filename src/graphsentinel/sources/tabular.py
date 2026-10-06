"""Any CSV or JSON-lines authentication export, through a column map.

For the formats nobody has written an adapter for -- a SIEM's own export, a
VPN concentrator, a bespoke identity system -- the operator names which
column holds what::

    --map "timestamp=event_time,user=account,source_host=client,destination_host=server,\\
           success=result:SUCCESS,auth_type=protocol,logon_type=method"

The four fields before ``success`` are required. ``success=<column>:<value>``
reads success as "the column equals this value" (case-insensitive); with no
value the column is read as a boolean-ish (``true/1/yes/success/ok``).
Timestamps take any shape ``parse_timestamp`` understands; ``assume_year``
covers year-less syslog stamps.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from graphsentinel.sources.base import (
    ParseStats,
    SourceEvent,
    canonical_host,
    canonical_user,
    parse_timestamp,
)

REQUIRED = ("timestamp", "user", "source_host", "destination_host")
OPTIONAL = ("success", "auth_type", "logon_type", "orientation", "destination_user", "domain")
TRUE_WORDS = {"true", "1", "yes", "y", "success", "succeeded", "ok", "accept", "accepted", "allow"}


@dataclass(frozen=True, slots=True)
class ColumnMap:
    columns: dict[str, str]
    success_value: str | None = None

    @classmethod
    def parse(cls, text: str) -> ColumnMap:
        columns: dict[str, str] = {}
        success_value: str | None = None
        for part in text.split(","):
            item = part.strip()
            if not item:
                continue
            field, _, column = item.partition("=")
            field, column = field.strip(), column.strip()
            if field not in REQUIRED + OPTIONAL:
                raise ValueError(f"unknown field {field!r}; use {REQUIRED + OPTIONAL}")
            if not column:
                raise ValueError(f"field {field!r} needs a column name")
            if field == "success" and ":" in column:
                column, _, success_value = column.partition(":")
            columns[field] = column
        missing = [f for f in REQUIRED if f not in columns]
        if missing:
            raise ValueError(f"column map lacks required fields: {missing}")
        return cls(columns=columns, success_value=success_value)


class TabularAuthLog:
    name = "tabular"
    description = "CSV (with header) or JSON lines through a --map of columns to fields"
    sample = (
        "event_time,account,client,server,result,protocol\n"
        "2026-03-02T09:14:03Z,alice@corp.example,WS05,FS01,SUCCESS,Kerberos\n"
        "2026-03-02T09:15:00Z,bob@corp.example,WS07,DB01,FAILURE,NTLM\n"
        "2026-03-02T09:15:20Z,bob@corp.example,WS07,DB01,SUCCESS,NTLM\n"
    )
    sample_map = (
        "timestamp=event_time,user=account,source_host=client,destination_host=server,"
        "success=result:SUCCESS,auth_type=protocol"
    )

    def __init__(self, column_map: ColumnMap, *, assume_year: int | None = None) -> None:
        self.map = column_map
        self.assume_year = assume_year

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        iterator = iter(lines)
        first = next(iterator, None)
        if first is None:
            return
        if first.lstrip().startswith("{"):
            records: Iterable[dict[str, Any]] = self._json_records([first, *iterator], stats)
        else:
            records = self._csv_records([first, *iterator])
        for record in records:
            stats.lines += 1
            event = self._event(record, stats)
            if event is not None:
                stats.events += 1
                yield event

    @staticmethod
    def _json_records(lines: Iterable[str], stats: ParseStats) -> Iterator[dict[str, Any]]:
        for line in lines:
            text = line.strip()
            if not text:
                continue
            try:
                record = json.loads(text)
            except json.JSONDecodeError:
                stats.lines += 1
                stats.skip("bad_json")
                continue
            if isinstance(record, dict):
                yield record

    @staticmethod
    def _csv_records(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
        text = io.StringIO("".join(line if line.endswith("\n") else line + "\n" for line in lines))
        yield from csv.DictReader(text)

    def _event(self, record: dict[str, Any], stats: ParseStats) -> SourceEvent | None:
        columns = self.map.columns

        def get(field: str) -> Any:
            return record.get(columns[field]) if field in columns else None

        timestamp = parse_timestamp(get("timestamp"), assume_year=self.assume_year)
        if timestamp is None:
            stats.skip("bad_timestamp")
            return None
        user = canonical_user(get("user"), get("domain"))
        source = canonical_host(get("source_host"))
        destination = canonical_host(get("destination_host"))
        if not user or not source or not destination:
            stats.skip("missing_entity")
            return None
        if source == destination:
            stats.skip("self_loop")
            return None
        success = True
        raw_success = get("success")
        if raw_success is not None:
            text = str(raw_success).strip().lower()
            success = (
                text == self.map.success_value.lower()
                if self.map.success_value is not None
                else text in TRUE_WORDS
            )
        destination_user = canonical_user(get("destination_user"), get("domain")) or user
        return SourceEvent(
            timestamp=timestamp,
            user=user,
            source_host=source,
            destination_host=destination,
            destination_user=destination_user,
            auth_type=str(get("auth_type") or "unknown"),
            logon_type=str(get("logon_type") or "unknown"),
            orientation=str(get("orientation") or "LogOn"),
            success=success,
            source="tabular",
        )


__all__ = ["ColumnMap", "TabularAuthLog"]
