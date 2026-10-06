"""Exact LANL red-team ground-truth indexing."""

from __future__ import annotations

import csv
import gzip
from dataclasses import dataclass
from pathlib import Path

RedTeamKey = tuple[int, str, str, str]


@dataclass(frozen=True, slots=True)
class RedTeamIndex:
    events: frozenset[RedTeamKey]
    rows_read: int
    duplicate_rows: int

    def contains(self, timestamp: int, user: str, src_host: str, dst_host: str) -> bool:
        return (timestamp, user, src_host, dst_host) in self.events

    @classmethod
    def from_gzip(cls, path: Path) -> RedTeamIndex:
        events: set[RedTeamKey] = set()
        rows_read = 0
        duplicate_rows = 0
        with gzip.open(path, mode="rt", encoding="utf-8", errors="strict", newline="") as stream:
            for row_number, row in enumerate(csv.reader(stream), start=1):
                if len(row) != 4:
                    raise ValueError(
                        f"{path.name}:{row_number}: expected 4 columns, found {len(row)}"
                    )
                try:
                    timestamp = int(row[0])
                except ValueError as error:
                    raise ValueError(
                        f"{path.name}:{row_number}: invalid timestamp {row[0]!r}"
                    ) from error
                if timestamp < 0:
                    raise ValueError(f"{path.name}:{row_number}: negative timestamp")
                key = (timestamp, row[1].strip(), row[2].strip(), row[3].strip())
                rows_read += 1
                if key in events:
                    duplicate_rows += 1
                events.add(key)
        if not events:
            raise ValueError(f"{path.name} contains no red-team events")
        return cls(frozenset(events), rows_read, duplicate_rows)
