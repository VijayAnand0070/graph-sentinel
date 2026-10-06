"""Atomic, typed Parquet partition writer."""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from graphsentinel.ingestion.auth import NormalizedAuthEvent


class ParquetDependencyError(RuntimeError):
    """Raised when the optional columnar data dependency is unavailable."""


class ParquetPartitionWriter:
    """Write chunks into Hive-style day partitions with atomic file publication."""

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self._part_number = 0
        try:
            import pyarrow as pa  # type: ignore[import-untyped]
            import pyarrow.parquet as pq  # type: ignore[import-untyped]
        except ImportError as error:
            raise ParquetDependencyError(
                'Parquet ingestion requires: python -m pip install -e ".[data]"'
            ) from error
        self._pa = pa
        self._pq = pq
        self._schema = pa.schema(
            [
                ("event_id", pa.int64()),
                ("timestamp", pa.int64()),
                ("src_user_id", pa.int32()),
                ("dst_user_id", pa.int32()),
                ("src_host_id", pa.int32()),
                ("dst_host_id", pa.int32()),
                ("auth_type_id", pa.int16()),
                ("logon_type_id", pa.int16()),
                ("orientation_id", pa.int8()),
                ("success", pa.int8()),
                ("label_redteam", pa.int8()),
                ("day", pa.int16()),
                ("hour", pa.int8()),
            ]
        )

    def write(self, events: Sequence[NormalizedAuthEvent]) -> int:
        by_day: dict[int, list[NormalizedAuthEvent]] = defaultdict(list)
        for event in events:
            by_day[event.day].append(event)

        written = 0
        for day, day_events in sorted(by_day.items()):
            partition = self.output_dir / f"auth_day={day:02d}"
            partition.mkdir(parents=True, exist_ok=True)
            destination = partition / f"part-{self._part_number:08d}.parquet"
            if destination.exists():
                raise FileExistsError(f"Refusing to overwrite {destination}")
            temporary = partition / f".{destination.name}.{uuid4().hex}.tmp"
            columns = {
                name: [getattr(event, name) for event in day_events] for name in self._schema.names
            }
            table = self._pa.Table.from_pydict(columns, schema=self._schema)
            try:
                self._pq.write_table(
                    table,
                    temporary,
                    compression="zstd",
                    use_dictionary=[
                        "auth_type_id",
                        "logon_type_id",
                        "orientation_id",
                        "success",
                        "label_redteam",
                        "day",
                        "hour",
                    ],
                    write_statistics=True,
                )
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            self._part_number += 1
            written += 1
        return written
