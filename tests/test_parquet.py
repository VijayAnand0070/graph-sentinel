from __future__ import annotations

from pathlib import Path

import pyarrow.parquet as pq

from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.ingestion.parquet import ParquetPartitionWriter


def _event(event_id: int, timestamp: int) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_user_id=1,
        dst_user_id=2,
        src_host_id=1,
        dst_host_id=2,
        auth_type_id=1,
        logon_type_id=1,
        orientation_id=1,
        success=1,
        label_redteam=event_id % 2,
        day=timestamp // 86_400,
        hour=(timestamp % 86_400) // 3_600,
    )


def test_parquet_writer_partitions_days_and_preserves_types(tmp_path: Path) -> None:
    writer = ParquetPartitionWriter(tmp_path)

    files_written = writer.write([_event(0, 1), _event(1, 86_401)])

    files = sorted(tmp_path.glob("auth_day=*/*.parquet"))
    assert files_written == 2
    assert [path.parent.name for path in files] == ["auth_day=00", "auth_day=01"]
    assert pq.read_table(files[0]).column("event_id").to_pylist() == [0]
    assert pq.read_schema(files[0]).field("src_user_id").type.bit_width == 32
    assert not list(tmp_path.rglob("*.tmp"))
