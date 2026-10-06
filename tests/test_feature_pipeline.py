from __future__ import annotations

import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from graphsentinel.features.pipeline import build_feature_dataset
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.ingestion.parquet import ParquetPartitionWriter


def _event(event_id: int, timestamp: int, destination: int, label: int) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_user_id=1,
        dst_user_id=1,
        src_host_id=1,
        dst_host_id=destination,
        auth_type_id=1,
        logon_type_id=1,
        orientation_id=1,
        success=1,
        label_redteam=label,
        day=timestamp // 86_400,
        hour=(timestamp % 86_400) // 3_600,
    )


def test_feature_pipeline_is_transactional_and_emits_eda(tmp_path: Path) -> None:
    interim = tmp_path / "interim"
    output = tmp_path / "features"
    external_report = tmp_path / "reports" / "features.json"
    ParquetPartitionWriter(interim).write(
        [_event(0, 1, 2, 0), _event(1, 2, 3, 1), _event(2, 3, 3, 0)]
    )

    report = build_feature_dataset(
        input_dir=interim,
        output_dir=output,
        report_path=external_report,
        chunk_rows=2,
    )

    files = sorted(output.glob("feature_day=*/*.parquet"))
    assert report.events == 3
    assert report.redteam_events == 1
    assert report.eda["new_pair_rate"] == pytest.approx(2 / 3)
    assert files
    assert pq.read_table(files[0]).column("event_id").to_pylist() == [0, 1]
    assert json.loads((output / "_feature_report.json").read_text())["events"] == 3
    assert external_report.is_file()
    assert not list(tmp_path.rglob("*.staging"))


def test_feature_pipeline_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "features"
    output.mkdir()

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        build_feature_dataset(
            input_dir=tmp_path / "missing",
            output_dir=output,
            report_path=tmp_path / "report.json",
        )
