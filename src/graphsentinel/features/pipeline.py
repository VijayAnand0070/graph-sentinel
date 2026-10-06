"""Streaming Parquet-to-Parquet causal feature pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections import defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

from graphsentinel.features.causal import (
    MODEL_FEATURE_NAMES,
    CausalFeatureEngine,
    FeatureRecord,
)
from graphsentinel.features.eda import SecurityEdaAccumulator
from graphsentinel.ingestion.auth import NormalizedAuthEvent

FEATURE_VERSION = "auth-causal-v1"


@dataclass(frozen=True, slots=True)
class FeatureBuildReport:
    schema_version: int
    feature_version: str
    feature_contract_sha256: str
    source_files: list[str]
    events: int
    redteam_events: int
    timestamp_min: int | None
    timestamp_max: int | None
    output_files: int
    model_features: list[str]
    eda: dict[str, object]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_interim_parquet(input_dir: Path) -> list[Path]:
    paths = sorted(input_dir.glob("auth_day=*/*.parquet"))
    if not paths:
        raise FileNotFoundError(f"No authentication Parquet files found under {input_dir}")
    return paths


def iter_normalized_parquet(
    paths: Sequence[Path], *, batch_rows: int = 65_536
) -> Iterator[NormalizedAuthEvent]:
    """Read normalized partitions in order and enforce event/timestamp continuity."""

    if batch_rows <= 0:
        raise ValueError("batch_rows must be positive")
    try:
        import pyarrow.parquet as pq  # type: ignore[import-untyped]
    except ImportError as error:
        raise RuntimeError('Feature building requires: pip install -e ".[data]"') from error

    expected_event_id = 0
    previous_timestamp: int | None = None
    field_names = tuple(NormalizedAuthEvent.__dataclass_fields__)
    for path in paths:
        parquet = pq.ParquetFile(path)
        missing = set(field_names) - set(parquet.schema_arrow.names)
        if missing:
            raise ValueError(f"{path} is missing normalized columns: {sorted(missing)}")
        for batch in parquet.iter_batches(batch_size=batch_rows, columns=list(field_names)):
            columns = batch.to_pydict()
            for row_index in range(batch.num_rows):
                values = {name: int(columns[name][row_index]) for name in field_names}
                event = NormalizedAuthEvent(**values)
                if event.event_id != expected_event_id:
                    raise ValueError(
                        f"Expected event_id {expected_event_id}, found {event.event_id} in {path}"
                    )
                if previous_timestamp is not None and event.timestamp < previous_timestamp:
                    raise ValueError(f"Timestamp order violation in {path}")
                expected_event_id += 1
                previous_timestamp = event.timestamp
                yield event


class _FeatureParquetWriter:
    def __init__(self, output_dir: Path) -> None:
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as error:
            raise RuntimeError('Feature building requires: pip install -e ".[data]"') from error
        self.output_dir = output_dir
        self._pa = pa
        self._pq = pq
        self._part_number = 0

    def write(self, records: Sequence[FeatureRecord]) -> int:
        by_day: dict[int, list[FeatureRecord]] = defaultdict(list)
        for record in records:
            by_day[record.day].append(record)
        files_written = 0
        for day, day_records in sorted(by_day.items()):
            partition = self.output_dir / f"feature_day={day:02d}"
            partition.mkdir(parents=True, exist_ok=True)
            destination = partition / f"part-{self._part_number:08d}.parquet"
            temporary = partition / f".{destination.name}.{uuid4().hex}.tmp"
            columns = {
                name: [getattr(record, name) for record in day_records]
                for name in FeatureRecord.__dataclass_fields__
            }
            table = self._pa.Table.from_pydict(columns)
            try:
                self._pq.write_table(
                    table,
                    temporary,
                    compression="zstd",
                    use_dictionary=True,
                    write_statistics=True,
                )
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
            self._part_number += 1
            files_written += 1
        return files_written


def _contract_hash() -> str:
    payload = json.dumps(
        {
            "version": FEATURE_VERSION,
            "fields": list(FeatureRecord.__dataclass_fields__),
            "model_features": MODEL_FEATURE_NAMES,
            "history_rule": "timestamp_strictly_less_than_event",
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def build_feature_dataset(
    *,
    input_dir: Path,
    output_dir: Path,
    report_path: Path,
    chunk_rows: int = 100_000,
) -> FeatureBuildReport:
    """Build a complete feature dataset transactionally from normalized partitions."""

    if chunk_rows <= 0:
        raise ValueError("chunk_rows must be positive")
    if output_dir.exists():
        raise FileExistsError(f"Refusing to overwrite feature dataset: {output_dir}")
    paths = discover_interim_parquet(input_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}.", suffix=".staging", dir=output_dir.parent)
    )
    writer = _FeatureParquetWriter(staging)
    engine = CausalFeatureEngine()
    eda = SecurityEdaAccumulator()
    buffer: list[FeatureRecord] = []
    output_files = 0
    events = 0
    positives = 0
    timestamp_min: int | None = None
    timestamp_max: int | None = None
    try:
        normalized_events = iter_normalized_parquet(paths)
        for record in engine.transform(normalized_events):
            eda.observe(record)
            buffer.append(record)
            events += 1
            positives += record.label_redteam
            timestamp_min = (
                record.timestamp if timestamp_min is None else min(timestamp_min, record.timestamp)
            )
            timestamp_max = (
                record.timestamp if timestamp_max is None else max(timestamp_max, record.timestamp)
            )
            if len(buffer) >= chunk_rows:
                output_files += writer.write(buffer)
                buffer = []
        if buffer:
            output_files += writer.write(buffer)
        report = FeatureBuildReport(
            schema_version=1,
            feature_version=FEATURE_VERSION,
            feature_contract_sha256=_contract_hash(),
            source_files=[str(path.resolve()) for path in paths],
            events=events,
            redteam_events=positives,
            timestamp_min=timestamp_min,
            timestamp_max=timestamp_max,
            output_files=output_files,
            model_features=list(MODEL_FEATURE_NAMES),
            eda=eda.to_dict(),
        )
        _write_json(staging / "_feature_report.json", report.to_dict())
        os.replace(staging, output_dir)
        _write_json(report_path, report.to_dict())
        return report
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
