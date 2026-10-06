"""Chunked normalization for LANL authentication telemetry."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.ingestion.labels import RedTeamIndex, RedTeamKey

AUTH_COLUMNS = (
    "time",
    "src_user",
    "dst_user",
    "src_host",
    "dst_host",
    "auth_type",
    "logon_type",
    "orientation",
    "success",
)
SECONDS_PER_DAY = 86_400


@dataclass(frozen=True, slots=True)
class NormalizedAuthEvent:
    event_id: int
    timestamp: int
    src_user_id: int
    dst_user_id: int
    src_host_id: int
    dst_host_id: int
    auth_type_id: int
    logon_type_id: int
    orientation_id: int
    success: int
    label_redteam: int
    day: int
    hour: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(slots=True)
class IngestionStats:
    rows_read: int = 0
    rows_parsed: int = 0
    rows_sampled_out: int = 0
    rows_rejected: int = 0
    rows_self_loop: int = 0
    redteam_self_loops: int = 0
    redteam_matches: int = 0
    timestamps_non_decreasing: bool = True
    timestamp_min: int | None = None
    timestamp_max: int | None = None
    missing_values: Counter[str] = field(default_factory=Counter)
    rejection_reasons: Counter[str] = field(default_factory=Counter)
    success_values: Counter[str] = field(default_factory=Counter)
    matched_redteam_keys: set[RedTeamKey] = field(default_factory=set)


@dataclass(frozen=True, slots=True)
class IngestionReport:
    schema_version: int
    source_auth: str
    source_redteam: str
    source_auth_sha256: str
    source_redteam_sha256: str
    chunk_rows: int
    sample_stride: int
    end_timestamp: int | None
    rows_read: int
    rows_parsed: int
    rows_sampled_out: int
    rows_rejected: int
    rejection_reasons: dict[str, int]
    missing_values: dict[str, int]
    success_values: dict[str, int]
    timestamp_min: int | None
    timestamp_max: int | None
    timestamps_non_decreasing: bool
    redteam_rows: int
    redteam_unique: int
    redteam_duplicates: int
    redteam_matches: int
    redteam_unmatched: int
    unique_counts: dict[str, int]
    parquet_files: int
    #: Whether events whose source and destination host are the same entity
    #: were dropped. The live gateway and the Windows collector both refuse
    #: them, so an offline corpus that keeps them trains on traffic the
    #: deployed path never sees (train/serve skew); dropping them here keeps
    #: the two identical. Reports written before this field existed kept them.
    drop_self_loops: bool = False
    rows_self_loop: int = 0
    redteam_self_loops: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_success(value: str) -> int | None:
    normalized = value.strip().casefold()
    if normalized == "success":
        return 1
    if normalized == "fail":
        return 0
    return None


def iter_normalized_auth_chunks(
    auth_path: Path,
    labels: RedTeamIndex,
    id_maps: AuthIdMaps,
    *,
    chunk_rows: int,
    sample_stride: int = 1,
    end_timestamp: int | None = None,
    drop_self_loops: bool = True,
    stats: IngestionStats,
) -> Iterator[list[NormalizedAuthEvent]]:
    """Yield chronological normalized events with optional bounded deterministic sampling.

    A ``sample_stride`` greater than one retains every Nth normal event while always
    retaining labelled red-team events.  ``end_timestamp`` safely bounds a run because
    the LANL authentication stream is chronological.

    ``drop_self_loops`` removes events whose source and destination host are
    the same string -- local logons. They are not lateral movement, no LANL
    red-team event is one, and the live gateway refuses them; keeping them
    offline trains the model on traffic it can never see in production (54%
    of the corpus). They are counted, and a labelled one is counted
    separately so a corpus in which that assumption fails is visible.
    """

    if chunk_rows <= 0:
        raise ValueError("chunk_rows must be positive")
    if sample_stride <= 0:
        raise ValueError("sample_stride must be positive")
    if end_timestamp is not None and end_timestamp < 0:
        raise ValueError("end_timestamp must be non-negative")
    chunk: list[NormalizedAuthEvent] = []
    previous_timestamp: int | None = None

    with gzip.open(auth_path, mode="rt", encoding="utf-8", errors="strict", newline="") as stream:
        for row in csv.reader(stream):
            stats.rows_read += 1
            if len(row) != len(AUTH_COLUMNS):
                stats.rows_rejected += 1
                stats.rejection_reasons["column_count"] += 1
                continue
            try:
                timestamp = int(row[0])
            except ValueError:
                stats.rows_rejected += 1
                stats.rejection_reasons["timestamp"] += 1
                continue
            if timestamp < 0:
                stats.rows_rejected += 1
                stats.rejection_reasons["timestamp"] += 1
                continue

            if end_timestamp is not None and timestamp > end_timestamp:
                break

            success = _parse_success(row[8])
            if success is None:
                stats.rows_rejected += 1
                stats.rejection_reasons["success"] += 1
                continue

            if previous_timestamp is not None and timestamp < previous_timestamp:
                stats.timestamps_non_decreasing = False
                stats.rows_rejected += 1
                stats.rejection_reasons["timestamp_order"] += 1
                continue
            previous_timestamp = timestamp

            values = [value.strip() for value in row]
            for index, value in enumerate(values):
                if value == "?":
                    stats.missing_values[AUTH_COLUMNS[index]] += 1

            label = int(labels.contains(timestamp, values[1], values[3], values[4]))
            if drop_self_loops and values[3] == values[4]:
                stats.rows_self_loop += 1
                stats.redteam_self_loops += label
                continue
            if not label and (stats.rows_read - 1) % sample_stride != 0:
                stats.rows_sampled_out += 1
                continue
            if label:
                stats.matched_redteam_keys.add((timestamp, values[1], values[3], values[4]))
            event = NormalizedAuthEvent(
                event_id=stats.rows_parsed,
                timestamp=timestamp,
                src_user_id=id_maps.users.encode(values[1]),
                dst_user_id=id_maps.users.encode(values[2]),
                src_host_id=id_maps.hosts.encode(values[3]),
                dst_host_id=id_maps.hosts.encode(values[4]),
                auth_type_id=id_maps.auth_types.encode(values[5]),
                logon_type_id=id_maps.logon_types.encode(values[6]),
                orientation_id=id_maps.orientations.encode(values[7]),
                success=success,
                label_redteam=label,
                day=timestamp // SECONDS_PER_DAY,
                hour=(timestamp % SECONDS_PER_DAY) // 3_600,
            )
            stats.rows_parsed += 1
            stats.redteam_matches += label
            stats.success_values[values[8]] += 1
            stats.timestamp_min = (
                timestamp if stats.timestamp_min is None else min(stats.timestamp_min, timestamp)
            )
            stats.timestamp_max = (
                timestamp if stats.timestamp_max is None else max(stats.timestamp_max, timestamp)
            )
            chunk.append(event)
            if len(chunk) >= chunk_rows:
                yield chunk
                chunk = []
    if chunk:
        yield chunk


ChunkWriter = Callable[[Sequence[NormalizedAuthEvent]], int]


def process_auth_stream(
    auth_path: Path,
    labels: RedTeamIndex,
    id_maps: AuthIdMaps,
    writer: ChunkWriter,
    *,
    chunk_rows: int,
    sample_stride: int = 1,
    end_timestamp: int | None = None,
    drop_self_loops: bool = True,
) -> tuple[IngestionStats, int]:
    """Normalize a stream and pass each chunk to an injected storage writer."""

    stats = IngestionStats()
    files_written = 0
    for chunk in iter_normalized_auth_chunks(
        auth_path,
        labels,
        id_maps,
        chunk_rows=chunk_rows,
        sample_stride=sample_stride,
        end_timestamp=end_timestamp,
        drop_self_loops=drop_self_loops,
        stats=stats,
    ):
        files_written += writer(chunk)
    return stats, files_written


def _write_report(path: Path, report: IngestionReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def ingest_auth(
    *,
    auth_path: Path,
    redteam_path: Path,
    output_dir: Path,
    id_map_dir: Path,
    report_path: Path,
    chunk_rows: int = 250_000,
    sample_stride: int = 1,
    end_timestamp: int | None = None,
    drop_self_loops: bool = True,
) -> IngestionReport:
    """Run Phase 2 authentication ingestion and persist all reproducibility artifacts."""

    from graphsentinel.ingestion.parquet import ParquetPartitionWriter

    if not auth_path.is_file():
        raise FileNotFoundError(auth_path)
    if not redteam_path.is_file():
        raise FileNotFoundError(redteam_path)
    labels = RedTeamIndex.from_gzip(redteam_path)
    id_maps = AuthIdMaps()
    writer = ParquetPartitionWriter(output_dir)
    stats, files_written = process_auth_stream(
        auth_path,
        labels,
        id_maps,
        writer.write,
        chunk_rows=chunk_rows,
        sample_stride=sample_stride,
        end_timestamp=end_timestamp,
        drop_self_loops=drop_self_loops,
    )
    id_maps.save(id_map_dir)

    report = IngestionReport(
        schema_version=1,
        source_auth=str(auth_path.resolve()),
        source_redteam=str(redteam_path.resolve()),
        source_auth_sha256=_file_sha256(auth_path),
        source_redteam_sha256=_file_sha256(redteam_path),
        chunk_rows=chunk_rows,
        sample_stride=sample_stride,
        end_timestamp=end_timestamp,
        rows_read=stats.rows_read,
        rows_parsed=stats.rows_parsed,
        rows_sampled_out=stats.rows_sampled_out,
        rows_rejected=stats.rows_rejected,
        rejection_reasons=dict(stats.rejection_reasons),
        missing_values={column: stats.missing_values[column] for column in AUTH_COLUMNS},
        success_values=dict(stats.success_values),
        timestamp_min=stats.timestamp_min,
        timestamp_max=stats.timestamp_max,
        timestamps_non_decreasing=stats.timestamps_non_decreasing,
        redteam_rows=labels.rows_read,
        redteam_unique=len(labels.events),
        redteam_duplicates=labels.duplicate_rows,
        redteam_matches=stats.redteam_matches,
        redteam_unmatched=len(labels.events - stats.matched_redteam_keys),
        unique_counts={name: len(mapping) - 1 for name, mapping in id_maps.items()},
        parquet_files=files_written,
        drop_self_loops=drop_self_loops,
        rows_self_loop=stats.rows_self_loop,
        redteam_self_loops=stats.redteam_self_loops,
    )
    _write_report(report_path, report)
    return report
