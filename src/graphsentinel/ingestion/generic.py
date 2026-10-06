"""Offline ingestion for any source format: normalized events to the interim dataset.

The LANL ingest (``ingestion/auth.py``) streams a nine-column text file. This
is its counterpart for every other format: an adapter from ``sources/`` yields
:class:`SourceEvent`; this module sorts them, drops local logons (the gateway
refuses them), encodes entities into the same append-only id maps, applies
labels, and writes the same day-partitioned parquet and a report. From here
on the pipeline -- features, baselines, training, backfill, serving -- does
not know which format the events came from.

Labels are optional and take the LANL red-team shape, ``time,user,src,dst``,
in plain or gzip CSV; an event whose four fields match a row is labelled.
Times in the label file are epoch seconds or anything ``parse_timestamp``
reads.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graphsentinel.ingestion.auth import SECONDS_PER_DAY, NormalizedAuthEvent
from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.sources import ParseStats, SourceEvent, adapter_for, read_lines, resolve_format
from graphsentinel.sources.base import parse_timestamp


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LabelIndex:
    keys: frozenset[tuple[int, str, str, str]]
    rows: int

    @classmethod
    def from_csv(cls, path: Path) -> LabelIndex:
        keys: set[tuple[int, str, str, str]] = set()
        rows = 0
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", newline="") as handle:
            for row in csv.reader(handle):
                if not row or row[0].strip().lower() in {"time", "timestamp"}:
                    continue
                if len(row) < 4:
                    raise ValueError(f"{path.name}: a label row needs time,user,src,dst: {row}")
                stamp = parse_timestamp(row[0].strip())
                if stamp is None:
                    raise ValueError(f"{path.name}: unreadable label time {row[0]!r}")
                keys.add((stamp, row[1].strip(), row[2].strip(), row[3].strip()))
                rows += 1
        if not keys:
            raise ValueError(f"{path.name} contains no labels")
        return cls(frozenset(keys), rows)

    def contains(self, event: SourceEvent) -> bool:
        return event.key() in self.keys


@dataclass
class GenericIngestionReport:
    schema_version: int
    format: str
    sources: list[str]
    parse: dict[str, object]
    events_sorted: int
    self_loops_dropped: int
    duplicates_dropped: int
    labels_file: str | None
    labels_rows: int
    labels_matched: int
    timestamp_min: int | None
    timestamp_max: int | None
    unique_counts: dict[str, int]
    success_values: dict[str, int]
    parquet_files: int
    drop_self_loops: bool = True
    rows_parsed: int = 0
    redteam_matches: int = 0
    notes: list[str] = field(default_factory=list)
    #: SHA-256 of each input file, and one digest over all of them (sorted by
    #: name) that identifies this dataset the way the LANL manifest's does, so
    #: a checkpoint trained on it carries real provenance.
    sources_sha256: dict[str, str] = field(default_factory=dict)
    dataset_sha256: str = ""
    #: What ``--format auto`` concluded, if it was used: the format, the
    #: inferred column map, the evidence and any warnings.
    detection: dict[str, object] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "format": self.format,
            "sources": self.sources,
            "parse": self.parse,
            "events_sorted": self.events_sorted,
            "rows_parsed": self.rows_parsed,
            "self_loops_dropped": self.self_loops_dropped,
            "duplicates_dropped": self.duplicates_dropped,
            "labels_file": self.labels_file,
            "labels_rows": self.labels_rows,
            "labels_matched": self.labels_matched,
            "redteam_matches": self.redteam_matches,
            "timestamp_min": self.timestamp_min,
            "timestamp_max": self.timestamp_max,
            "timestamps_non_decreasing": True,
            "unique_counts": self.unique_counts,
            "success_values": self.success_values,
            "parquet_files": self.parquet_files,
            "drop_self_loops": self.drop_self_loops,
            "notes": self.notes,
            "sources_sha256": self.sources_sha256,
            "dataset_sha256": self.dataset_sha256,
            "detection": self.detection,
        }


def normalize_events(
    events: Iterable[SourceEvent],
    id_maps: AuthIdMaps,
    *,
    labels: LabelIndex | None = None,
) -> tuple[list[NormalizedAuthEvent], dict[str, Any]]:
    """Sort, de-duplicate, drop local logons, encode and label.

    Sorting is by timestamp with the file order as the tie-break, which keeps
    same-second events in the order the source wrote them. Exact duplicate
    lines (same four-part key and outcome) are dropped: log shippers retry.
    """
    ordered = sorted(enumerate(events), key=lambda item: (item[1].timestamp, item[0]))
    seen: set[tuple[int, str, str, str, bool]] = set()
    normalized: list[NormalizedAuthEvent] = []
    self_loops = duplicates = matched = 0
    success_values: Counter[str] = Counter()
    for _index, event in ordered:
        if event.is_self_loop:
            self_loops += 1
            continue
        identity = (*event.key(), event.success)
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        label = int(labels is not None and labels.contains(event))
        matched += label
        success_values["Success" if event.success else "Fail"] += 1
        normalized.append(
            NormalizedAuthEvent(
                event_id=len(normalized),
                timestamp=event.timestamp,
                src_user_id=id_maps.users.encode(event.user),
                dst_user_id=id_maps.users.encode(event.destination_user or event.user),
                src_host_id=id_maps.hosts.encode(event.source_host),
                dst_host_id=id_maps.hosts.encode(event.destination_host),
                auth_type_id=id_maps.auth_types.encode(event.auth_type),
                logon_type_id=id_maps.logon_types.encode(event.logon_type),
                orientation_id=id_maps.orientations.encode(event.orientation),
                success=int(event.success),
                label_redteam=label,
                day=event.timestamp // SECONDS_PER_DAY,
                hour=(event.timestamp % SECONDS_PER_DAY) // 3_600,
            )
        )
    return normalized, {
        "self_loops": self_loops,
        "duplicates": duplicates,
        "labels_matched": matched,
        "success_values": dict(success_values),
    }


def ingest_logs(
    *,
    format_name: str,
    inputs: Sequence[Path],
    output_dir: Path,
    id_map_dir: Path,
    report_path: Path,
    labels_path: Path | None = None,
    column_map: str | None = None,
    assume_year: int | None = None,
    chunk_rows: int = 250_000,
) -> GenericIngestionReport:
    """Any supported format -> interim parquet + id maps + report."""
    from graphsentinel.ingestion.parquet import ParquetPartitionWriter

    for path in inputs:
        if not path.is_file():
            raise FileNotFoundError(path)
    digests = {path.name: _sha256(path) for path in inputs}
    dataset_digest = hashlib.sha256(
        "\n".join(f"{name}:{digest}" for name, digest in sorted(digests.items())).encode()
    ).hexdigest()
    # "auto" is resolved against the files themselves before anything is
    # parsed, and the detection is written into the report: a dataset whose
    # format was guessed must carry the guess, and what it was based on.
    format_name, column_map, detection = resolve_format(
        format_name, inputs, column_map=column_map
    )
    adapter = adapter_for(format_name, column_map=column_map, assume_year=assume_year)
    stats = ParseStats()
    events = list(adapter.parse(read_lines(inputs), stats))
    if not events:
        raise ValueError(
            f"{format_name}: no authentication events in {[p.name for p in inputs]} "
            f"(skipped: {dict(stats.skipped)})"
        )
    labels = LabelIndex.from_csv(labels_path) if labels_path is not None else None
    id_maps = AuthIdMaps()
    normalized, counts = normalize_events(events, id_maps, labels=labels)
    if not normalized:
        raise ValueError("every event was a local logon or a duplicate; nothing to write")

    writer = ParquetPartitionWriter(output_dir)
    files = 0
    for start in range(0, len(normalized), max(1, chunk_rows)):
        files += writer.write(normalized[start : start + chunk_rows])
    id_maps.save(id_map_dir)

    notes: list[str] = []
    if detection is not None:
        notes.append(
            f"format detected automatically: {detection.format} "
            f"(confidence {detection.confidence:.2f}; {'; '.join(detection.reasons)})"
        )
        notes.extend(f"detection warning: {w}" for w in detection.warnings)
    if stats.skipped.get("year_needed"):
        notes.append(
            f"{stats.skipped['year_needed']} lines carried year-less syslog stamps; "
            "pass --assume-year"
        )
    report = GenericIngestionReport(
        schema_version=1,
        format=format_name,
        sources=[str(p.resolve()) for p in inputs],
        parse=stats.to_dict(),
        events_sorted=len(events),
        rows_parsed=len(normalized),
        self_loops_dropped=counts["self_loops"],
        duplicates_dropped=counts["duplicates"],
        labels_file=str(labels_path.resolve()) if labels_path else None,
        labels_rows=labels.rows if labels else 0,
        labels_matched=counts["labels_matched"],
        redteam_matches=counts["labels_matched"],
        timestamp_min=normalized[0].timestamp,
        timestamp_max=normalized[-1].timestamp,
        unique_counts={name: len(mapping) - 1 for name, mapping in id_maps.items()},
        success_values=counts["success_values"],
        parquet_files=files,
        notes=notes,
        sources_sha256=digests,
        dataset_sha256=dataset_digest,
        detection=detection.to_dict() if detection is not None else None,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_name(f".{report_path.name}.tmp")
    temporary.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, report_path)
    return report


__all__ = ["GenericIngestionReport", "LabelIndex", "ingest_logs", "normalize_events"]
