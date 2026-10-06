"""Streaming integrity checks for large gzip telemetry files."""

from __future__ import annotations

import csv
import gzip
import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import BinaryIO

from graphsentinel.datasets.catalog import DatasetFileSpec


class IntegrityError(ValueError):
    """Raised when a raw file violates the declared data contract."""


@dataclass(frozen=True, slots=True)
class ValidationResult:
    file: str
    compressed_bytes: int
    sha256: str
    validation_level: str
    rows_examined: int
    total_rows: int | None
    malformed_rows: int
    missing_values: dict[str, int]
    timestamp_min: int | None
    timestamp_max: int | None
    timestamps_non_decreasing: bool
    first_valid_row: list[str] | None
    last_valid_row: list[str] | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _sha256_stream(stream: BinaryIO, chunk_bytes: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(chunk_bytes):
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    """Hash compressed bytes without loading the file into memory."""

    with path.open("rb") as stream:
        return _sha256_stream(stream)


def inspect_gzip(
    path: Path,
    spec: DatasetFileSpec,
    *,
    full_scan: bool,
    quick_scan_rows: int = 10_000,
) -> ValidationResult:
    """Validate rows causally and with bounded memory.

    A quick scan validates the first ``quick_scan_rows`` decompressed records. A full scan
    validates every record and is required for global ordering, total rows, and a true last row.
    SHA-256 always covers the complete compressed file.
    """

    if quick_scan_rows <= 0:
        raise ValueError("quick_scan_rows must be positive")
    if not path.is_file():
        raise FileNotFoundError(path)

    with path.open("rb") as raw:
        magic = raw.read(2)
    if magic != b"\x1f\x8b":
        raise IntegrityError(f"{path} is not a gzip stream")

    missing = dict.fromkeys(spec.columns, 0)
    rows_examined = 0
    malformed_rows = 0
    first_valid: list[str] | None = None
    last_valid: list[str] | None = None
    timestamp_min: int | None = None
    timestamp_max: int | None = None
    previous_timestamp: int | None = None
    non_decreasing = True

    try:
        with gzip.open(path, mode="rt", encoding="utf-8", errors="strict", newline="") as stream:
            reader = csv.reader(stream)
            for row in reader:
                if not full_scan and rows_examined >= quick_scan_rows:
                    break
                rows_examined += 1

                if len(row) != spec.column_count:
                    malformed_rows += 1
                    continue

                try:
                    timestamp = int(row[0])
                except ValueError:
                    malformed_rows += 1
                    continue
                if timestamp < 0:
                    malformed_rows += 1
                    continue

                if previous_timestamp is not None and timestamp < previous_timestamp:
                    non_decreasing = False
                previous_timestamp = timestamp
                timestamp_min = (
                    timestamp if timestamp_min is None else min(timestamp_min, timestamp)
                )
                timestamp_max = (
                    timestamp if timestamp_max is None else max(timestamp_max, timestamp)
                )

                for index, value in enumerate(row):
                    if value == "?":
                        missing[spec.columns[index]] += 1
                if first_valid is None:
                    first_valid = row
                last_valid = row
    except (gzip.BadGzipFile, EOFError, UnicodeDecodeError) as error:
        raise IntegrityError(f"Cannot decode {path.name}: {error}") from error

    if rows_examined == 0:
        raise IntegrityError(f"{path.name} contains no records")
    if first_valid is None:
        raise IntegrityError(f"{path.name} contains no valid records")

    return ValidationResult(
        file=spec.name,
        compressed_bytes=path.stat().st_size,
        sha256=sha256_file(path),
        validation_level="full" if full_scan else "quick",
        rows_examined=rows_examined,
        total_rows=rows_examined if full_scan else None,
        malformed_rows=malformed_rows,
        missing_values=missing,
        timestamp_min=timestamp_min,
        timestamp_max=timestamp_max,
        timestamps_non_decreasing=non_decreasing,
        first_valid_row=first_valid,
        last_valid_row=last_valid if full_scan else None,
    )
