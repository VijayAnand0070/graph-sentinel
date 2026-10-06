"""Safe registration of user-downloaded LANL files into immutable raw storage."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from graphsentinel.datasets.catalog import LANL_DOI, LANL_SOURCE_PAGE, required_specs
from graphsentinel.datasets.integrity import ValidationResult, inspect_gzip


class RegistrationError(RuntimeError):
    """Raised when safe raw-data registration cannot continue."""


def verified_manifest_dataset_sha256(raw_dir: Path, scope: str = "core") -> str:
    """Return the canonical dataset digest only for a complete full-scan manifest."""

    manifest_path = raw_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise RegistrationError(f"Cannot read verified raw manifest: {error}") from error
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list):
        raise RegistrationError("Verified raw manifest has no file inventory")
    entries = {
        item.get("file"): item
        for item in files
        if isinstance(item, dict) and isinstance(item.get("file"), str)
    }
    hashes: dict[str, str] = {}
    for spec in required_specs(scope):
        entry = entries.get(spec.name)
        if (
            not isinstance(entry, dict)
            or entry.get("validation_level") != "full"
            or entry.get("malformed_rows") != 0
            or entry.get("timestamps_non_decreasing") is not True
        ):
            raise RegistrationError(f"{spec.name} has not passed the complete raw-data contract")
        digest = entry.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RegistrationError(f"{spec.name} has no valid SHA-256 provenance")
        hashes[spec.name] = digest
    encoded = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class RegistrationPlan:
    source_dir: Path
    raw_dir: Path
    scope: str
    files: tuple[str, ...]


def plan_registration(source_dir: Path, raw_dir: Path, scope: str) -> RegistrationPlan:
    source_dir = source_dir.resolve()
    raw_dir = raw_dir.resolve()
    specs = required_specs(scope)
    missing = [spec.name for spec in specs if not (source_dir / spec.name).is_file()]
    if missing:
        raise RegistrationError(f"Missing required source files: {', '.join(missing)}")
    collisions = [spec.name for spec in specs if (raw_dir / spec.name).exists()]
    if collisions:
        raise RegistrationError(
            "Raw targets already exist; refusing to overwrite: " + ", ".join(collisions)
        )
    return RegistrationPlan(
        source_dir=source_dir,
        raw_dir=raw_dir,
        scope=scope,
        files=tuple(spec.name for spec in specs),
    )


def _copy_exclusive(source: Path, target: Path) -> None:
    """Copy once to a temporary file, then atomically publish via an exclusive hard link."""

    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".partial", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_stream:
            shutil.copyfileobj(input_stream, output, length=8 * 1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        # Hard-link creation is atomic and fails if another process created the target.
        os.link(temporary, target)
        temporary.unlink()
        target.chmod(stat.S_IREAD)
    finally:
        temporary.unlink(missing_ok=True)


def _manifest_payload(
    scope: str,
    results: list[ValidationResult],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "dataset": "LANL Comprehensive, Multi-Source Cyber-Security Events",
        "dataset_doi": LANL_DOI,
        "source_page": LANL_SOURCE_PAGE,
        "registered_at_utc": datetime.now(UTC).isoformat(),
        "scope": scope,
        "files": [result.to_dict() for result in results],
    }


def _enforce_results(results: list[ValidationResult]) -> None:
    failures = [
        result.file
        for result in results
        if result.malformed_rows > 0 or not result.timestamps_non_decreasing
    ]
    if failures:
        raise RegistrationError(
            "Dataset contract failed for: "
            + ", ".join(failures)
            + " (malformed rows or non-monotonic timestamps)"
        )


def write_manifest(raw_dir: Path, payload: dict[str, Any]) -> Path:
    """Atomically create or replace the derived manifest (never a raw source file)."""

    raw_dir.mkdir(parents=True, exist_ok=True)
    destination = raw_dir / "manifest.json"
    temporary = raw_dir / ".manifest.json.tmp"
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, destination)
    return destination


def execute_registration(
    plan: RegistrationPlan,
    *,
    full_scan: bool,
    quick_scan_rows: int,
) -> tuple[Path, list[ValidationResult]]:
    """Copy required files, validate raw copies, and emit a provenance manifest."""

    specs = {spec.name: spec for spec in required_specs(plan.scope)}
    copied: list[Path] = []
    results: list[ValidationResult] = []
    try:
        for name in plan.files:
            target = plan.raw_dir / name
            _copy_exclusive(plan.source_dir / name, target)
            copied.append(target)
            results.append(
                inspect_gzip(
                    target,
                    specs[name],
                    full_scan=full_scan,
                    quick_scan_rows=quick_scan_rows,
                )
            )
        _enforce_results(results)
    except Exception:
        # A failed transaction removes only files created by this invocation.
        for copied_path in copied:
            copied_path.chmod(stat.S_IWRITE | stat.S_IREAD)
            copied_path.unlink(missing_ok=True)
        raise

    manifest = write_manifest(plan.raw_dir, _manifest_payload(plan.scope, results))
    return manifest, results


def verify_registered(
    raw_dir: Path,
    scope: str,
    *,
    full_scan: bool,
    quick_scan_rows: int,
) -> tuple[Path, list[ValidationResult]]:
    specs = required_specs(scope)
    missing = [spec.name for spec in specs if not (raw_dir / spec.name).is_file()]
    if missing:
        raise RegistrationError(f"Missing registered raw files: {', '.join(missing)}")
    existing_manifest: dict[str, Any] | None = None
    manifest_path = raw_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            existing_manifest = loaded if isinstance(loaded, dict) else None
        except (json.JSONDecodeError, OSError) as error:
            raise RegistrationError(f"Cannot read existing raw manifest: {error}") from error
    results = [
        inspect_gzip(
            raw_dir / spec.name,
            spec,
            full_scan=full_scan,
            quick_scan_rows=quick_scan_rows,
        )
        for spec in specs
    ]
    _enforce_results(results)
    if existing_manifest is not None:
        original_files = existing_manifest.get("files")
        if not isinstance(original_files, list):
            raise RegistrationError("Existing raw manifest has no valid file inventory")
        original_hashes = {
            item.get("file"): item.get("sha256")
            for item in original_files
            if isinstance(item, dict)
        }
        changed = [
            result.file for result in results if original_hashes.get(result.file) != result.sha256
        ]
        if changed:
            raise RegistrationError(
                "Registered raw file hash changed since initial registration: " + ", ".join(changed)
            )
    payload = _manifest_payload(scope, results)
    if existing_manifest is not None:
        # A quick verification must never erase full-scan provenance. The
        # hash check above proved each file is byte-identical to the one the
        # full scan examined, so everything that scan established (row count,
        # first and last row, monotonic timestamps) still holds; a quick
        # re-check adds nothing and would silently downgrade the manifest
        # that ``train`` requires to be complete.
        originals = {
            item.get("file"): item
            for item in existing_manifest.get("files", [])
            if isinstance(item, dict)
        }
        payload["files"] = [
            originals[result.file]
            if (
                result.validation_level != "full"
                and originals.get(result.file, {}).get("validation_level") == "full"
                and originals[result.file].get("sha256") == result.sha256
            )
            else result.to_dict()
            for result in results
        ]
        if isinstance(existing_manifest.get("registered_at_utc"), str):
            payload["registered_at_utc"] = existing_manifest["registered_at_utc"]
    payload["verified_at_utc"] = datetime.now(UTC).isoformat()
    manifest = write_manifest(raw_dir, payload)
    return manifest, results
