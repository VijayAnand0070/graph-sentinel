from __future__ import annotations

import gzip
import json
import stat
from pathlib import Path

import pytest

from graphsentinel.datasets.registry import (
    RegistrationError,
    execute_registration,
    plan_registration,
    verified_manifest_dataset_sha256,
    verify_registered,
)


def _write_core_files(directory: Path) -> None:
    directory.mkdir()
    with gzip.open(directory / "auth.txt.gz", "wt", encoding="utf-8") as stream:
        stream.write("1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n")
    with gzip.open(directory / "redteam.txt.gz", "wt", encoding="utf-8") as stream:
        stream.write("1,U1@D,C1,C2\n")


def test_registration_copies_validates_and_manifests(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    raw = tmp_path / "raw"
    _write_core_files(source)

    plan = plan_registration(source, raw, "core")
    manifest_path, results = execute_registration(plan, full_scan=True, quick_scan_rows=10)

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert payload["scope"] == "core"
    assert {entry["file"] for entry in payload["files"]} == {
        "auth.txt.gz",
        "redteam.txt.gz",
    }
    assert len(results) == 2
    assert len(verified_manifest_dataset_sha256(raw)) == 64
    assert not (raw / "auth.txt.gz").stat().st_mode & stat.S_IWRITE


def test_registration_refuses_to_overwrite_raw_data(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    raw = tmp_path / "raw"
    _write_core_files(source)
    raw.mkdir()
    (raw / "auth.txt.gz").write_bytes(b"existing")

    with pytest.raises(RegistrationError, match="refusing to overwrite"):
        plan_registration(source, raw, "core")


def test_registration_requires_complete_scope(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    source.mkdir()
    raw = tmp_path / "raw"

    with pytest.raises(RegistrationError, match="Missing required"):
        plan_registration(source, raw, "core")


def test_verification_rejects_raw_file_changed_since_registration(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    raw = tmp_path / "raw"
    _write_core_files(source)
    execute_registration(
        plan_registration(source, raw, "core"),
        full_scan=True,
        quick_scan_rows=10,
    )
    (raw / "auth.txt.gz").chmod(stat.S_IWRITE | stat.S_IREAD)
    with gzip.open(raw / "auth.txt.gz", "wt", encoding="utf-8") as stream:
        stream.write("2,U2@D,U2@D,C2,C3,Kerberos,Network,LogOn,Success\n")

    with pytest.raises(RegistrationError, match="hash changed"):
        verify_registered(raw, "core", full_scan=True, quick_scan_rows=10)


def test_quick_verification_keeps_full_scan_provenance(tmp_path: Path) -> None:
    """``dataset verify`` defaults to a quick scan. It must not overwrite the
    full-scan entries that ``train`` requires, because the file it just
    hashed is byte-identical to the one the full scan examined."""
    source = tmp_path / "downloads"
    raw = tmp_path / "raw"
    _write_core_files(source)
    execute_registration(
        plan_registration(source, raw, "core"), full_scan=True, quick_scan_rows=10
    )
    full_digest = verified_manifest_dataset_sha256(raw, "core")

    manifest, results = verify_registered(raw, "core", full_scan=False, quick_scan_rows=10)

    assert [r.validation_level for r in results] == ["quick", "quick"]
    persisted = json.loads(manifest.read_text(encoding="utf-8"))
    assert {f["validation_level"] for f in persisted["files"]} == {"full"}
    assert persisted["files"][0]["total_rows"] == 1
    assert isinstance(persisted["verified_at_utc"], str)
    assert verified_manifest_dataset_sha256(raw, "core") == full_digest


def test_quick_verification_before_any_full_scan_stays_quick(tmp_path: Path) -> None:
    source = tmp_path / "downloads"
    raw = tmp_path / "raw"
    _write_core_files(source)
    execute_registration(
        plan_registration(source, raw, "core"), full_scan=False, quick_scan_rows=10
    )
    manifest, _ = verify_registered(raw, "core", full_scan=False, quick_scan_rows=10)
    persisted = json.loads(manifest.read_text(encoding="utf-8"))
    assert {f["validation_level"] for f in persisted["files"]} == {"quick"}
    with pytest.raises(RegistrationError, match="complete raw-data contract"):
        verified_manifest_dataset_sha256(raw, "core")
