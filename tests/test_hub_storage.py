from __future__ import annotations

import gzip
import shutil
from pathlib import Path
from typing import Any

import pytest

from graphsentinel.datasets import hub_storage
from graphsentinel.datasets.hub_storage import (
    HubStorageError,
    pull_registered_core,
    push_registered_core,
)
from graphsentinel.datasets.registry import execute_registration, plan_registration


def _registered_core(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    raw = tmp_path / "raw"
    source.mkdir()
    with gzip.open(source / "auth.txt.gz", "wt", encoding="utf-8") as stream:
        stream.write("1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n")
    with gzip.open(source / "redteam.txt.gz", "wt", encoding="utf-8") as stream:
        stream.write("1,U1@D,C1,C2\n")
    execute_registration(
        plan_registration(source, raw, "core"),
        full_scan=True,
        quick_scan_rows=10,
    )
    return raw


class _FakeApi:
    def __init__(self) -> None:
        self.created: dict[str, Any] | None = None
        self.card: bytes | None = None
        self.upload: dict[str, Any] | None = None

    def whoami(self, *, token: bool) -> dict[str, Any]:
        assert token is True
        return {"name": "security-researcher"}

    def create_repo(self, repo_id: str, **kwargs: Any) -> None:
        self.created = {"repo_id": repo_id, **kwargs}

    def upload_file(self, *, path_or_fileobj: bytes, **kwargs: Any) -> None:
        self.card = path_or_fileobj

    def upload_folder(self, **kwargs: Any) -> None:
        self.upload = kwargs


class _FakeHub:
    def __init__(self, api: _FakeApi, snapshot_source: Path | None = None) -> None:
        self.api = api
        self.snapshot_source = snapshot_source

    def HfApi(self) -> _FakeApi:
        return self.api

    def snapshot_download(self, **kwargs: Any) -> str:
        assert self.snapshot_source is not None
        destination = Path(kwargs["local_dir"])
        for name in kwargs["allow_patterns"]:
            shutil.copyfile(self.snapshot_source / name, destination / name)
        return str(destination)


def test_push_uses_private_dataset_repo_and_verified_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = _registered_core(tmp_path)
    api = _FakeApi()
    monkeypatch.setattr(hub_storage, "_load_hub", lambda: _FakeHub(api))

    receipt = push_registered_core(raw, "security-researcher/graphsentinel-lanl")

    assert receipt.operation == "push"
    assert receipt.private is True
    assert len(receipt.dataset_sha256) == 64
    assert api.created == {
        "repo_id": "security-researcher/graphsentinel-lanl",
        "repo_type": "dataset",
        "private": True,
        "exist_ok": True,
        "token": True,
    }
    assert api.card is not None and b"GraphSentinel LANL core storage" in api.card
    assert api.upload is not None
    assert set(api.upload["allow_patterns"]) == {
        "auth.txt.gz",
        "redteam.txt.gz",
        "manifest.json",
    }


def test_pull_verifies_snapshot_hashes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _registered_core(tmp_path)
    destination = tmp_path / "restore"
    monkeypatch.setattr(
        hub_storage,
        "_load_hub",
        lambda: _FakeHub(_FakeApi(), snapshot_source=raw),
    )

    receipt = pull_registered_core(
        "security-researcher/graphsentinel-lanl",
        destination,
    )

    assert receipt.operation == "pull"
    assert (destination / "auth.txt.gz").is_file()
    assert (destination / "redteam.txt.gz").is_file()
    assert len(receipt.dataset_sha256) == 64


def test_pull_rejects_existing_protected_file(tmp_path: Path) -> None:
    destination = tmp_path / "restore"
    destination.mkdir()
    (destination / "auth.txt.gz").write_bytes(b"existing")

    with pytest.raises(HubStorageError, match="refusing to overwrite"):
        pull_registered_core("security-researcher/graphsentinel-lanl", destination)


def test_repo_id_requires_namespace(tmp_path: Path) -> None:
    with pytest.raises(HubStorageError, match="username-or-org"):
        push_registered_core(tmp_path, "missing-namespace")
