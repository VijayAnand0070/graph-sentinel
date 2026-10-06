"""Private Hugging Face Hub storage for verified LANL dataset artifacts."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from graphsentinel.datasets.catalog import LANL_DOI, LANL_SOURCE_PAGE, required_specs
from graphsentinel.datasets.registry import RegistrationError, verified_manifest_dataset_sha256

_REPO_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")


class HubStorageError(RuntimeError):
    """Raised when a safe Hub storage operation cannot continue."""


class _HubApi(Protocol):
    def whoami(self, *, token: bool) -> dict[str, Any]: ...

    def create_repo(
        self,
        repo_id: str,
        *,
        repo_type: str,
        private: bool,
        exist_ok: bool,
        token: bool,
    ) -> object: ...

    def upload_file(
        self,
        *,
        path_or_fileobj: bytes,
        path_in_repo: str,
        repo_id: str,
        repo_type: str,
        revision: str,
        token: bool,
        commit_message: str,
    ) -> object: ...

    def upload_folder(
        self,
        *,
        folder_path: Path,
        repo_id: str,
        repo_type: str,
        revision: str,
        token: bool,
        allow_patterns: list[str],
        commit_message: str,
    ) -> object: ...


class _HubModule(Protocol):
    def HfApi(self) -> _HubApi: ...

    def snapshot_download(
        self,
        *,
        repo_id: str,
        repo_type: str,
        revision: str,
        local_dir: Path,
        token: bool,
        allow_patterns: list[str],
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class HubStorageReceipt:
    operation: str
    repo_id: str
    revision: str
    local_dir: str
    dataset_sha256: str
    files: tuple[str, ...]
    private: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready transfer receipt."""

        return asdict(self)


def _load_hub() -> _HubModule:
    try:
        module = importlib.import_module("huggingface_hub")
    except ImportError as error:
        raise HubStorageError(
            "Hugging Face support is not installed; install GraphSentinel with the `hub` extra"
        ) from error
    return cast(_HubModule, module)


def _validate_repo_id(repo_id: str) -> None:
    if not _REPO_ID.fullmatch(repo_id):
        raise HubStorageError("repo_id must use the form `username-or-org/repository-name`")


def _manifest(raw_dir: Path) -> tuple[dict[str, Any], str]:
    try:
        dataset_sha256 = verified_manifest_dataset_sha256(raw_dir, "core")
        payload = json.loads((raw_dir / "manifest.json").read_text(encoding="utf-8"))
    except (RegistrationError, FileNotFoundError, json.JSONDecodeError, OSError) as error:
        raise HubStorageError(f"A verified full-scan core manifest is required: {error}") from error
    if not isinstance(payload, dict):
        raise HubStorageError("The raw manifest must contain a JSON object")
    return payload, dataset_sha256


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_downloaded_files(local_dir: Path) -> str:
    manifest, dataset_sha256 = _manifest(local_dir)
    inventory = manifest.get("files")
    if not isinstance(inventory, list):
        raise HubStorageError("The downloaded manifest has no file inventory")
    expected = {
        entry.get("file"): entry.get("sha256") for entry in inventory if isinstance(entry, dict)
    }
    for spec in required_specs("core"):
        path = local_dir / spec.name
        if not path.is_file():
            raise HubStorageError(f"Hub snapshot is missing {spec.name}")
        digest = _sha256(path)
        if digest != expected.get(spec.name):
            raise HubStorageError(f"Hub snapshot hash mismatch for {spec.name}")
    return dataset_sha256


def _dataset_card(repo_id: str, dataset_sha256: str) -> bytes:
    content = f"""---
license: cc0-1.0
task_categories:
- anomaly-detection
tags:
- cybersecurity
- temporal-graph
- lanl
---

# GraphSentinel LANL core storage

Private storage mirror used by GraphSentinel for reproducible TGN training. It contains the
registered `auth.txt.gz`, `redteam.txt.gz`, and their immutable full-scan provenance manifest.

- Repository: `{repo_id}`
- Canonical dataset SHA-256: `{dataset_sha256}`
- Source: {LANL_SOURCE_PAGE}
- DOI: {LANL_DOI}

The manifest records per-file hashes, schema validation, row integrity, and timestamp ordering.
"""
    return content.encode("utf-8")


def push_registered_core(
    raw_dir: Path,
    repo_id: str,
    *,
    revision: str = "main",
) -> HubStorageReceipt:
    """Upload only verified core files to a private Hub dataset repository."""

    _validate_repo_id(repo_id)
    raw_dir = raw_dir.resolve()
    _, dataset_sha256 = _manifest(raw_dir)
    names = (*(spec.name for spec in required_specs("core")), "manifest.json")
    for name in names:
        if not (raw_dir / name).is_file():
            raise HubStorageError(f"Verified raw storage is missing {name}")

    hub = _load_hub()
    api = hub.HfApi()
    try:
        identity = api.whoami(token=True)
        if not isinstance(identity.get("name"), str):
            raise HubStorageError("Hugging Face authentication returned no username")
        api.create_repo(
            repo_id,
            repo_type="dataset",
            private=True,
            exist_ok=True,
            token=True,
        )
        api.upload_file(
            path_or_fileobj=_dataset_card(repo_id, dataset_sha256),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="dataset",
            revision=revision,
            token=True,
            commit_message="Add GraphSentinel dataset card",
        )
        api.upload_folder(
            folder_path=raw_dir,
            repo_id=repo_id,
            repo_type="dataset",
            revision=revision,
            token=True,
            allow_patterns=list(names),
            commit_message="Store verified GraphSentinel LANL core dataset",
        )
    except HubStorageError:
        raise
    except Exception as error:
        raise HubStorageError(f"Hugging Face upload failed: {error}") from error

    return HubStorageReceipt(
        operation="push",
        repo_id=repo_id,
        revision=revision,
        local_dir=str(raw_dir),
        dataset_sha256=dataset_sha256,
        files=names,
        private=True,
    )


def pull_registered_core(
    repo_id: str,
    destination: Path,
    *,
    revision: str = "main",
) -> HubStorageReceipt:
    """Download a private core snapshot and verify every file against its manifest."""

    _validate_repo_id(repo_id)
    destination = destination.resolve()
    names = (*(spec.name for spec in required_specs("core")), "manifest.json")
    collisions = [name for name in names if (destination / name).exists()]
    if collisions:
        raise HubStorageError(
            "Destination already contains protected files; refusing to overwrite: "
            + ", ".join(collisions)
        )
    destination.mkdir(parents=True, exist_ok=True)

    hub = _load_hub()
    try:
        hub.snapshot_download(
            repo_id=repo_id,
            repo_type="dataset",
            revision=revision,
            local_dir=destination,
            token=True,
            allow_patterns=list(names),
        )
        dataset_sha256 = _verify_downloaded_files(destination)
    except HubStorageError:
        raise
    except Exception as error:
        raise HubStorageError(f"Hugging Face download failed: {error}") from error

    return HubStorageReceipt(
        operation="pull",
        repo_id=repo_id,
        revision=revision,
        local_dir=str(destination),
        dataset_sha256=dataset_sha256,
        files=names,
        private=True,
    )
