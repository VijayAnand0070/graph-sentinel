"""Deterministic, append-only categorical ID maps."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

UNKNOWN_TOKEN = "<UNKNOWN>"


def auth_id_map_sha256(directory: Path) -> str:
    digest = hashlib.sha256()
    for name in ("users", "hosts", "auth_types", "logon_types", "orientations"):
        path = directory / f"{name}.json"
        digest.update(name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


@dataclass(slots=True)
class StableIdMap:
    """Assign compact IDs in first-observed chronological order.

    ID zero is permanently reserved for missing/unknown values. Persisted maps can be reloaded
    and extended without changing any previously assigned ID.
    """

    namespace: str
    _value_to_id: dict[str, int] = field(default_factory=lambda: {UNKNOWN_TOKEN: 0}, repr=False)

    def __post_init__(self) -> None:
        if self._value_to_id.get(UNKNOWN_TOKEN) != 0:
            raise ValueError("ID zero must be reserved for <UNKNOWN>")
        ids = sorted(self._value_to_id.values())
        if ids != list(range(len(ids))):
            raise ValueError("IDs must be unique and contiguous from zero")

    def encode(self, value: str | None) -> int:
        normalized = value.strip() if value is not None else ""
        if not normalized or normalized == "?":
            return 0
        existing = self._value_to_id.get(normalized)
        if existing is not None:
            return existing
        assigned = len(self._value_to_id)
        self._value_to_id[normalized] = assigned
        return assigned

    def mark(self) -> int:
        """Position to roll back to: ids are assigned sequentially from the size."""
        return len(self._value_to_id)

    def rollback(self, mark: int) -> None:
        """Forget every value encoded since ``mark``. Cheap: the dict is
        insertion-ordered and new ids are always the highest."""
        for value in [v for v, i in self._value_to_id.items() if i >= mark]:
            del self._value_to_id[value]

    def lookup(self, value: str | None) -> int | None:
        normalized = value.strip() if value is not None else ""
        if not normalized or normalized == "?":
            return 0
        return self._value_to_id.get(normalized)

    def __len__(self) -> int:
        return len(self._value_to_id)

    def to_dict(self) -> dict[str, object]:
        values = [
            value
            for value, _identifier in sorted(self._value_to_id.items(), key=lambda item: item[1])
        ]
        return {"schema_version": 1, "namespace": self.namespace, "values": values}

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)

    @classmethod
    def load(cls, path: Path, *, expected_namespace: str | None = None) -> StableIdMap:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise ValueError(f"Unsupported ID-map schema in {path}")
        namespace = payload.get("namespace")
        if not isinstance(namespace, str):
            raise ValueError(f"Invalid namespace in {path}")
        if expected_namespace is not None and namespace != expected_namespace:
            raise ValueError(f"Expected namespace {expected_namespace!r}, found {namespace!r}")
        values = payload.get("values")
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise ValueError(f"Invalid values in {path}")
        mapping = {value: index for index, value in enumerate(values)}
        if len(mapping) != len(values):
            raise ValueError(f"Duplicate value in {path}")
        return cls(namespace=namespace, _value_to_id=mapping)


@dataclass(slots=True)
class AuthIdMaps:
    users: StableIdMap = field(default_factory=lambda: StableIdMap("users"))
    hosts: StableIdMap = field(default_factory=lambda: StableIdMap("hosts"))
    auth_types: StableIdMap = field(default_factory=lambda: StableIdMap("auth_types"))
    logon_types: StableIdMap = field(default_factory=lambda: StableIdMap("logon_types"))
    orientations: StableIdMap = field(default_factory=lambda: StableIdMap("orientations"))

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for name, mapping in self.items():
            mapping.save(directory / f"{name}.json")

    def items(self) -> tuple[tuple[str, StableIdMap], ...]:
        return (
            ("users", self.users),
            ("hosts", self.hosts),
            ("auth_types", self.auth_types),
            ("logon_types", self.logon_types),
            ("orientations", self.orientations),
        )

    @classmethod
    def load(cls, directory: Path) -> AuthIdMaps:
        return cls(
            users=StableIdMap.load(directory / "users.json", expected_namespace="users"),
            hosts=StableIdMap.load(directory / "hosts.json", expected_namespace="hosts"),
            auth_types=StableIdMap.load(
                directory / "auth_types.json", expected_namespace="auth_types"
            ),
            logon_types=StableIdMap.load(
                directory / "logon_types.json", expected_namespace="logon_types"
            ),
            orientations=StableIdMap.load(
                directory / "orientations.json", expected_namespace="orientations"
            ),
        )
