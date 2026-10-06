"""Authoritative raw schemas for the LANL comprehensive dataset."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

LANL_SOURCE_PAGE = "https://csr.lanl.gov/data/cyber1/"
LANL_DOI = "10.17021/1179829"


@dataclass(frozen=True, slots=True)
class DatasetFileSpec:
    """Immutable expectations for one LANL source file."""

    name: str
    columns: tuple[str, ...]
    scope: str
    approximate_compressed_bytes: int

    @property
    def column_count(self) -> int:
        return len(self.columns)


_SPECS = {
    "auth.txt.gz": DatasetFileSpec(
        name="auth.txt.gz",
        columns=(
            "time",
            "src_user",
            "dst_user",
            "src_host",
            "dst_host",
            "auth_type",
            "logon_type",
            "orientation",
            "success",
        ),
        scope="core",
        approximate_compressed_bytes=7_200_000_000,
    ),
    "redteam.txt.gz": DatasetFileSpec(
        name="redteam.txt.gz",
        columns=("time", "user", "src_host", "dst_host"),
        scope="core",
        approximate_compressed_bytes=4_800,
    ),
    "proc.txt.gz": DatasetFileSpec(
        name="proc.txt.gz",
        columns=("time", "user", "host", "process", "action"),
        scope="enrichment",
        approximate_compressed_bytes=2_200_000_000,
    ),
    "flows.txt.gz": DatasetFileSpec(
        name="flows.txt.gz",
        columns=(
            "time",
            "duration",
            "src_host",
            "src_port",
            "dst_host",
            "dst_port",
            "protocol",
            "packets",
            "bytes",
        ),
        scope="enrichment",
        approximate_compressed_bytes=1_100_000_000,
    ),
    "dns.txt.gz": DatasetFileSpec(
        name="dns.txt.gz",
        columns=("time", "src_host", "resolved_host"),
        scope="enrichment",
        approximate_compressed_bytes=177_000_000,
    ),
}

LANL_FILE_SPECS = MappingProxyType(_SPECS)


def required_specs(scope: str) -> tuple[DatasetFileSpec, ...]:
    """Return deterministic file requirements for ``core`` or ``all`` scope."""

    if scope not in {"core", "all"}:
        raise ValueError(f"Unsupported dataset scope: {scope!r}")
    return tuple(
        spec for spec in LANL_FILE_SPECS.values() if scope == "all" or spec.scope == "core"
    )
