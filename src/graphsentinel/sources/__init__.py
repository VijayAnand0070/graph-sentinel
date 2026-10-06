"""Authentication log sources: one normalized event, many formats.

``FORMATS`` is the registry the CLI reads. Every adapter yields
:class:`SourceEvent`; the offline ingest (``ingestion/generic.py``) and the
live forwarder consume that and nothing else, so adding a format is adding a
file here and a row in the table.

=================  ==============================================================
format             what it reads
=================  ==============================================================
``windows-json``   Windows Security events as JSON lines (SIEM exports,
                   winlogbeat, OTRF Security-Datasets); XML via ``ingestion/windows``
``ssh-auth``       Linux ``sshd`` lines from ``auth.log`` / ``secure``
``zeek``           Zeek ``kerberos.log`` and ``ntlm.log`` (JSON or TSV)
``entra-signin``   Microsoft Entra ID sign-in logs (Graph ``signIns``)
``okta``           Okta System Log
``tabular``        any CSV / JSON lines through a column map
``lanl``           the research corpus itself, through ``ingest auth``
``auto``           whichever of the above the file turns out to be, sniffed
                   from its first lines (``sources/detect.py``); for a format
                   with no adapter, the column map is inferred from the header
=================  ==============================================================
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path

from graphsentinel.sources.base import (
    Adapter,
    ParseStats,
    SourceEvent,
    canonical_host,
    canonical_user,
    parse_timestamp,
)
from graphsentinel.sources.cloud import EntraSignIns, OktaSystemLog
from graphsentinel.sources.detect import (
    Detection,
    UnknownLogFormat,
    sniff,
    sniff_path,
    sniff_paths,
)
from graphsentinel.sources.ssh import SSHAuthLog
from graphsentinel.sources.tabular import ColumnMap, TabularAuthLog
from graphsentinel.sources.windows import WindowsJsonEvents
from graphsentinel.sources.zeek import ZeekAuthLog

AdapterFactory = Callable[..., Adapter]

FORMATS: dict[str, AdapterFactory] = {
    "windows-json": lambda **_: WindowsJsonEvents(),
    "ssh-auth": lambda assume_year=None, **_: SSHAuthLog(assume_year=assume_year),
    "zeek": lambda **_: ZeekAuthLog(),
    "entra-signin": lambda **_: EntraSignIns(),
    "okta": lambda **_: OktaSystemLog(),
    "tabular": lambda column_map=None, assume_year=None, **_: TabularAuthLog(
        ColumnMap.parse(column_map or ""), assume_year=assume_year
    ),
}

DESCRIPTIONS: dict[str, str] = {
    "windows-json": WindowsJsonEvents.description,
    "ssh-auth": SSHAuthLog.description,
    "zeek": ZeekAuthLog.description,
    "entra-signin": EntraSignIns.description,
    "okta": OktaSystemLog.description,
    "tabular": TabularAuthLog.description,
}


def adapter_for(
    name: str, *, column_map: str | None = None, assume_year: int | None = None
) -> Adapter:
    try:
        factory = FORMATS[name]
    except KeyError as error:
        raise ValueError(f"unknown source format {name!r}; known: {sorted(FORMATS)}") from error
    return factory(column_map=column_map, assume_year=assume_year)


def resolve_format(
    name: str,
    paths: Sequence[Path],
    *,
    column_map: str | None = None,
) -> tuple[str, str | None, Detection | None]:
    """Settle on a format and a column map for these files.

    ``auto`` sniffs the inputs and returns what they are; any other name is
    taken at face value. An explicit ``column_map`` always wins over an
    inferred one -- a detection is a starting point an operator may correct,
    never an override of what they asked for.
    """
    if name != "auto":
        return name, column_map, None
    detection = sniff_paths(list(paths))
    return detection.format, column_map or detection.column_map, detection


def read_lines(paths: Iterable[Path]) -> Iterator[str]:
    """Lines from plain or gzip-compressed files, in the order given."""
    import gzip

    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
            yield from handle


__all__ = [
    "DESCRIPTIONS",
    "FORMATS",
    "Adapter",
    "ColumnMap",
    "Detection",
    "EntraSignIns",
    "OktaSystemLog",
    "ParseStats",
    "SSHAuthLog",
    "SourceEvent",
    "TabularAuthLog",
    "UnknownLogFormat",
    "WindowsJsonEvents",
    "ZeekAuthLog",
    "adapter_for",
    "canonical_host",
    "canonical_user",
    "parse_timestamp",
    "read_lines",
    "resolve_format",
    "sniff",
    "sniff_path",
    "sniff_paths",
]
