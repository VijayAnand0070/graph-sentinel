"""One authentication event, whatever produced it.

Every adapter in this package turns its own log format into :class:`SourceEvent`
-- the vendor-neutral shape the live gateway accepts and the offline ingest
normalises -- so the rest of the product never sees a format. The graph the
detector reasons about is *accounts moving between machines*; any log that
records "this identity, from here, authenticated to there, at this time" can
feed it.

Skips are counted, never silent: a line the adapter cannot turn into an edge
between two distinct entities is recorded under a reason, and the ingestion
report says how many of each. An unexplained gap between lines read and events
produced is how an integration goes wrong quietly.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from graphsentinel.ingestion.windows import canonical_host as _windows_host
from graphsentinel.ingestion.windows import canonical_user as _windows_user


@dataclass(frozen=True, slots=True)
class SourceEvent:
    """The gateway's vocabulary. ``timestamp`` is epoch seconds."""

    timestamp: int
    user: str
    source_host: str
    destination_host: str
    destination_user: str | None = None
    auth_type: str = "unknown"
    logon_type: str = "unknown"
    orientation: str = "LogOn"
    success: bool = True
    source: str = "generic"

    @property
    def is_self_loop(self) -> bool:
        return self.source_host == self.destination_host

    def to_payload(self) -> dict[str, Any]:
        """Exactly what ``POST /api/v1/live/events`` accepts."""
        return {
            "timestamp": self.timestamp,
            "user": self.user,
            "source_host": self.source_host,
            "destination_host": self.destination_host,
            "destination_user": self.destination_user,
            "auth_type": self.auth_type,
            "logon_type": self.logon_type,
            "orientation": self.orientation,
            "success": self.success,
            "source": self.source,
        }

    def key(self) -> tuple[int, str, str, str]:
        """The label key: ``(time, user, source host, destination host)``."""
        return (self.timestamp, self.user, self.source_host, self.destination_host)


@dataclass
class ParseStats:
    lines: int = 0
    events: int = 0
    skipped: Counter[str] = field(default_factory=Counter)

    def skip(self, reason: str) -> None:
        self.skipped[reason] += 1

    def to_dict(self) -> dict[str, object]:
        return {"lines": self.lines, "events": self.events, "skipped": dict(self.skipped)}


class Adapter(Protocol):
    """A log format. ``parse`` yields events in file order; callers sort."""

    name: str
    description: str
    #: A few lines in the format, used by tests and by ``sources describe``.
    sample: str

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]: ...


_MONTHS = {
    m: i
    for i, m in enumerate(
        ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"),
        start=1,
    )
}
_SYSLOG = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")


def parse_timestamp(value: object, *, assume_year: int | None = None) -> int | None:
    """Epoch seconds from the shapes logs actually use.

    ISO 8601 with ``Z`` or an offset (fractional seconds of any width),
    epoch seconds or milliseconds, and the year-less BSD syslog stamp
    (``Jan  5 10:00:00``), which needs ``assume_year``. Naive stamps are UTC.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
        if number > 1e11:  # milliseconds
            number /= 1000.0
        return int(number) if number >= 0 else None
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", text):
        return parse_timestamp(float(text))
    match = _SYSLOG.match(text)
    if match:
        if assume_year is None:
            return None
        month = _MONTHS.get(match.group("mon").lower())
        if month is None:
            return None
        hour, minute, second = (int(x) for x in match.group("time").split(":"))
        stamp = datetime(
            assume_year, month, int(match.group("day")), hour, minute, second, tzinfo=UTC
        )
        return int(stamp.timestamp())
    iso = text.replace("Z", "+00:00")
    iso = re.sub(r"\.(\d{6})\d+", r".\1", iso)
    if " " in iso and "T" not in iso:
        iso = iso.replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp())


def canonical_host(value: object) -> str:
    """One identity rule for every source: the Windows adapter's.

    ``WS001.corp.local``, ``WS001``, ``ws001$`` are one host; IP addresses are
    kept verbatim. Sharing the function is what lets a Zeek sensor and the
    host's own Security log agree on which machine they are talking about.
    """
    return _windows_host(str(value) if value is not None else None)


def canonical_user(name: object, domain: object = None) -> str:
    """``user@REALM`` with the realm folded to its first label, as Windows does."""
    return _windows_user(
        str(name) if name is not None else None, str(domain) if domain is not None else None
    )


__all__ = [
    "Adapter",
    "ParseStats",
    "SourceEvent",
    "canonical_host",
    "canonical_user",
    "parse_timestamp",
]
