"""Linux ``sshd`` authentication lines from ``auth.log`` / ``secure``.

SSH is the lateral-movement transport on Linux estates: a credential (or a
stolen key) hopping between hosts leaves one ``Accepted`` line on each
destination, and the failures around it. The destination is the host that
wrote the line; the source is the client address sshd recorded.

Handles both syslog stamp styles -- the year-less BSD form (``Jan  5
10:00:00``, needs ``assume_year``) and rsyslog's ISO form -- and the message
forms::

    Accepted publickey for alice from 10.0.0.5 port 51234 ssh2: RSA SHA256:...
    Failed password for bob from 10.0.0.7 port 2222 ssh2
    Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2
    Invalid user admin from 203.0.113.9 port 4444

``Disconnected``, ``session opened`` and the rest are not authentications and
are skipped, counted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from graphsentinel.sources.base import (
    ParseStats,
    SourceEvent,
    canonical_host,
    canonical_user,
    parse_timestamp,
)

_LINE = re.compile(
    r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\S+T\S+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<source>\S+) port \d+"
)
_FAILED = re.compile(
    r"^Failed (?P<method>[\w/-]+) for (?:invalid user )?(?P<user>\S+) from (?P<source>\S+) port \d+"
)
_INVALID = re.compile(r"^Invalid user (?P<user>\S+) from (?P<source>\S+)")


class SSHAuthLog:
    name = "ssh-auth"
    description = "Linux sshd lines from auth.log / secure (BSD or ISO syslog stamps)"
    sample = (
        "2026-03-02T09:14:03.120000+00:00 web01 sshd[2211]: Accepted publickey for alice "
        "from 10.0.0.5 port 51234 ssh2: RSA SHA256:abc\n"
        "2026-03-02T09:14:40.000000+00:00 db01 sshd[871]: Failed password for bob from "
        "10.0.0.7 port 2222 ssh2\n"
        "2026-03-02T09:15:01.000000+00:00 db01 sshd[871]: Accepted password for bob from "
        "10.0.0.7 port 2222 ssh2\n"
        "2026-03-02T09:15:02.000000+00:00 db01 sshd[871]: pam_unix(sshd:session): session "
        "opened for user bob\n"
        "Mar  2 09:16:00 app02 sshd[1900]: Failed password for invalid user admin from "
        "203.0.113.9 port 4444 ssh2\n"
    )

    def __init__(self, *, assume_year: int | None = None) -> None:
        self.assume_year = assume_year

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        for raw in lines:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            stats.lines += 1
            match = _LINE.match(line)
            if match is None:
                stats.skip("not_sshd")
                continue
            message = match.group("message")
            accepted = _ACCEPTED.match(message)
            failed = _FAILED.match(message) if accepted is None else None
            invalid = _INVALID.match(message) if accepted is None and failed is None else None
            hit = accepted or failed or invalid
            if hit is None:
                stats.skip("not_authentication")
                continue
            timestamp = parse_timestamp(match.group("stamp"), assume_year=self.assume_year)
            if timestamp is None:
                stats.skip("bad_timestamp" if self.assume_year else "year_needed")
                continue
            destination = canonical_host(match.group("host"))
            source = canonical_host(hit.group("source"))
            user = canonical_user(hit.group("user"))
            if not destination or not source or not user:
                stats.skip("missing_entity")
                continue
            if source == destination:
                stats.skip("self_loop")
                continue
            method = hit.groupdict().get("method") or "password"
            stats.events += 1
            yield SourceEvent(
                timestamp=timestamp,
                user=user,
                source_host=source,
                destination_host=destination,
                destination_user=user,
                auth_type=f"ssh-{method}",
                logon_type="Remote",
                orientation="LogOn",
                success=accepted is not None,
                source="ssh",
            )


__all__ = ["SSHAuthLog"]
