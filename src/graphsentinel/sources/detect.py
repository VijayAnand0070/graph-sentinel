"""Work out which authentication log this is, and how to read it.

Every adapter in this package already turns its own format into
:class:`SourceEvent`. The gap this module closes is the first five minutes on
a new estate: an operator has a file, and naming the format -- and, for
anything without a dedicated adapter, naming which column holds the account
and which holds the destination -- is a step they have to get right before
anything runs at all.

:func:`sniff` reads a bounded sample of lines and answers both questions.
Formats with a dedicated adapter are recognised by the fields only they
carry (a Windows event ID, Zeek's ``id.orig_h``, Okta's ``eventType``, an
Entra ``userPrincipalName``, sshd's tag). Anything else is CSV or JSON lines
from a SIEM or an identity system nobody has written an adapter for, and for
those the column map is *inferred* from the header names, which is exactly
the guess an operator would otherwise make by hand.

Inference is a guess, so it is reported as one: every detection carries the
evidence it matched, a confidence, and warnings about anything that looked
wrong (a success column whose values mean nothing to the parser, a
destination column that is mostly equal to the source). ``sources sniff``
prints all of it and the ``--map`` it would use, so the operator can accept
it or correct it. Nothing about detection is silent, because a mis-mapped
column produces a detector that runs happily on the wrong graph.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from typing import Any

from graphsentinel.sources.base import parse_timestamp
from graphsentinel.sources.tabular import REQUIRED, TRUE_WORDS

#: How many lines are enough to recognise a format. A log whose first two
#: hundred lines say nothing about its shape is one an operator must name.
SAMPLE_LINES = 200

_SSHD = re.compile(r"\bsshd(\[\d+\])?:")
_ZEEK_JSON_KEYS = ("id.orig_h", "id.resp_h")
_WINDOWS_ID_KEYS = ("EventID", "event_id", "EventId", "event.code")


@dataclass(frozen=True, slots=True)
class Detection:
    """What the sniffer concluded, and what it saw."""

    format: str
    confidence: float
    #: The ``--map`` string for ``tabular``; ``None`` for formats that need none.
    column_map: str | None = None
    #: What matched, in the order it was checked.
    reasons: tuple[str, ...] = ()
    #: Things that parse but may not mean what the map says.
    warnings: tuple[str, ...] = ()
    #: field -> column, for display; empty unless the format is ``tabular``.
    fields: dict[str, str] = field(default_factory=dict)
    lines_sampled: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "confidence": round(self.confidence, 3),
            "column_map": self.column_map,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "fields": dict(self.fields),
            "lines_sampled": self.lines_sampled,
        }


class UnknownLogFormat(ValueError):
    """Raised when nothing in the sample identifies an authentication log."""


# --------------------------------------------------------------------------
# column inference
# --------------------------------------------------------------------------

def _normalise(name: str) -> str:
    """``Source Host`` / ``src-host`` / ``SourceHost`` -> ``sourcehost``."""
    return re.sub(r"[^a-z0-9]", "", name.strip().lower())


#: Header names seen in real exports, best first. Matching is exact on the
#: normalised name; a prefix/suffix pass follows for compound names.
SYNONYMS: dict[str, tuple[str, ...]] = {
    "timestamp": (
        "timestamp", "time", "eventtime", "datetime", "date", "ts", "when",
        "createddatetime", "created", "createdat", "logtime", "occurredat",
        "starttime", "eventtimestamp", "published", "authtime", "logontime",
        "receivedtime", "firstseen", "timegenerated", "timecreated",
    ),
    "user": (
        "user", "username", "account", "accountname", "username1", "principal",
        "upn", "userprincipalname", "subject", "actor", "identity", "login",
        "logonuser", "samaccountname", "srcuser", "sourceuser", "useridentity",
        "accountupn", "targetusername", "callername", "who", "userid", "userkey",
    ),
    "source_host": (
        "sourcehost", "srchost", "source", "src", "client", "clienthost",
        "workstation", "workstationname", "sourcecomputer", "origin",
        "sourcemachine", "clientname", "sourceip", "srcip", "clientip",
        "ipaddress", "sourceaddress", "fromhost", "originhost", "devicename",
    ),
    "destination_host": (
        "destinationhost", "dsthost", "destination", "dst", "dest", "desthost",
        "target", "targethost", "server", "servername", "resource",
        "destinationcomputer", "destinationip", "dstip", "destip",
        "targetserver", "tohost", "destinationaddress", "computer", "hostname",
        "host", "machine", "targetresource",
    ),
    "success": (
        "success", "result", "outcome", "status", "authresult", "eventoutcome",
        "disposition", "resultcode", "logonresult", "authenticationresult",
        "succeeded", "issuccess", "ok", "allowed", "granted", "action", "verdict",
        "decision", "authstatus", "eventresult",
    ),
    "auth_type": (
        "authtype", "authenticationtype", "protocol", "authprotocol",
        "authenticationpackage", "authenticationpackagename", "mechanism",
        "authmethod", "authenticationmethod", "package",
    ),
    "logon_type": (
        "logontype", "logintype", "sessiontype", "type", "authtypecode",
        "connectiontype",
    ),
    "destination_user": (
        "destinationuser", "targetuser", "dstuser", "impersonateduser",
        "runasuser",
    ),
    "domain": ("domain", "domainname", "realm", "tenant", "tenantid", "ntdomain"),
}

#: Tokens that name the *role* a column plays and tokens that name the
#: *thing* it holds. A header is read as both: ``src_machine`` is a role
#: (``src``) applied to a thing (``machine``), which is how a column nobody
#: has ever seen before still lands on the right field.
ROLE_TOKENS: dict[str, tuple[str, ...]] = {
    "source_host": ("src", "source", "client", "origin", "from", "workstation", "caller",
                    "initiator", "local", "requesting"),
    "destination_host": ("dst", "dest", "destination", "target", "to", "remote", "server",
                         "resource", "requested", "accessed"),
    "user": ("user", "account", "principal", "actor", "subject", "identity", "login",
             "logon", "upn", "sam", "caller"),
    "destination_user": ("targetuser", "destuser", "dstuser", "impersonated", "runas"),
    "timestamp": ("time", "timestamp", "date", "created", "published", "occurred", "logged"),
    "success": ("success", "result", "outcome", "status", "disposition", "succeeded"),
    "auth_type": ("auth", "authentication", "protocol", "mechanism", "package"),
    "logon_type": ("logon", "login", "session", "connection"),
    "domain": ("domain", "realm", "tenant"),
}

HOST_TOKENS = ("host", "hostname", "machine", "computer", "device", "server", "workstation",
               "node", "endpoint", "ip", "ipaddress", "address", "system", "asset", "name")
USER_TOKENS = ("user", "username", "account", "accountname", "principal", "upn", "name", "id")
TIME_TOKENS = ("time", "timestamp", "date", "datetime", "epoch", "utc", "at")
TYPE_TOKENS = ("type", "method", "protocol", "package", "mechanism", "kind")

#: Fields are matched in this order, and a column is used once: ``user`` sees
#: ``targetusername`` before ``destination_user`` can take it, and the two
#: host fields are resolved together by score rather than first-come.
_ORDER = (
    "timestamp",
    "user",
    "source_host",
    "destination_host",
    "success",
    "auth_type",
    "logon_type",
    "destination_user",
    "domain",
)


def _tokens(name: str) -> list[str]:
    """``TargetServerName`` / ``target_server_name`` -> ['target','server','name']."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name.strip())
    parts = re.split(r"[^A-Za-z0-9]+", spaced)
    return [part.lower() for part in parts if part]


def _score(field_name: str, header: str) -> float:
    """How well this column name fits this field. 0 means "not at all"."""
    norm = _normalise(header)
    if not norm:
        return 0.0
    if norm in SYNONYMS[field_name]:
        return 10.0
    tokens = _tokens(header)
    token_set = set(tokens)
    roles = ROLE_TOKENS[field_name]
    thing = {
        "source_host": HOST_TOKENS,
        "destination_host": HOST_TOKENS,
        "user": USER_TOKENS,
        "destination_user": USER_TOKENS,
        "timestamp": TIME_TOKENS,
        "success": (),
        "auth_type": TYPE_TOKENS,
        "logon_type": TYPE_TOKENS,
        "domain": (),
    }[field_name]
    has_role = any(token in roles for token in token_set) or any(
        norm.startswith(role) or norm.endswith(role) for role in roles if len(role) >= 4
    )
    has_thing = (not thing) or any(token in thing for token in token_set)
    if has_role and has_thing:
        # Two roles in one name (``source_target_host``) is ambiguous, not a
        # better match, so a competing role costs the score rather than
        # leaving it to column order.
        competing = {
            "source_host": "destination_host",
            "destination_host": "source_host",
        }.get(field_name)
        if competing and any(token in ROLE_TOKENS[competing] for token in token_set):
            return 2.0
        return 6.0 if len(token_set) > 1 else 5.0
    # A bare thing with no role: ``host``, ``computer``, ``time``. Only the
    # fields where an unqualified name has a conventional meaning take it.
    if not has_role and has_thing and field_name in {"destination_host", "timestamp", "user"}:
        return 3.0 if token_set & set(thing) else 0.0
    return 0.0


def infer_column_map(
    headers: Sequence[str], rows: Sequence[dict[str, Any]] = ()
) -> tuple[dict[str, str], list[str]]:
    """Map fields to columns by name, then sanity-check against the values.

    Scores every (field, column) pair and assigns the best first, so the two
    host fields settle against each other instead of by column order: with
    ``src_machine`` and ``dest_machine`` present, neither can be claimed by
    the wrong side merely for being earlier in the file.

    Returns ``(fields, warnings)``. A field with no plausible column is simply
    absent, and the caller decides whether that is fatal (it is, for the four
    required ones).
    """

    candidates: list[tuple[float, int, str, str]] = []
    for rank, field_name in enumerate(_ORDER):
        for header in headers:
            if not header:
                continue
            score = _score(field_name, header)
            if score > 0:
                candidates.append((score, -rank, field_name, header))
    candidates.sort(reverse=True)

    fields: dict[str, str] = {}
    taken: set[str] = set()
    for _score_value, _rank, field_name, header in candidates:
        if field_name in fields or header in taken:
            continue
        fields[field_name] = header
        taken.add(header)

    warnings: list[str] = []
    if rows:
        warnings.extend(_check_values(fields, rows))
    return fields, warnings


def _column_values(rows: Sequence[dict[str, Any]], column: str) -> list[str]:
    return [str(row.get(column, "")).strip() for row in rows if row.get(column) not in (None, "")]


def _check_values(fields: dict[str, str], rows: Sequence[dict[str, Any]]) -> list[str]:
    """Does the data behave the way the mapping claims?"""
    warnings: list[str] = []

    if "timestamp" in fields:
        values = _column_values(rows, fields["timestamp"])
        unreadable = [v for v in values if parse_timestamp(v) is None]
        if values and len(unreadable) == len(values):
            warnings.append(
                f"no value in {fields['timestamp']!r} parses as a time "
                f"(first: {values[0]!r}); year-less syslog stamps need --assume-year"
            )
    if "source_host" in fields and "destination_host" in fields:
        pairs = [
            (str(row.get(fields["source_host"], "")), str(row.get(fields["destination_host"], "")))
            for row in rows
        ]
        same = sum(1 for a, b in pairs if a and a == b)
        if pairs and same == len(pairs):
            warnings.append(
                f"{fields['source_host']!r} and {fields['destination_host']!r} hold the same "
                "value on every sampled row; this log may not record where the login came from"
            )
    if "success" not in fields:
        # The tabular adapter records an event with no success column as a
        # success. For a detector whose chain rule counts only successful
        # hops, silently turning every failed logon into a hop is the worst
        # kind of wrong, so say so here rather than let it be discovered in
        # the alert rate.
        warnings.append(
            "no column reads as the authentication's outcome: every event will be "
            "recorded as a success. Add success=<column> to --map if this log has one"
        )
    if "success" in fields:
        values = [v.lower() for v in _column_values(rows, fields["success"])]
        distinct = Counter(values)
        if values and not any(v in TRUE_WORDS for v in distinct):
            warnings.append(
                f"no value in {fields['success']!r} reads as success "
                f"(saw {sorted(distinct)[:4]}); pass success=<column>:<value> in --map "
                "or every event will be recorded as a failure"
            )
        elif len(distinct) == 1:
            warnings.append(
                f"{fields['success']!r} holds one value ({next(iter(distinct))!r}) in the sample; "
                "failed authentications may be logged elsewhere"
            )
    return warnings


def format_column_map(fields: dict[str, str]) -> str:
    """The ``--map`` string for these fields, in the documented order."""
    return ",".join(f"{name}={fields[name]}" for name in _ORDER if name in fields)


# --------------------------------------------------------------------------
# format detection
# --------------------------------------------------------------------------

def _json_records(lines: Sequence[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in lines:
        text = line.strip()
        if not text.startswith("{"):
            continue
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _flat_keys(record: dict[str, Any], prefix: str = "") -> set[str]:
    """Keys, including dotted paths one level into nested objects."""
    keys: set[str] = set()
    for key, value in record.items():
        name = f"{prefix}{key}"
        keys.add(name)
        if isinstance(value, dict) and not prefix:
            keys |= _flat_keys(value, prefix=f"{key}.")
    return keys


def sniff(lines: Iterable[str], *, sample_lines: int = SAMPLE_LINES) -> Detection:
    """Identify the log format from a bounded sample of its lines."""

    sample = list(islice((line for line in lines if line.strip()), sample_lines))
    if not sample:
        raise UnknownLogFormat("the file is empty")

    # -- Zeek TSV: its own header says so.
    if any(line.startswith("#fields") for line in sample):
        path_line = next((line for line in sample if line.startswith("#path")), "")
        return Detection(
            format="zeek",
            confidence=0.99,
            reasons=("a Zeek '#fields' header" + (f" ({path_line.strip()})" if path_line else ""),),
            lines_sampled=len(sample),
        )

    records = _json_records(sample)
    if records:
        keys: set[str] = set()
        for record in records:
            keys |= _flat_keys(record)
        share = len(records) / len(sample)

        if {"_path"} & keys and any(
            str(r.get("_path", "")).lower() in {"kerberos", "ntlm"} for r in records
        ):
            return Detection("zeek", 0.99, reasons=("Zeek '_path' of kerberos or ntlm",),
                             lines_sampled=len(sample))
        if all(k in keys for k in _ZEEK_JSON_KEYS):
            return Detection("zeek", 0.95, reasons=("Zeek connection keys id.orig_h / id.resp_h",),
                             lines_sampled=len(sample))
        matched_windows = [k for k in _WINDOWS_ID_KEYS if k in keys] or (
            ["winlog.event_id"] if "winlog.event_id" in keys else []
        )
        if matched_windows:
            return Detection(
                "windows-json", 0.97,
                reasons=(f"a Windows event id field ({matched_windows[0]})",),
                lines_sampled=len(sample),
            )
        entra_keys = {"createdDateTime", "deviceDetail", "appDisplayName"}
        if "userPrincipalName" in keys and entra_keys & keys:
            return Detection(
                "entra-signin", 0.96,
                reasons=("Entra sign-in fields (userPrincipalName + createdDateTime)",),
                lines_sampled=len(sample),
            )
        if "eventType" in keys and {"actor", "published", "outcome"} & keys:
            return Detection("okta", 0.96,
                             reasons=("Okta System Log fields (eventType + actor/outcome)",),
                             lines_sampled=len(sample))

        # An unrecognised JSON export: infer a column map over its own keys.
        headers = sorted({k for k in keys if "." not in k})
        fields, warnings = infer_column_map(headers, records)
        return _tabular_detection(
            fields, warnings, headers,
            reasons=(f"JSON lines with no adapter-specific field ({len(records)} of "
                     f"{len(sample)} sampled lines parsed as JSON objects)",),
            confidence=0.80 * share,
            lines_sampled=len(sample),
        )

    # -- sshd text
    if any(_SSHD.search(line) for line in sample):
        matched = sum(1 for line in sample if _SSHD.search(line))
        return Detection(
            "ssh-auth",
            min(0.99, 0.6 + matched / len(sample)),
            reasons=(f"an sshd tag on {matched} of {len(sample)} sampled lines",),
            warnings=(
                ("the stamps are year-less syslog; pass --assume-year",)
                if _looks_like_bsd_syslog(sample)
                else ()
            ),
            lines_sampled=len(sample),
        )

    # -- delimited text with a header
    header, rows, delimiter = _read_delimited(sample)
    if header:
        fields, warnings = infer_column_map(header, rows)
        return _tabular_detection(
            fields, warnings, header,
            reasons=(f"a delimited header of {len(header)} columns "
                     f"(delimiter {delimiter!r})",),
            confidence=0.85,
            lines_sampled=len(sample),
        )

    raise UnknownLogFormat(
        "nothing in the sample identifies an authentication log: it is not JSON lines, "
        "not sshd text, not Zeek, and has no delimited header. Name the format with "
        "--format, or export it as CSV with a header row."
    )


def _looks_like_bsd_syslog(sample: Sequence[str]) -> bool:
    return any(re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", line) for line in sample)


def _read_delimited(sample: Sequence[str]) -> tuple[list[str], list[dict[str, Any]], str]:
    text = "".join(line if line.endswith("\n") else line + "\n" for line in sample)
    try:
        dialect = csv.Sniffer().sniff(text[:8_000], delimiters=",;\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        delimiter = ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    header = [h for h in (reader.fieldnames or []) if h is not None]
    if len(header) < 3:
        return [], [], delimiter
    rows = list(islice(reader, 50))
    return header, rows, delimiter


def _tabular_detection(
    fields: dict[str, str],
    warnings: list[str],
    headers: Sequence[str],
    *,
    reasons: tuple[str, ...],
    confidence: float,
    lines_sampled: int,
) -> Detection:
    missing = [name for name in REQUIRED if name not in fields]
    if missing:
        raise UnknownLogFormat(
            "this looks like a generic authentication export, but no column could be "
            f"matched to {missing}. Columns seen: {list(headers)[:12]}. "
            "Name them with --format tabular --map "
            '"timestamp=<col>,user=<col>,source_host=<col>,destination_host=<col>".'
        )
    found = ", ".join(f"{name}={fields[name]}" for name in REQUIRED)
    # Every required field matched by an exact synonym is worth more than one
    # rescued by the compound-name pass; confidence says how much of a guess
    # this is, and the caller prints it.
    exact = sum(1 for name in REQUIRED if _normalise(fields[name]) in SYNONYMS[name])
    confidence = min(0.95, confidence * (0.6 + 0.1 * exact))
    return Detection(
        format="tabular",
        confidence=confidence,
        column_map=format_column_map(fields),
        reasons=(*reasons, f"columns matched by name: {found}"),
        warnings=tuple(warnings),
        fields=fields,
        lines_sampled=lines_sampled,
    )


def sniff_path(path: Path, *, sample_lines: int = SAMPLE_LINES) -> Detection:
    """Sniff one file, plain or gzip-compressed."""
    import gzip

    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return sniff(handle, sample_lines=sample_lines)


def sniff_paths(paths: Sequence[Path], *, sample_lines: int = SAMPLE_LINES) -> Detection:
    """Sniff the first file and confirm the rest agree.

    Ingesting a directory of mixed formats in one pass would produce a corpus
    whose provenance is a guess; the adapters are cheap to run twice, so
    disagreement is an error rather than a majority vote.
    """
    if not paths:
        raise UnknownLogFormat("no input files")
    first = sniff_path(paths[0], sample_lines=sample_lines)
    for other in paths[1:]:
        detection = sniff_path(other, sample_lines=sample_lines)
        if detection.format != first.format:
            raise UnknownLogFormat(
                f"{paths[0].name} looks like {first.format} but {other.name} looks like "
                f"{detection.format}; ingest one format at a time or name it with --format"
            )
        if detection.column_map != first.column_map:
            raise UnknownLogFormat(
                f"{paths[0].name} and {other.name} are both {first.format} but their columns "
                f"differ ({first.column_map} vs {detection.column_map}); pass --map explicitly"
            )
    return first


__all__ = [
    "SAMPLE_LINES",
    "SYNONYMS",
    "Detection",
    "UnknownLogFormat",
    "format_column_map",
    "infer_column_map",
    "sniff",
    "sniff_path",
    "sniff_paths",
]
