"""Windows Security events as JSON -- SIEM exports, winlogbeat, OTRF datasets.

The XML adapter in ``ingestion/windows.py`` reads what ``Get-WinEvent``
emits. Almost every other route out of a Windows estate flattens the event
into JSON with the EventData fields at the top level and the system fields
under one of a few well-known names: winlogbeat (``winlog.event_id``,
``winlog.event_data``), Splunk/Elastic exports (``EventID``, ``Computer``),
and the OTRF Security-Datasets / Mordor corpora (``EventID``, ``Hostname``,
``@timestamp``), which are the public labelled lateral-movement recordings
this product can be checked against. This adapter accepts all of those and
reuses the XML adapter's normalisation, so the two cannot drift.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from graphsentinel.ingestion.windows import SUPPORTED_EVENT_IDS, normalize
from graphsentinel.sources.base import ParseStats, SourceEvent

_ID_KEYS = ("EventID", "event_id", "EventId", "winlog.event_id", "event.code")
_TIME_KEYS = (
    "TimeCreated",
    "@timestamp",
    "time_created",
    "UtcTime",
    "winlog.time_created",
    "timestamp",
)
_HOST_KEYS = (
    "Computer",
    "Hostname",
    "computer",
    "host.name",
    "winlog.computer_name",
    "ComputerName",
)


def _lookup(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in record:
            return record[key]
        if "." in key:  # nested form of a dotted key
            value: Any = record
            for part in key.split("."):
                value = value.get(part) if isinstance(value, dict) else None
            if value is not None:
                return value
    return None


def reshape(record: dict[str, Any]) -> dict[str, Any] | None:
    """A flat SIEM/OTRF/winlogbeat record into the XML adapter's shape."""
    event_id = _lookup(record, _ID_KEYS)
    if event_id is None:
        return None
    try:
        code = int(event_id)
    except (TypeError, ValueError):
        return None
    winlog = record.get("winlog") if isinstance(record.get("winlog"), dict) else {}
    data: dict[str, Any] = {}
    for candidate in (record.get("EventData"), winlog.get("event_data") if winlog else None):
        if isinstance(candidate, dict):
            data.update(candidate)
    # OTRF and Splunk exports put EventData fields at the top level.
    for key, value in record.items():
        if key not in data and isinstance(value, str | int | float) and key[:1].isupper():
            data[key] = value
    time_created = _lookup(record, _TIME_KEYS)
    if time_created is None and winlog:
        time_created = winlog.get("time_created")
    return {
        "event_id": code,
        "time_created": time_created,
        "computer": _lookup(record, _HOST_KEYS) or (winlog.get("computer_name") if winlog else ""),
        "data": {k: str(v) for k, v in data.items()},
    }


class WindowsJsonEvents:
    name = "windows-json"
    description = (
        "Windows Security events as JSON lines (SIEM exports, winlogbeat, OTRF Security-Datasets)"
    )
    sample = (
        '{"EventID":4624,"@timestamp":"2026-03-02T09:14:03.120Z","Hostname":"FS01.corp.example",'
        '"TargetUserName":"alice","TargetDomainName":"CORP","WorkstationName":"WS05",'
        '"IpAddress":"10.0.0.5","LogonType":3,"AuthenticationPackageName":"Kerberos"}\n'
        '{"EventID":4769,"@timestamp":"2026-03-02T09:14:01.000Z","Hostname":"DC01.corp.example",'
        '"TargetUserName":"alice@CORP.EXAMPLE","TargetDomainName":"CORP.EXAMPLE",'
        '"IpAddress":"::ffff:10.0.0.5","ServiceName":"FS01$","Status":"0x0"}\n'
        '{"EventID":4625,"@timestamp":"2026-03-02T09:15:00.000Z","Hostname":"DB01",'
        '"TargetUserName":"bob","TargetDomainName":"CORP","WorkstationName":"WS07",'
        '"IpAddress":"10.0.0.7","LogonType":3,"AuthenticationPackageName":"NTLM","Status":"0xc000006d"}\n'
        '{"EventID":4688,"@timestamp":"2026-03-02T09:15:01.000Z","Hostname":"DB01",'
        '"NewProcessName":"C:\\\\Windows\\\\System32\\\\cmd.exe"}\n'
    )

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            stats.lines += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                stats.skip("bad_json")
                continue
            if not isinstance(record, dict):
                stats.skip("bad_json")
                continue
            shaped = reshape(record)
            if shaped is None:
                stats.skip("no_event_id")
                continue
            if shaped["event_id"] not in SUPPORTED_EVENT_IDS:
                stats.skip("not_authentication")
                continue
            event = normalize(shaped)
            if event is None:
                stats.skip("missing_entity_or_self_loop")
                continue
            stats.events += 1
            yield SourceEvent(
                timestamp=event.timestamp,
                user=event.user,
                source_host=event.source_host,
                destination_host=event.destination_host,
                destination_user=event.destination_user,
                auth_type=event.auth_type,
                logon_type=event.logon_type,
                orientation=event.orientation,
                success=event.success,
                source="windows",
            )


__all__ = ["WindowsJsonEvents", "reshape"]
