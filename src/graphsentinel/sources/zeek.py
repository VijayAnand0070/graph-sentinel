"""Zeek ``kerberos.log`` and ``ntlm.log`` -- authentication seen on the wire.

Network sensors see every Kerberos ticket request and every NTLM
authentication that crosses a monitored segment, whether or not the endpoints
log them. For Kerberos a service-ticket request (``TGS``) names the target
service, which is the real destination of a lateral move; the KDC that
answered is only the broker. For NTLM the client's claimed hostname is the
source and the server's NetBIOS name the destination, with the IP addresses
as the fallback for either.

Accepts Zeek's JSON lines (``zeek -j`` / ``json-streaming-logs``, with or
without the ``_path`` field) and the classic tab-separated form with a
``#fields`` header. The two logs can be mixed in one stream.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from typing import Any

from graphsentinel.sources.base import (
    ParseStats,
    SourceEvent,
    canonical_host,
    canonical_user,
    parse_timestamp,
)


def _principal(value: object) -> str:
    """``alice/CORP.EXAMPLE`` or ``alice@CORP.EXAMPLE`` -> ``alice@CORP``."""
    text = str(value or "").strip()
    if not text or text == "-":
        return ""
    if "/" in text and "@" not in text:
        local, _, realm = text.partition("/")
        return canonical_user(local, realm.split(".")[0])
    return canonical_user(text)


def _service_host(service: object) -> str:
    """``host/server.corp.example`` / ``cifs/fs01`` -> the host part."""
    text = str(service or "").strip()
    if not text or text == "-":
        return ""
    if "/" in text:
        _kind, _, target = text.partition("/")
        target = target.split("@")[0]
        return canonical_host(target)
    return canonical_host(text)


class ZeekAuthLog:
    name = "zeek"
    description = "Zeek kerberos.log and ntlm.log (JSON lines or TSV with a #fields header)"
    sample = (
        '{"_path":"kerberos","ts":1772442843.12,"id.orig_h":"10.0.0.5","id.resp_h":"10.0.0.2",'
        '"request_type":"TGS","client":"alice/CORP.EXAMPLE","service":"cifs/fs01.corp.example",'
        '"success":true}\n'
        '{"_path":"ntlm","ts":1772442880.0,"id.orig_h":"10.0.0.7","id.resp_h":"10.0.0.9",'
        '"username":"bob","hostname":"WS07","domainname":"CORP","server_nb_computer_name":"DB01",'
        '"success":false}\n'
        '{"_path":"kerberos","ts":1772442900.0,"id.orig_h":"10.0.0.5","id.resp_h":"10.0.0.2",'
        '"request_type":"AS","client":"alice/CORP.EXAMPLE","service":"krbtgt/CORP.EXAMPLE",'
        '"success":true}\n'
    )

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        fields: list[str] | None = None
        path_hint: str | None = None
        for raw in lines:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#path"):
                    path_hint = line.split("\t")[1].strip() if "\t" in line else None
                continue
            stats.lines += 1
            record: dict[str, Any]
            if line.startswith("{"):
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    stats.skip("bad_json")
                    continue
            elif fields is not None:
                values = line.split("\t")
                if len(values) != len(fields):
                    stats.skip("column_count")
                    continue
                record = dict(zip(fields, values, strict=True))
                if path_hint:
                    record.setdefault("_path", path_hint)
            else:
                stats.skip("no_fields_header")
                continue
            event = self._event(record, stats)
            if event is not None:
                stats.events += 1
                yield event

    @staticmethod
    def _event(record: dict[str, Any], stats: ParseStats) -> SourceEvent | None:
        kind = str(record.get("_path") or "").lower()
        if not kind:
            kind = (
                "kerberos" if "request_type" in record else "ntlm" if "username" in record else ""
            )
        timestamp = parse_timestamp(record.get("ts"))
        if timestamp is None:
            stats.skip("bad_timestamp")
            return None
        success_raw = record.get("success")
        success = (
            str(success_raw).strip().lower() in {"true", "t", "1"}
            if success_raw not in (None, "-")
            else True
        )
        if kind == "kerberos":
            user = _principal(record.get("client"))
            source = canonical_host(record.get("id.orig_h"))
            request = str(record.get("request_type") or "").upper()
            service = record.get("service")
            destination = (
                _service_host(service)
                if request == "TGS" and service and not str(service).lower().startswith("krbtgt")
                else canonical_host(record.get("id.resp_h"))
            )
            orientation = "TGT" if request == "AS" else "TGS" if request == "TGS" else "LogOn"
            auth_type = "Kerberos"
            logon_type = "Network"
        elif kind == "ntlm":
            user = canonical_user(record.get("username"), record.get("domainname"))
            source = canonical_host(record.get("hostname")) or canonical_host(
                record.get("id.orig_h")
            )
            destination = canonical_host(record.get("server_nb_computer_name")) or canonical_host(
                record.get("id.resp_h")
            )
            orientation = "LogOn"
            auth_type = "NTLM"
            logon_type = "Network"
        else:
            stats.skip("not_authentication_log")
            return None
        if not user or not source or not destination:
            stats.skip("missing_entity")
            return None
        if source == destination:
            stats.skip("self_loop")
            return None
        return SourceEvent(
            timestamp=timestamp,
            user=user,
            source_host=source,
            destination_host=destination,
            destination_user=user,
            auth_type=auth_type,
            logon_type=logon_type,
            orientation=orientation,
            success=success,
            source="zeek",
        )


__all__ = ["ZeekAuthLog"]
