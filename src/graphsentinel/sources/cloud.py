"""Cloud identity sign-ins: Microsoft Entra ID (Azure AD) and Okta.

Lateral movement in a cloud-first estate is an identity reaching applications
it never used, from devices it never used, and the sign-in log is the only
place that is recorded. The mapping to the graph: the *source* is the device
the sign-in came from (its display name when the tenant knows it, the client
address otherwise) and the *destination* is the application or resource that
was reached. Both formats are exported as JSON: an array, a ``{"value":
[...]}`` envelope (Graph API), or one object per line.
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


def _records(lines: Iterable[str], stats: ParseStats) -> Iterator[dict[str, Any]]:
    """JSON lines, a JSON array, or a Graph ``value`` envelope -- all common."""
    buffered: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("{") and line.endswith("}") and not buffered:
            stats.lines += 1
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                stats.skip("bad_json")
            continue
        buffered.append(raw)
    if buffered:
        try:
            payload = json.loads("".join(buffered))
        except json.JSONDecodeError:
            stats.skip("bad_json")
            return
        if isinstance(payload, dict):
            payload = payload.get("value", [payload])
        if isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    stats.lines += 1
                    yield item


def _get(record: dict[str, Any], *path: str) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


class EntraSignIns:
    name = "entra-signin"
    description = "Microsoft Entra ID (Azure AD) sign-in logs (Graph signIns JSON)"
    sample = (
        '{"createdDateTime":"2026-03-02T09:14:03Z","userPrincipalName":"alice@corp.example",'
        '"ipAddress":"10.0.0.5","deviceDetail":{"displayName":"WS05"},'
        '"resourceDisplayName":"SharePoint Online","appDisplayName":"Office 365",'
        '"clientAppUsed":"Browser","authenticationProtocol":"oAuth2","status":{"errorCode":0}}\n'
        '{"createdDateTime":"2026-03-02T09:20:10Z","userPrincipalName":"bob@corp.example",'
        '"ipAddress":"203.0.113.9","deviceDetail":{"displayName":""},'
        '"resourceDisplayName":"Azure Key Vault","appDisplayName":"Azure Portal",'
        '"clientAppUsed":"Mobile Apps and Desktop clients","status":{"errorCode":50126}}\n'
    )

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        for record in _records(lines, stats):
            timestamp = parse_timestamp(record.get("createdDateTime"))
            user = canonical_user(record.get("userPrincipalName"))
            source = canonical_host(_get(record, "deviceDetail", "displayName")) or canonical_host(
                record.get("ipAddress")
            )
            destination = canonical_host(
                record.get("resourceDisplayName") or record.get("appDisplayName")
            )
            if timestamp is None:
                stats.skip("bad_timestamp")
                continue
            if not user or not source or not destination:
                stats.skip("missing_entity")
                continue
            if source == destination:
                stats.skip("self_loop")
                continue
            error = _get(record, "status", "errorCode")
            stats.events += 1
            yield SourceEvent(
                timestamp=timestamp,
                user=user,
                source_host=source,
                destination_host=destination,
                destination_user=user,
                auth_type=str(record.get("authenticationProtocol") or "oAuth2"),
                logon_type=str(record.get("clientAppUsed") or "Browser"),
                orientation="LogOn",
                success=(error in (None, 0, "0")),
                source="entra",
            )


class OktaSystemLog:
    name = "okta"
    description = "Okta System Log (JSON): session starts and app sign-ons"
    sample = (
        '{"published":"2026-03-02T09:14:03.000Z","eventType":"user.session.start",'
        '"actor":{"alternateId":"alice@corp.example"},"client":{"ipAddress":"10.0.0.5",'
        '"device":"Computer"},"outcome":{"result":"SUCCESS"},"target":[]}\n'
        '{"published":"2026-03-02T09:16:30.000Z","eventType":"user.authentication.sso",'
        '"actor":{"alternateId":"alice@corp.example"},"client":{"ipAddress":"10.0.0.5",'
        '"device":"Computer"},"outcome":{"result":"SUCCESS"},'
        '"target":[{"type":"AppInstance","displayName":"Salesforce"}]}\n'
        '{"published":"2026-03-02T09:18:00.000Z","eventType":"user.session.start",'
        '"actor":{"alternateId":"bob@corp.example"},"client":{"ipAddress":"203.0.113.9",'
        '"device":"Unknown"},"outcome":{"result":"FAILURE","reason":"INVALID_CREDENTIALS"},'
        '"target":[]}\n'
    )

    AUTH_EVENTS = ("user.session.start", "user.authentication.")

    def parse(self, lines: Iterable[str], stats: ParseStats) -> Iterator[SourceEvent]:
        for record in _records(lines, stats):
            kind = str(record.get("eventType") or "")
            if not kind.startswith(self.AUTH_EVENTS):
                stats.skip("not_authentication")
                continue
            timestamp = parse_timestamp(record.get("published"))
            user = canonical_user(_get(record, "actor", "alternateId"))
            source = canonical_host(_get(record, "client", "ipAddress"))
            targets = record.get("target") or []
            app = next(
                (
                    t.get("displayName")
                    for t in targets
                    if isinstance(t, dict) and t.get("type") in {"AppInstance", "AppUser"}
                ),
                None,
            )
            destination = canonical_host(app) if app else "OKTA"
            if timestamp is None:
                stats.skip("bad_timestamp")
                continue
            if not user or not source:
                stats.skip("missing_entity")
                continue
            if source == destination:
                stats.skip("self_loop")
                continue
            stats.events += 1
            yield SourceEvent(
                timestamp=timestamp,
                user=user,
                source_host=source,
                destination_host=destination,
                destination_user=user,
                auth_type="sso" if "sso" in kind else "password",
                logon_type=str(_get(record, "client", "device") or "unknown"),
                orientation="LogOn",
                success=str(_get(record, "outcome", "result") or "").upper() == "SUCCESS",
                source="okta",
            )


__all__ = ["EntraSignIns", "OktaSystemLog"]
