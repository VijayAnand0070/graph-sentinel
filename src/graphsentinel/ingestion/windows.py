"""Windows Security event ingestion.

No organisation has LANL-format authentication logs. They have Windows
Security events, and this is the adapter that turns those into the
vendor-neutral shape the live gateway already accepts. It is the difference
between a research prototype and something installable.

Supported event IDs
-------------------
=====  ==================================  ===================================
ID     Meaning                             Mapped orientation / success
=====  ==================================  ===================================
4624   Successful logon                    LogOn, success
4625   Failed logon                        LogOn, failure
4768   Kerberos TGT requested              TGT
4769   Kerberos service ticket requested   TGS
4776   NTLM credential validation          LogOn
=====  ==================================  ===================================

Together these cover interactive, network and Kerberos authentication, which
is the full surface the detection features are computed from.

Identity, and why it needs care
-------------------------------
The graph is only as good as its entity resolution. The same machine appears
across these events as a NetBIOS name, an FQDN, a machine account with a
trailing ``$``, or bare IP, and treating those as four entities would shatter
the graph and make every edge look novel -- which is precisely the signal the
detector keys on. :func:`canonical_host` folds them together.

Validation status
-----------------
Parsing and normalisation are tested against fixtures that reproduce the exact
EventData layout Windows emits. They have **not** been validated against a
live Security log on this machine, which requires elevation this session does
not have. Until that check runs, treat this adapter as correct-by-specification
rather than correct-by-observation; the distinction matters, because reading
the schema is not the same as meeting the data.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator
from xml.etree import ElementTree

EVENT_NAMESPACE = "{http://schemas.microsoft.com/win/2004/08/events/event}"

#: Windows LogonType codes mapped to the project's logon-type vocabulary.
#: Numbers 0/1 exist in the spec but are not produced by modern Windows.
LOGON_TYPES: dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

SUPPORTED_EVENT_IDS = frozenset({4624, 4625, 4768, 4769, 4776})

#: Accounts that generate enormous volumes of local, non-lateral activity.
#: Keeping them would swamp the graph with edges that carry no signal about
#: an attacker moving between machines.
NOISE_ACCOUNTS = frozenset({
    "ANONYMOUS LOGON", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-",
})

#: Kerberos result codes. 0x0 is success; anything else is a failure whose
#: code carries real meaning (0x18 = bad password, 0x12 = disabled account).
KERBEROS_SUCCESS = {"0x0", "0x00", "0"}


@dataclass(frozen=True, slots=True)
class WindowsAuthEvent:
    """One authentication, normalised to the gateway's vocabulary."""

    timestamp: int
    user: str
    source_host: str
    destination_host: str
    destination_user: str
    auth_type: str
    logon_type: str
    orientation: str
    success: bool
    event_id: int
    source: str = "windows"

    def to_payload(self) -> dict[str, Any]:
        """The exact shape ``POST /api/v1/live/events`` accepts."""
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


def canonical_host(value: str | None) -> str:
    """Fold the many spellings of one machine into a single identity.

    ``WS001.corp.local``, ``WS001``, ``ws001$`` and ``WS001$@CORP`` are the
    same host. Left unresolved they become four graph nodes, every edge
    between them reads as a brand-new relationship, and ``is_new_pair`` -- the
    strongest feature in the set -- fires constantly on ordinary traffic.

    IP addresses are kept, not resolved: guessing at reverse DNS would invent an
    identity rather than resolve one. But one address has one spelling. Windows
    writes Kerberos events (4768/4769) with IPv4-mapped IPv6 addresses --
    ``::ffff:172.18.39.5`` -- and logon events (4624) with the bare IPv4
    address; kept verbatim, one machine became two graph nodes and every
    authentication between the two spellings read as a new relationship. Any
    loopback address, in any spelling, is the machine talking to itself.
    """
    if not value:
        return ""
    text = value.strip()
    if not text or text == "-":
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if address.is_loopback or address.is_unspecified:
            return ""
        return str(address)
    text = text.split("@", 1)[0]
    text = text.split(".", 1)[0]          # FQDN -> NetBIOS
    text = text.rstrip("$")               # machine account -> machine
    return text.upper()


def canonical_user(name: str | None, domain: str | None) -> str:
    """``DOMAIN\\user`` style identity, stable across event types."""
    if not name:
        return ""
    user = name.strip()
    if not user or user == "-":
        return ""
    # A machine account authenticating is a real actor and must be preserved
    # as such -- the trailing $ is what the tactic engine keys on to spot a
    # computer behaving like a person.
    realm = (domain or "").strip().split(".", 1)[0].upper()
    if "@" in user:
        user, _, suffix = user.partition("@")
        realm = realm or suffix.split(".", 1)[0].upper()
    if "\\" in user:
        realm_part, _, user = user.partition("\\")
        realm = realm or realm_part.upper()
    return f"{user}@{realm}" if realm else user


def _is_noise(user: str) -> bool:
    local = user.split("@", 1)[0].upper()
    return local in NOISE_ACCOUNTS


def parse_xml(xml: str) -> dict[str, Any] | None:
    """Extract EventID, timestamp and EventData from one Windows event XML.

    Accepts the exact string ``Get-WinEvent | ForEach-Object { $_.ToXml() }``
    produces.
    """
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return None

    system = root.find(f"{EVENT_NAMESPACE}System")
    if system is None:
        return None

    event_id_node = system.find(f"{EVENT_NAMESPACE}EventID")
    time_node = system.find(f"{EVENT_NAMESPACE}TimeCreated")
    computer_node = system.find(f"{EVENT_NAMESPACE}Computer")
    if event_id_node is None or event_id_node.text is None:
        return None

    fields: dict[str, str] = {}
    data_node = root.find(f"{EVENT_NAMESPACE}EventData")
    if data_node is not None:
        for item in data_node.findall(f"{EVENT_NAMESPACE}Data"):
            name = item.get("Name")
            if name:
                fields[name] = (item.text or "").strip()

    return {
        "event_id": int(event_id_node.text),
        "time_created": time_node.get("SystemTime") if time_node is not None else None,
        "computer": (computer_node.text or "") if computer_node is not None else "",
        "data": fields,
    }


def _to_epoch(value: str | None) -> int | None:
    """Windows emits ISO-8601 UTC with fractional seconds of varying width."""
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Python's parser accepts at most 6 fractional digits; Windows emits 7.
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def normalize(record: dict[str, Any]) -> WindowsAuthEvent | None:
    """Turn one parsed Windows event into a graph edge, or None to skip it.

    Returns None for events that are not authentications between two
    identifiable entities. Skipping is deliberate and common: a logon with no
    resolvable source host is not a lateral-movement edge, and inventing one
    would put a fictional relationship into the graph.
    """
    event_id = int(record.get("event_id", 0))
    if event_id not in SUPPORTED_EVENT_IDS:
        return None

    timestamp = _to_epoch(record.get("time_created"))
    if timestamp is None:
        return None

    data: dict[str, str] = record.get("data") or {}
    destination = canonical_host(record.get("computer"))

    if event_id in {4624, 4625, 4776}:
        user = canonical_user(
            data.get("TargetUserName"),
            data.get("TargetDomainName") or data.get("TargetDomainName"),
        )
        # WorkstationName is the claimed origin; IpAddress is the observed one.
        # Prefer the name when present since it joins with other events, and
        # fall back to the address rather than dropping the edge.
        source = canonical_host(data.get("WorkstationName")) or canonical_host(
            data.get("IpAddress")
        )
        auth_type = (data.get("AuthenticationPackageName") or "NTLM").strip() or "NTLM"
        try:
            logon_code = int(data.get("LogonType", "3") or 3)
        except ValueError:
            logon_code = 3
        logon_type = LOGON_TYPES.get(logon_code, "Network")
        orientation = "LogOn"
        success = event_id != 4625
        if event_id == 4776:
            # 4776 carries its own status field rather than a separate ID.
            success = (data.get("Status", "0x0") or "0x0").lower() in KERBEROS_SUCCESS
            auth_type = "NTLM"
    else:  # 4768 (TGT) / 4769 (service ticket)
        user = canonical_user(data.get("TargetUserName"), data.get("TargetDomainName"))
        source = canonical_host(data.get("IpAddress"))
        auth_type = "Kerberos"
        logon_type = "Network"
        orientation = "TGT" if event_id == 4768 else "TGS"
        status = (data.get("Status") or "0x0").lower()
        success = status in KERBEROS_SUCCESS
        # For a service ticket the destination is the service being requested,
        # which is the actual target of the lateral move -- the DC that issued
        # the ticket is merely the broker and would make every path route
        # through it.
        if event_id == 4769:
            service = data.get("ServiceName") or ""
            if service and service.lower() != "krbtgt":
                destination = canonical_host(service) or destination

    if not user or not source or not destination:
        return None
    if source == destination:
        # A host authenticating to itself is not lateral movement, and the
        # gateway rejects self-loops anyway.
        return None
    if _is_noise(user):
        return None

    return WindowsAuthEvent(
        timestamp=timestamp,
        user=user,
        source_host=source,
        destination_host=destination,
        destination_user=user,
        auth_type=auth_type,
        logon_type=logon_type,
        orientation=orientation,
        success=success,
        event_id=event_id,
    )


def events_from_xml(documents: Iterable[str]) -> Iterator[WindowsAuthEvent]:
    """Stream normalised events from raw Windows event XML documents."""
    for document in documents:
        parsed = parse_xml(document)
        if parsed is None:
            continue
        event = normalize(parsed)
        if event is not None:
            yield event


def events_from_records(records: Iterable[dict[str, Any]]) -> Iterator[WindowsAuthEvent]:
    """Stream from already-parsed records, e.g. JSON exported by a SIEM."""
    for record in records:
        event = normalize(record)
        if event is not None:
            yield event


def ingestion_report(events: Iterable[WindowsAuthEvent]) -> dict[str, Any]:
    """Summarise what an ingestion run actually produced.

    Reported so an operator can sanity-check a new feed before trusting its
    detections: an entity count far below the known estate size usually means
    host resolution is failing, which is invisible in the event count alone.
    """
    users: set[str] = set()
    hosts: set[str] = set()
    by_id: dict[int, int] = {}
    failures = 0
    total = 0
    earliest: int | None = None
    latest: int | None = None

    for event in events:
        total += 1
        users.add(event.user)
        hosts.add(event.source_host)
        hosts.add(event.destination_host)
        by_id[event.event_id] = by_id.get(event.event_id, 0) + 1
        if not event.success:
            failures += 1
        earliest = event.timestamp if earliest is None else min(earliest, event.timestamp)
        latest = event.timestamp if latest is None else max(latest, event.timestamp)

    return {
        "events": total,
        "distinct_users": len(users),
        "distinct_hosts": len(hosts),
        "failures": failures,
        "failure_rate": round(failures / total, 4) if total else 0.0,
        "by_event_id": dict(sorted(by_id.items())),
        "first_timestamp": earliest,
        "last_timestamp": latest,
        "span_seconds": (latest - earliest) if (earliest and latest) else 0,
    }
