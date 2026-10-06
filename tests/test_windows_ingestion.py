"""Windows Security event ingestion.

Fixtures reproduce the exact EventData layout Windows emits, field names and
all. The properties under test are the ones that decide whether the resulting
graph is meaningful:

* identity folding -- the same machine must not become four nodes
* direction -- the edge must point from where the logon came to where it landed
* honest skipping -- an event that is not an edge between two identifiable
  entities must be dropped, not invented
"""

from __future__ import annotations

from graphsentinel.ingestion.windows import (LOGON_TYPES, SUPPORTED_EVENT_IDS,
                                             WindowsAuthEvent, canonical_host,
                                             canonical_user, events_from_xml,
                                             ingestion_report, normalize,
                                             parse_xml)

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def logon_xml(
    *,
    event_id: int = 4624,
    time: str = "2024-01-15T10:30:00.1234567Z",
    computer: str = "SRV01.corp.local",
    target_user: str = "jdoe",
    target_domain: str = "CORP",
    logon_type: str = "3",
    package: str = "Kerberos",
    workstation: str = "WS002",
    ip: str = "10.0.0.5",
) -> str:
    return f"""<Event {NS}>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{time}"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">SRV01$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="TargetUserName">{target_user}</Data>
    <Data Name="TargetDomainName">{target_domain}</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="AuthenticationPackageName">{package}</Data>
    <Data Name="WorkstationName">{workstation}</Data>
    <Data Name="IpAddress">{ip}</Data>
  </EventData>
</Event>"""


def kerberos_xml(
    *,
    event_id: int = 4769,
    service: str = "SRV09$",
    target_user: str = "jdoe@CORP.LOCAL",
    ip: str = "10.0.0.5",
    status: str = "0x0",
    computer: str = "DC01.corp.local",
) -> str:
    return f"""<Event {NS}>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="2024-01-15T10:31:00.000Z"/>
    <Computer>{computer}</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">{target_user}</Data>
    <Data Name="TargetDomainName">CORP.LOCAL</Data>
    <Data Name="ServiceName">{service}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="Status">{status}</Data>
  </EventData>
</Event>"""


class TestCanonicalHost:
    def test_all_spellings_of_one_machine_fold_together(self) -> None:
        """The property the whole graph depends on.

        Unresolved, one machine becomes four nodes, every edge between them
        looks brand new, and `is_new_pair` fires on ordinary traffic.
        """
        forms = ["WS001.corp.local", "WS001", "ws001$", "WS001$@CORP", "  WS001  "]
        assert len({canonical_host(f) for f in forms}) == 1
        assert canonical_host("WS001.corp.local") == "WS001"

    def test_ip_addresses_are_kept_verbatim(self) -> None:
        """Already unambiguous. Guessing at reverse DNS invents identity."""
        assert canonical_host("10.0.0.5") == "10.0.0.5"
        assert canonical_host("fe80::1") == "fe80::1"

    def test_one_address_has_one_spelling(self) -> None:
        """Windows writes 4768/4769 with IPv4-mapped IPv6 and 4624 with IPv4.

        Kept verbatim, the same workstation was two graph nodes, and every
        Kerberos request read as a new relationship with a machine the account
        had just logged on to (found on the OTRF Security-Datasets recordings).
        """
        forms = ["172.18.39.5", "::ffff:172.18.39.5", "::FFFF:172.18.39.5", " 172.18.39.5 "]
        assert {canonical_host(f) for f in forms} == {"172.18.39.5"}

    def test_placeholders_resolve_to_nothing(self) -> None:
        for value in ("-", "", None, "::1", "127.0.0.1"):
            assert canonical_host(value) == ""

    def test_every_loopback_spelling_is_the_machine_itself(self) -> None:
        for value in ("::ffff:127.0.0.1", "127.0.0.2", "0.0.0.0", "::"):
            assert canonical_host(value) == ""


class TestCanonicalUser:
    def test_the_three_windows_spellings_converge(self) -> None:
        """Windows names the same account three ways across event types.

        4624 supplies TargetUserName + TargetDomainName, some sources emit
        DOMAIN\\user, and Kerberos events use the UPN. All three must produce
        one identity or the account fragments across the graph.
        """
        assert canonical_user("jdoe", "CORP") == "jdoe@CORP"
        assert canonical_user("CORP\\jdoe", None) == "jdoe@CORP"
        assert canonical_user("jdoe@corp.local", None) == "jdoe@CORP"

    def test_machine_accounts_keep_their_dollar(self) -> None:
        """The tactic engine keys on the trailing $ to spot a computer
        behaving like a person; stripping it would erase that signal."""
        assert canonical_user("WS001$", "CORP").endswith("$@CORP")


class TestParsing:
    def test_real_layout_parses(self) -> None:
        parsed = parse_xml(logon_xml())
        assert parsed is not None
        assert parsed["event_id"] == 4624
        assert parsed["computer"] == "SRV01.corp.local"
        assert parsed["data"]["TargetUserName"] == "jdoe"

    def test_seven_digit_fractional_seconds_are_handled(self) -> None:
        """Windows emits 7 fractional digits; Python's parser accepts 6.
        Getting this wrong drops every event on the floor."""
        event = normalize(parse_xml(logon_xml(time="2024-01-15T10:30:00.1234567Z")))
        assert event is not None
        assert event.timestamp > 0

    def test_malformed_xml_is_skipped_not_raised(self) -> None:
        """One corrupt record must not end an ingestion run."""
        assert parse_xml("<Event><broken") is None
        assert list(events_from_xml(["<Event><broken", logon_xml()])) != []


class TestNormalisation:
    def test_successful_logon_becomes_a_directed_edge(self) -> None:
        event = normalize(parse_xml(logon_xml()))
        assert event is not None
        assert event.source_host == "WS002"        # where the logon came from
        assert event.destination_host == "SRV01"   # where it landed
        assert event.user == "jdoe@CORP"
        assert event.success is True
        assert event.logon_type == "Network"
        assert event.auth_type == "Kerberos"

    def test_failed_logon_is_marked_unsuccessful(self) -> None:
        event = normalize(parse_xml(logon_xml(event_id=4625)))
        assert event is not None and event.success is False

    def test_ip_is_used_when_workstation_name_is_absent(self) -> None:
        """Dropping the edge would lose a real authentication."""
        event = normalize(parse_xml(logon_xml(workstation="-", ip="10.0.0.9")))
        assert event is not None and event.source_host == "10.0.0.9"

    def test_every_logon_type_code_maps(self) -> None:
        for code, name in LOGON_TYPES.items():
            event = normalize(parse_xml(logon_xml(logon_type=str(code))))
            assert event is not None and event.logon_type == name

    def test_service_ticket_targets_the_service_not_the_dc(self) -> None:
        """A 4769 is issued BY the domain controller but is ABOUT the service.

        Using the DC as destination would route every lateral path through it
        and hide the actual target.
        """
        event = normalize(parse_xml(kerberos_xml(service="SRV09$", computer="DC01.corp.local")))
        assert event is not None
        assert event.destination_host == "SRV09"
        assert event.orientation == "TGS"

    def test_tgt_request_keeps_the_dc_as_destination(self) -> None:
        event = normalize(parse_xml(kerberos_xml(event_id=4768, service="krbtgt")))
        assert event is not None
        assert event.destination_host == "DC01"
        assert event.orientation == "TGT"

    def test_kerberos_failure_status_is_respected(self) -> None:
        event = normalize(parse_xml(kerberos_xml(status="0x18")))   # bad password
        assert event is not None and event.success is False


class TestSkipping:
    def test_self_authentication_is_dropped(self) -> None:
        """Not lateral movement, and the gateway rejects self-loops anyway."""
        assert normalize(parse_xml(logon_xml(computer="WS002.corp.local",
                                             workstation="WS002"))) is None

    def test_noise_accounts_are_dropped(self) -> None:
        """SYSTEM and ANONYMOUS LOGON generate volume with no lateral signal."""
        for account in ("SYSTEM", "ANONYMOUS LOGON", "LOCAL SERVICE"):
            assert normalize(parse_xml(logon_xml(target_user=account))) is None

    def test_unresolvable_source_is_dropped_not_invented(self) -> None:
        assert normalize(parse_xml(logon_xml(workstation="-", ip="-"))) is None

    def test_unsupported_event_ids_are_ignored(self) -> None:
        assert normalize(parse_xml(logon_xml(event_id=4634))) is None   # logoff
        assert 4634 not in SUPPORTED_EVENT_IDS


def test_payload_matches_the_gateway_contract() -> None:
    """The adapter's output must be directly postable to /api/v1/live/events."""
    event = normalize(parse_xml(logon_xml()))
    assert event is not None
    payload = event.to_payload()
    required = {"timestamp", "user", "source_host", "destination_host",
                "destination_user", "auth_type", "logon_type", "orientation",
                "success", "source"}
    assert required <= set(payload)
    assert isinstance(payload["timestamp"], int)
    assert isinstance(payload["success"], bool)


def test_ingestion_report_summarises_a_feed() -> None:
    documents = [
        logon_xml(target_user="alice", workstation="WS001"),
        logon_xml(target_user="bob", workstation="WS002", event_id=4625),
        kerberos_xml(service="SRV09$"),
    ]
    report = ingestion_report(events_from_xml(documents))
    assert report["events"] == 3
    assert report["distinct_users"] == 3
    assert report["failures"] == 1
    assert report["by_event_id"] == {4624: 1, 4625: 1, 4769: 1}
    assert report["span_seconds"] >= 0
