"""Windows Security events, end to end, through the real gateway.

The unit tests prove the adapter parses. This proves it *integrates*: raw
Windows event XML in, scored alerts with ATT&CK attribution out, through the
same `/api/v1/live/events` endpoint a deployment would use.

An adapter that parses correctly but produces payloads the gateway rejects is
worth nothing, and that failure mode is invisible to parser tests.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.ingestion.windows import events_from_xml, ingestion_report

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'
BASE_TIME = 1_700_000_000


def logon(
    *,
    second: int,
    user: str,
    source: str,
    destination: str,
    event_id: int = 4624,
    logon_type: str = "3",
    package: str = "Kerberos",
) -> str:
    """A 4624/4625 in the exact shape Windows emits."""
    stamp = f"2023-11-14T{22 + second // 3600:02d}:{(second // 60) % 60:02d}:{second % 60:02d}.1234567Z"
    return f"""<Event {NS}>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{stamp}"/>
    <Computer>{destination}.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">{user}</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">{logon_type}</Data>
    <Data Name="AuthenticationPackageName">{package}</Data>
    <Data Name="WorkstationName">{source}</Data>
    <Data Name="IpAddress">10.0.0.5</Data>
  </EventData>
</Event>"""


def lateral_movement_campaign() -> list[str]:
    """One account fanning out from a foothold to many hosts.

    This is the shape the corpus actually contains (4 sources reaching 292
    destinations) rather than the pivot chain the synthetic generator assumes
    -- see DETECTION_RESEARCH_FINDINGS.md, Findings 3a and 4.
    """
    documents = [
        # Ordinary background traffic first, so the campaign has a baseline
        # to stand out against.
        logon(second=i, user=f"user{i % 5}", source=f"WS{i % 5:03d}",
              destination=f"SRV{i % 3:03d}")
        for i in range(30)
    ]
    documents += [
        logon(second=100 + i * 3, user="svc_backup", source="WS099",
              destination=f"TARGET{i:03d}")
        for i in range(18)
    ]
    return documents


def post_events(client: TestClient, events, batch_id: str) -> dict:
    payload = {"batch_id": batch_id, "events": [e.to_payload() for e in events]}
    response = client.post("/api/v1/live/events", json=payload)
    assert response.status_code == 200, response.text
    return response.json()


def test_windows_xml_flows_through_the_gateway() -> None:
    """Raw Windows XML to scored events, with no hand-editing in between."""
    client = TestClient(create_app(DetectionService(threshold=0.5)))
    events = sorted(events_from_xml(lateral_movement_campaign()),
                    key=lambda e: e.timestamp)
    assert events, "adapter produced nothing to send"

    # The gateway requires strictly advancing timestamps across a stream.
    seen: set[int] = set()
    deduped = []
    for event in events:
        stamp = event.timestamp
        while stamp in seen:
            stamp += 1
        seen.add(stamp)
        deduped.append(
            type(event)(**{**event.__dict__, "timestamp": stamp})
            if hasattr(event, "__dict__") else event
        )

    body = post_events(client, events, "win-1")
    assert len(body["results"]) == len(events)
    for result in body["results"]:
        assert 0.0 <= result["risk"] <= 1.0
        assert "alerted" in result


def test_fanout_campaign_is_attributed_to_lateral_movement() -> None:
    """The end-to-end claim: a Windows-sourced campaign is classified.

    Exercises adapter -> gateway -> feature engine -> tactic engine, which is
    every layer a real deployment depends on.
    """
    client = TestClient(create_app(DetectionService(threshold=0.5)))
    events = sorted(events_from_xml(lateral_movement_campaign()),
                    key=lambda e: e.timestamp)

    attributed: dict[str, int] = {}
    for start in range(0, len(events), 25):
        body = post_events(client, events[start:start + 25], f"win-{start}")
        for result in body["results"]:
            tactic = result.get("tactic")
            key = tactic["technique_id"] if tactic else "NONE"
            attributed[key] = attributed.get(key, 0) + 1

    assert attributed, "no events were scored"
    # The campaign account reaches 18 distinct hosts; background accounts
    # reach 3. Fan-out is what T1021 keys on, so it must appear.
    assert "T1021" in attributed, f"expected lateral movement, got {attributed}"


def test_machine_account_interactive_logon_is_attributed() -> None:
    """A computer account logging in interactively is anomalous by construction."""
    client = TestClient(create_app(DetectionService(threshold=0.5)))
    documents = [
        logon(second=i, user="WS050$", source="WS050", destination=f"SRV{i:03d}",
              logon_type="2")                      # Interactive
        for i in range(6)
    ]
    events = sorted(events_from_xml(documents), key=lambda e: e.timestamp)
    body = post_events(client, events, "win-machine")

    techniques = {
        r["tactic"]["technique_id"] for r in body["results"] if r.get("tactic")
    }
    assert "T1078.002" in techniques, f"expected machine-account misuse, got {techniques}"


def test_failed_logons_reach_the_gateway_as_failures() -> None:
    """Failure is the signal brute-force detection is built on; if the adapter
    reported everything as successful, T1110 could never fire from Windows."""
    client = TestClient(create_app(DetectionService(threshold=0.5)))
    documents = [
        logon(second=i, user="target", source="WS077", destination="DC01",
              event_id=4625)
        for i in range(8)
    ]
    events = sorted(events_from_xml(documents), key=lambda e: e.timestamp)
    assert all(not e.success for e in events)
    body = post_events(client, events, "win-failures")
    assert len(body["results"]) == len(events)


def test_ingestion_report_reflects_the_feed() -> None:
    report = ingestion_report(events_from_xml(lateral_movement_campaign()))
    assert report["events"] > 0
    assert report["distinct_users"] >= 6      # 5 background + the campaign account
    assert report["distinct_hosts"] >= 20
    assert report["by_event_id"].get(4624, 0) > 0
