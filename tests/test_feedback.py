"""Analyst decisions become training labels."""

from __future__ import annotations

from fastapi.testclient import TestClient
from test_response_api import _request
from test_response_coordinator import _alert

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import NoisyOrConfig
from graphsentinel.response.coordinator import ResponseCoordinator
from graphsentinel.response.feedback import feedback_labels, feedback_rows
from graphsentinel.response.store import MemoryResponseStore


def _coordinator(clock):  # type: ignore[no-untyped-def]
    return ResponseCoordinator(store=MemoryResponseStore(), mode="dry_run", clock=clock, immediate_lock=True)


def test_an_approved_disruptive_action_confirms_the_alert() -> None:
    now = [10_000]
    c = _coordinator(lambda: now[0])
    c.on_alert(_alert("GS-00000201", risk=0.95))
    c.approve("GS-00000201", "block_network_path", approver="analyst-1")
    verdict = feedback_labels(c.store.all_records())["GS-00000201"]
    assert verdict.label == 1 and verdict.decided_by == "analyst-1"
    assert "block_network_path" in verdict.source


def test_keeping_the_lock_confirms_and_lifting_it_marks_benign() -> None:
    now = [10_000]
    c = _coordinator(lambda: now[0])
    c.on_alert(_alert("GS-00000202", risk=0.95, user="U1@DOM1"))
    c.on_alert(_alert("GS-00000203", risk=0.95, user="U2@DOM1"))
    c.keep_escalation("U1@DOM1", actor="analyst-2")
    c.revert_escalation("U2@DOM1", actor="analyst-2")
    labels = feedback_labels(c.store.all_records())
    assert labels["GS-00000202"].label == 1 and labels["GS-00000202"].source == "kept the lock"
    assert labels["GS-00000203"].label == 0 and labels["GS-00000203"].decided_by == "analyst-2"


def test_rejecting_every_waiting_action_marks_benign_but_one_rejection_does_not() -> None:
    now = [10_000]
    c = _coordinator(lambda: now[0])
    c.on_alert(_alert("GS-00000204", risk=0.95))
    waiting = sorted({r.action for r in c.pending() if r.alert_id == "GS-00000204"})
    assert len(waiting) >= 2
    c.reject("GS-00000204", waiting[0], approver="analyst-3")
    assert "GS-00000204" not in feedback_labels(c.store.all_records())
    for action in waiting[1:]:
        c.reject("GS-00000204", action, approver="analyst-3")
    assert feedback_labels(c.store.all_records())["GS-00000204"].label == 0


def test_an_automatic_lift_is_not_a_verdict() -> None:
    now = [10_000]
    c = _coordinator(lambda: now[0])
    c.on_alert(_alert("GS-00000205", risk=0.95))
    now[0] += 7_200
    c.tick()
    assert "GS-00000205" not in feedback_labels(c.store.all_records())


def test_rows_carry_the_event_for_the_feature_join() -> None:
    now = [10_000]
    c = _coordinator(lambda: now[0])
    alert = _alert("GS-00000206", risk=0.95)
    c.on_alert(alert)
    c.keep_escalation("U66@DOM1", actor="analyst-4")
    rows = feedback_rows([alert], feedback_labels(c.store.all_records()))
    assert rows == [{
        "alert_id": "GS-00000206", "event_id": 1, "timestamp": 1_000, "user": "U66@DOM1",
        "source_host": "C17693", "destination_host": "C1020", "risk": 0.95, "label": 1,
        "source": "kept the lock", "decided_by": "analyst-4", "decided_at": 10_000,
    }]


def test_the_api_exports_labels_as_json_and_csv(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", "0")  # lock on the first confident alert
    client = TestClient(create_app(DetectionService(threshold=0.5, fusion=NoisyOrConfig())))
    event = _request(1)
    alert_id = client.post("/score-batch", json={"events": [event]}).json()["results"][0]["alert_id"]
    kept = client.post("/api/v1/response/incidents/keep", json={"account": event["user"], "actor": "analyst"})
    assert kept.status_code == 200, kept.text
    body = client.get("/api/v1/feedback/labels").json()
    assert body["confirmed"] == 1 and body["labels"][0]["alert_id"] == alert_id
    csv = client.get("/api/v1/feedback/labels", params={"format": "csv"})
    assert csv.headers["content-type"].startswith("text/csv")
    assert csv.text.splitlines()[0].startswith("alert_id,event_id")
    assert alert_id in csv.text
