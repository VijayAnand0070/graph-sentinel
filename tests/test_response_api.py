"""The automatic-response surface, end to end through the API.

One scoring call produces an alert; the coordinator must have dispatched it by
the time the response returns, the endpoints must show exactly what happened,
an approval must release a reserved step, and arming must be refused while the
backend performs nothing. The same tests would pass against an armed
deployment with the outcomes reading ``executed`` instead of ``dry_run``.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import NoisyOrConfig


def _request(event_id: int, *, confidence: str = "high", tgn: float = 0.99) -> dict[str, object]:
    return {
        "event_id": event_id,
        "timestamp": 1_000 + event_id,
        "user_id": 10 + event_id,
        "source_host_id": 1,
        "destination_host_id": 2 + event_id,
        "user": f"U{10 + event_id}@DOM1",
        "source_host": "C1",
        "destination_host": f"C{2 + event_id}",
        "is_new_pair": True,
        "user_fanout_5m": 8,
        "recent_failures": 0,
        "evidence_support": 0.0,
        "components": {
            "tgn": tgn,
            "novelty": 0.9,
            "burst": 0.2,
            "pivot": 0.8,
            "corroboration": 0.0,
        },
        "tactic": {
            "technique_id": "T1021",
            "name": "Lateral Movement",
            "tactic": "lateral-movement",
            "score": 0.9,
            "confidence": confidence,
            "evidence": ["fan-out"],
        },
    }


def _client() -> TestClient:
    # The production operator (noisy-OR) at its calibrated threshold, so the
    # fused risk of a strong event clears the execution gate as it would live.
    return TestClient(create_app(DetectionService(threshold=0.5, fusion=NoisyOrConfig())))


def test_an_alert_is_dispatched_automatically_and_visible_everywhere() -> None:
    client = _client()
    scored = client.post("/score-batch", json={"events": [_request(1)]}).json()
    assert scored["results"][0]["alerted"]
    alert_id = scored["results"][0]["alert_id"]

    status = client.get("/api/v1/response/status").json()
    assert status["mode"] == "dry_run" and status["armed"] is False
    assert status["counts"]["dispatched"] >= 3
    assert status["counts"]["executed"] == 0, "nothing runs in dry_run"
    assert status["unattended_ceiling"]["action"] == "force_reauth"

    executions = client.get("/api/v1/response/executions", params={"alert_id": alert_id}).json()
    outcomes = {r["action"]: r["outcome"] for r in executions["records"]}
    assert outcomes["notify_soc"] == "dry_run"
    assert outcomes["force_reauth"] == "dry_run"
    assert outcomes["isolate_host"] == "pending_approval"
    planned = next(r for r in executions["records"] if r["action"] == "force_reauth")
    assert "logoff" in planned["command"]["text"], "the literal command is reviewable"

    plan = client.get(f"/api/v1/alerts/{alert_id}/response").json()
    assert plan["mode"] == "dry_run"
    assert "isolate_host" in plan["pending"]
    assert {r["action"] for r in plan["executions"]} == set(outcomes)


def test_an_approval_releases_a_reserved_step_and_only_that_step() -> None:
    client = _client()
    alert_id = client.post("/score-batch", json={"events": [_request(2)]}).json()["results"][0][
        "alert_id"
    ]
    pending = client.get("/api/v1/response/pending").json()["pending"]
    assert any(r["alert_id"] == alert_id and r["action"] == "isolate_host" for r in pending)

    released = client.post(
        "/api/v1/response/approve",
        json={
            "alert_id": alert_id,
            "action": "isolate_host",
            "approver": "analyst-7",
        },
    )
    assert released.status_code == 200
    record = released.json()
    assert record["outcome"] == "dry_run" and record["approved_by"] == "analyst-7"
    assert "/isolate" in record["command"]["text"]

    still_pending = client.get("/api/v1/response/pending").json()["pending"]
    assert not any(
        r["alert_id"] == alert_id and r["action"] == "isolate_host" for r in still_pending
    )
    assert any(
        r["alert_id"] == alert_id and r["action"] == "block_network_path" for r in still_pending
    )


def test_approving_something_never_recommended_is_refused() -> None:
    client = _client()
    alert_id = client.post("/score-batch", json={"events": [_request(3)]}).json()["results"][0][
        "alert_id"
    ]
    refused = client.post(
        "/api/v1/response/approve",
        json={
            "alert_id": alert_id,
            "action": "reset_credentials",
            "approver": "analyst",
        },
    )
    assert refused.status_code == 404
    unknown = client.post(
        "/api/v1/response/approve",
        json={
            "alert_id": "GS-99999999",
            "action": "isolate_host",
            "approver": "analyst",
        },
    )
    assert unknown.status_code == 404


def test_arming_is_refused_while_the_backend_performs_nothing() -> None:
    client = _client()
    refused = client.post("/api/v1/response/mode", json={"mode": "armed", "actor": "ops"})
    assert refused.status_code == 409
    assert "cannot arm" in refused.json()["detail"]
    assert client.get("/api/v1/response/status").json()["mode"] == "dry_run"

    off = client.post("/api/v1/response/mode", json={"mode": "off", "actor": "ops"})
    assert off.status_code == 200 and off.json()["mode"] == "off"
    assert off.json()["changed_by"] == "ops"
    before = client.get("/api/v1/response/status").json()["counts"]["dispatched"]
    client.post("/score-batch", json={"events": [_request(4)]})
    after = client.get("/api/v1/response/status").json()["counts"]["dispatched"]
    assert after == before, "off means nothing is dispatched"


def test_a_low_confidence_alert_never_gets_a_disruptive_step() -> None:
    client = _client()
    alert_id = client.post("/score-batch", json={"events": [_request(5, confidence="low")]}).json()[
        "results"
    ][0]["alert_id"]
    records = client.get("/api/v1/response/executions", params={"alert_id": alert_id}).json()[
        "records"
    ]
    assert {r["action"] for r in records} <= {"increase_monitoring", "notify_soc"}


def test_a_replayed_batch_cannot_dispatch_twice() -> None:
    """Two layers guard this. The service refuses a batch that does not advance
    the stream (409), so the coordinator is never asked twice; and were it
    asked, its idempotency key would answer ``duplicate``. Either way the
    directory sees one dispatch."""
    client = _client()
    assert client.post("/score-batch", json={"events": [_request(6)]}).status_code == 200
    assert client.post("/score-batch", json={"events": [_request(6)]}).status_code == 409
    records = client.get("/api/v1/response/executions", params={"alert_id": "GS-00000006"}).json()[
        "records"
    ]
    force = [r["outcome"] for r in records if r["action"] == "force_reauth"]
    assert force == ["dry_run"]


def test_the_prevention_loop_escalates_over_the_api_and_can_be_kept_or_lifted(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """With the immediate lock off: two confident detections on one account
    inside the window; the second is evidence the session kill did not hold,
    so the system locks the account on its own, shows it, and lets an analyst
    keep or lift it."""
    monkeypatch.setenv("GRAPHSENTINEL_IMMEDIATE_LOCK", "off")
    client = _client()
    same_user = dict(_request(1))
    first = client.post("/score-batch", json={"events": [same_user]}).json()
    assert first["results"][0]["alerted"]
    again = dict(_request(2))
    again.update({"user_id": same_user["user_id"], "user": same_user["user"]})
    second = client.post("/score-batch", json={"events": [again]}).json()
    assert second["results"][0]["alerted"]

    incidents = client.get("/api/v1/response/incidents").json()
    assert incidents["escalations_total"] == 1
    active = incidents["active"][0]
    assert active["account"] == same_user["user"] and active["action"] == "lock_account"
    assert active["revert_at"] is not None

    executions = client.get(
        "/api/v1/response/executions", params={"alert_id": second["results"][0]["alert_id"]}
    ).json()["records"]
    lock = next(r for r in executions if r["action"] == "lock_account")
    assert lock["authority"] == "escalation" and lock["outcome"] == "dry_run"
    assert "Disable-ADAccount" in lock["command"]["text"]

    kept = client.post(
        "/api/v1/response/incidents/keep", json={"account": same_user["user"], "actor": "analyst"}
    ).json()
    assert kept["kept_by"] == "analyst" and kept["revert_at"] is None
    lifted = client.post(
        "/api/v1/response/incidents/revert",
        json={"account": same_user["user"], "actor": "analyst"},
    ).json()
    assert lifted["reverted"]["outcome"] == "reverted"
    assert "Enable-ADAccount" in lifted["reverted"]["command"]["text"]
    assert client.get("/api/v1/response/incidents").json()["active"] == []
    refused = client.post(
        "/api/v1/response/incidents/revert",
        json={"account": same_user["user"], "actor": "analyst"},
    )
    assert refused.status_code == 404
    status = client.get("/api/v1/response/status").json()
    assert status["escalation"]["escalations_total"] == 1


def test_a_confident_alert_locks_the_account_at_once_and_further_actions_wait(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", "0")  # lock on the first confident alert
    """The product default: the first confident alert locks the account for two
    hours without a person; every further action waits for an approval."""
    client = _client()
    scored = client.post("/score-batch", json={"events": [_request(1)]}).json()
    alert_id = scored["results"][0]["alert_id"]
    records = client.get("/api/v1/response/executions", params={"alert_id": alert_id}).json()["records"]
    lock = next(r for r in records if r["action"] == "lock_account")
    assert lock["authority"] == "auto_lock" and lock["outcome"] == "dry_run"
    assert "Disable-ADAccount" in lock["command"]["text"]
    assert lock["command"]["revert"] and "Enable-ADAccount" in lock["command"]["revert"]["text"]
    active = client.get("/api/v1/response/incidents").json()["active"]
    assert len(active) == 1 and active[0]["revert_at"] is not None
    pending = client.get("/api/v1/response/pending").json()
    assert pending["approval_window"]["on_timeout"] == "wait"
    waiting = {r["action"] for r in pending["pending"] if r["alert_id"] == alert_id}
    assert waiting and "lock_account" not in waiting
    assert all(r["on_timeout"] == "wait" for r in pending["pending"])
    status = client.get("/api/v1/response/status").json()
    assert status["unattended_ceiling"]["immediate_lock"] is True


def test_by_default_the_lock_needs_two_earlier_alerts_on_the_account(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", raising=False)
    client = _client()
    status = client.get("/api/v1/response/status").json()
    assert status["unattended_ceiling"]["immediate_lock"] is True
    for k in (1, 2):
        event = dict(_request(k))
        event.update({"user_id": 10, "user": "U10@DOM1"})
        client.post("/score-batch", json={"events": [event]})
        assert client.get("/api/v1/response/incidents").json()["active"] == []
    third = dict(_request(3))
    third.update({"user_id": 10, "user": "U10@DOM1"})
    client.post("/score-batch", json={"events": [third]})
    active = client.get("/api/v1/response/incidents").json()["active"]
    assert len(active) == 1 and active[0]["account"] == "U10@DOM1"
    assert active[0]["alert_id"] == "GS-00000003"
