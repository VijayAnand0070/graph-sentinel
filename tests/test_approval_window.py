"""The approval window: two hours for a person, then a reversible block.

An action the catalogue reserves for a person must not wait forever while the
attacker keeps moving, and must not run because nobody looked unless it is a
reversible block. These tests pin both halves, and the API and SOC report
views of the window.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import NoisyOrConfig
from graphsentinel.explain.soc_report import build_soc_incident_bundle
from graphsentinel.response.coordinator import (
    DEFAULT_APPROVAL_WINDOW_SECONDS,
    ApprovalWindow,
    ResponseCoordinator,
    approval_window_from_environment,
)
from graphsentinel.response.store import MemoryResponseStore, SQLiteResponseStore
from test_response_coordinator import _alert


def _coordinator(clock, **window):  # type: ignore[no-untyped-def]
    window.setdefault("on_timeout", "block")
    return ResponseCoordinator(
        store=MemoryResponseStore(),
        mode="dry_run",
        clock=clock,
        approval_window=ApprovalWindow(**window),
    )


def _waiting(coordinator: ResponseCoordinator) -> set[str]:
    return {r.action for r in coordinator.pending()}


def test_the_default_window_is_two_hours_and_waits_for_a_person() -> None:
    assert DEFAULT_APPROVAL_WINDOW_SECONDS == 7_200
    default = ApprovalWindow()
    assert default.seconds == 7_200
    assert default.on_timeout == "wait"
    assert not default.applies_on_timeout("lock_account")
    assert "never runs without a person" in default.describe("isolate_host")
    window = ApprovalWindow(on_timeout="block")
    assert window.applies_on_timeout("lock_account")
    assert window.applies_on_timeout("block_network_path")
    # Irreversible or host-wide actions only ever expire.
    assert not window.applies_on_timeout("reset_credentials")
    assert not window.applies_on_timeout("isolate_host")


def test_an_irreversible_action_cannot_be_made_timeout_blockable() -> None:
    with pytest.raises(ValueError):
        ApprovalWindow(blockable=frozenset({"reset_credentials"}))
    with pytest.raises(ValueError):
        ApprovalWindow(seconds=0)


def test_nothing_happens_inside_the_window() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000100", risk=0.95))
    before = _waiting(coordinator)
    assert "block_network_path" in before
    now[0] += 7_199
    assert coordinator.tick() == []
    assert _waiting(coordinator) == before


def test_an_unanswered_block_is_applied_when_the_window_closes() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000101", risk=0.95))
    now[0] += 7_200
    closed = {r.action: r for r in coordinator.tick()}
    block = closed["block_network_path"]
    assert block.outcome == "dry_run"
    assert block.authority == "timeout"
    assert "approval timeout" in block.output
    assert block.command is not None and block.command.revert is not None
    assert closed["isolate_host"].outcome == "expired"
    assert coordinator.pending() == []
    counts = coordinator.status().to_dict()["counts"]
    assert counts["blocked_on_timeout"] == 1
    assert counts["expired"] >= 1


def test_the_expire_policy_applies_nothing() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0], on_timeout="expire")
    coordinator.on_alert(_alert("GS-00000102", risk=0.95))
    now[0] += 7_200
    closed = coordinator.tick()
    assert closed and all(r.outcome == "expired" for r in closed)


def test_a_rejected_action_never_runs_even_after_the_window() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000103", risk=0.95))
    rejected = coordinator.reject(
        "GS-00000103", "block_network_path", approver="analyst-1", note="admin jump host"
    )
    assert rejected.outcome == "rejected"
    assert rejected.approved_by == "analyst-1"
    assert "admin jump host" in rejected.output
    now[0] += 7_200
    assert "block_network_path" not in {r.action for r in coordinator.tick()}
    with pytest.raises(LookupError):
        coordinator.reject("GS-00000103", "block_network_path", approver="analyst-1")


def test_an_approval_after_the_deadline_is_refused() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000104", risk=0.95))
    record = coordinator.approve("GS-00000104", "isolate_host", approver="analyst-2")
    assert record.authority == "approval"
    now[0] += 7_200
    with pytest.raises(LookupError):
        coordinator.approve("GS-00000104", "block_network_path", approver="analyst-2")


def test_a_timeout_block_can_be_lifted_by_an_analyst() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000105", risk=0.95))
    now[0] += 7_200
    coordinator.tick()
    lifted = coordinator.unblock("GS-00000105", "block_network_path", actor="analyst-3")
    assert lifted.outcome == "reverted"
    assert lifted.authority == "revert"
    with pytest.raises(LookupError):
        coordinator.unblock("GS-00000105", "block_network_path", actor="analyst-3")


def test_the_window_survives_a_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    now = [10_000]
    store = SQLiteResponseStore(tmp_path / "response.sqlite")
    block = ApprovalWindow(on_timeout="block")
    first = ResponseCoordinator(store=store, mode="dry_run", clock=lambda: now[0], approval_window=block)
    first.on_alert(_alert("GS-00000106", risk=0.95))
    now[0] += 3_600
    second = ResponseCoordinator(store=store, mode="dry_run", clock=lambda: now[0], approval_window=block)
    view = {r["action"]: r for r in second.pending_view()}
    assert view["block_network_path"]["seconds_left"] == 3_600
    now[0] += 3_600
    assert "block_network_path" in {
        r.action for r in second.tick() if r.authority == "timeout" and r.outcome == "dry_run"
    }
    store.close()


def test_the_window_is_configurable_from_the_environment(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GRAPHSENTINEL_APPROVAL_WINDOW_SECONDS", "1800")
    monkeypatch.setenv("GRAPHSENTINEL_APPROVAL_TIMEOUT", "expire")
    window = approval_window_from_environment()
    assert (window.seconds, window.on_timeout) == (1_800, "expire")
    monkeypatch.setenv("GRAPHSENTINEL_APPROVAL_TIMEOUT", "maybe")
    with pytest.raises(ValueError):
        approval_window_from_environment()


def test_the_soc_report_states_the_deadline() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0])
    alert = _alert("GS-00000107", risk=0.95)
    coordinator.on_alert(alert)
    bundle = build_soc_incident_bundle(
        "U66@DOM1",
        [alert],
        coordinator.executions(alert_id="GS-00000107"),
        approval_window=coordinator.approval_window,
    )
    waiting = [f.statement for f in bundle.facts if "decision due by" in f.statement]
    assert any("block_network_path" in s and "applied automatically" in s for s in waiting)
    assert any("isolate_host" in s and "expires unapplied" in s for s in waiting)
    assert bundle.actions_pending
    assert all(a.decision_due == 10_000 + 7_200 for a in bundle.actions_pending)


def test_the_api_shows_deadlines_and_accepts_rejections(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", "0")  # lock on the first confident alert
    from test_response_api import _request as api_request

    client = TestClient(create_app(DetectionService(threshold=0.5, fusion=NoisyOrConfig())))
    scored = client.post("/score-batch", json={"events": [api_request(1)]})
    assert scored.status_code == 200, scored.text
    body = client.get("/api/v1/response/pending").json()
    assert body["approval_window"]["seconds"] == 7_200
    assert body["approval_window"]["on_timeout"] == "wait"
    assert body["pending"], body
    first = body["pending"][0]
    assert first["seconds_left"] > 0
    assert first["on_timeout"] == "wait"
    assert first["overdue"] is False
    rejected = client.post(
        "/api/v1/response/reject",
        json={"alert_id": first["alert_id"], "action": first["action"], "approver": "analyst-4"},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["outcome"] == "rejected"
    again = client.post(
        "/api/v1/response/reject",
        json={"alert_id": first["alert_id"], "action": first["action"], "approver": "analyst-4"},
    )
    assert again.status_code == 404
    # The immediate lock is lifted through the same call, and the loop agrees.
    locked = client.post(
        "/api/v1/response/unblock",
        json={"alert_id": first["alert_id"], "action": "lock_account", "actor": "analyst-4"},
    )
    assert locked.status_code == 200, locked.text
    assert locked.json()["outcome"] == "reverted"
    assert client.get("/api/v1/response/incidents").json()["active"] == []
    missing = client.post(
        "/api/v1/response/unblock",
        json={"alert_id": first["alert_id"], "action": "isolate_host", "actor": "analyst-4"},
    )
    assert missing.status_code == 404


def test_a_new_alert_is_pushed_to_the_soc_webhook_with_its_pending_actions(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import json as _json
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from test_response_api import _request as api_request

    received: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(_json.loads(body))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_URL", f"http://127.0.0.1:{server.server_port}/hook")
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_FORMAT", "generic")
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_MIN_SEVERITY", "low")
    try:
        client = TestClient(create_app(DetectionService(threshold=0.5, fusion=NoisyOrConfig())))
        scored = client.post("/score-batch", json={"events": [api_request(1)]}).json()
        assert scored["results"][0]["alerted"]
        deadline = time.time() + 5
        while not [r for r in received if "alert_id" in r] and time.time() < deadline:
            time.sleep(0.05)
    finally:
        server.shutdown()
    alerts = [r for r in received if "alert_id" in r]
    assert alerts, "no alert webhook delivered"
    payload = alerts[0]
    assert payload["source"] == "graphsentinel"
    assert payload["pending_actions"], payload
    assert isinstance(payload["decision_due"], int)


def test_under_the_wait_policy_nothing_runs_and_the_action_stays_pending() -> None:
    now = [10_000]
    coordinator = _coordinator(lambda: now[0], on_timeout="wait")
    coordinator.on_alert(_alert("GS-00000120", risk=0.95))
    before = _waiting(coordinator)
    now[0] += 3 * 7_200
    assert coordinator.tick() == []
    assert _waiting(coordinator) == before
    view = {r["action"]: r for r in coordinator.pending_view()}
    assert view["block_network_path"]["overdue"] is True
    # A late decision is still accepted: the system waits for the person.
    record = coordinator.approve("GS-00000120", "block_network_path", approver="analyst-5")
    assert record.authority == "approval" and record.outcome == "dry_run"


def _locking(clock, **kwargs):  # type: ignore[no-untyped-def]
    return ResponseCoordinator(
        store=MemoryResponseStore(), mode="dry_run", clock=clock, immediate_lock=True, **kwargs
    )


def test_a_confident_alert_locks_the_account_for_two_hours_without_a_person() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0])
    records = {r.action: r for r in coordinator.on_alert(_alert("GS-00000130", risk=0.95))}
    lock = records["lock_account"]
    assert lock.authority == "auto_lock" and lock.outcome == "dry_run"
    assert lock.approved_by is None
    assert lock.command is not None and lock.command.revert is not None
    assert records["force_reauth"].outcome == "dry_run"  # sessions are cut as well
    active = coordinator.incident_view()["active"]
    assert len(active) == 1 and active[0]["revert_at"] == now[0] + 7_200
    # Every further action waits for a person.
    waiting = _waiting(coordinator)
    assert waiting and "lock_account" not in waiting and "force_reauth" not in waiting
    # The lock lifts by itself after two hours; the further actions still wait.
    now[0] += 7_199
    assert [r for r in coordinator.tick() if r.authority == "revert"] == []
    now[0] += 1
    assert [r.outcome for r in coordinator.tick() if r.authority == "revert"] == ["reverted"]
    assert _waiting(coordinator) == waiting


def test_a_second_alert_on_a_locked_account_does_not_lock_it_again() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000131", risk=0.95, timestamp=1_000))
    now[0] += 60
    again = coordinator.on_alert(_alert("GS-00000132", risk=0.95, timestamp=1_060))
    assert "lock_account" not in {r.action for r in again if r.outcome == "dry_run"}
    state = coordinator.incident_view()["active"][0]
    assert state["later_alerts"] == ["GS-00000132"]
    assert state["revert_at"] == now[0] + 7_200  # the clock restarts


def test_an_analyst_can_keep_or_lift_the_immediate_lock() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0])
    coordinator.on_alert(_alert("GS-00000133", risk=0.95))
    kept = coordinator.keep_escalation("U66@DOM1", actor="analyst-6")
    assert kept.kept_by == "analyst-6" and kept.revert_at is None
    now[0] += 10 * 7_200
    assert [r for r in coordinator.tick() if r.authority == "revert"] == []
    lifted = coordinator.revert_escalation("U66@DOM1", actor="analyst-6")
    assert lifted is not None and lifted.outcome == "reverted"


def test_the_immediate_lock_survives_a_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    now = [10_000]
    store = SQLiteResponseStore(tmp_path / "response.sqlite")
    first = ResponseCoordinator(store=store, mode="dry_run", clock=lambda: now[0], immediate_lock=True)
    first.on_alert(_alert("GS-00000134", risk=0.95))
    now[0] += 3_600
    second = ResponseCoordinator(store=store, mode="dry_run", clock=lambda: now[0], immediate_lock=True)
    active = second.incident_view()["active"]
    assert len(active) == 1 and active[0]["revert_at"] == 10_000 + 7_200
    now[0] += 3_600
    assert [r.outcome for r in second.tick() if r.authority == "revert"] == ["reverted"]
    store.close()


def test_when_the_budget_refuses_the_lock_waits_for_a_person() -> None:
    from graphsentinel.response.coordinator import UnattendedBudget

    now = [10_000]
    coordinator = _locking(lambda: now[0], budget=UnattendedBudget(per_hour=0, cooldown_seconds=None))
    records = {r.action: r for r in coordinator.on_alert(_alert("GS-00000135", risk=0.95))}
    assert records["lock_account"].outcome == "pending_approval"
    assert "budget" in records["lock_account"].output
    assert coordinator.incident_view()["active"] == []


def test_a_low_risk_alert_never_locks() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0])
    records = coordinator.on_alert(_alert("GS-00000136", risk=0.40))
    assert all(not (r.action == "lock_account" and r.outcome == "dry_run") for r in records)
    assert coordinator.incident_view()["active"] == []


def test_a_corroborated_lock_waits_for_a_second_alert_from_the_same_host() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0], lock_prior_alerts=1, lock_prior_scope="host")
    first = coordinator.on_alert(_alert("GS-00000140", risk=0.95, user="U1@DOM1", timestamp=1_000))
    assert not any(r.action == "lock_account" and r.outcome == "dry_run" for r in first)
    # another account from the same source host, 10 minutes later: corroborated
    second = coordinator.on_alert(_alert("GS-00000141", risk=0.95, user="U2@DOM1", timestamp=1_600))
    lock = next(r for r in second if r.action == "lock_account")
    assert lock.authority == "auto_lock" and lock.target.account == "U2@DOM1"


def test_an_old_alert_does_not_corroborate() -> None:
    now = [10_000]
    coordinator = _locking(lambda: now[0], lock_prior_alerts=1, lock_prior_scope="account")
    coordinator.on_alert(_alert("GS-00000142", risk=0.95, timestamp=1_000))
    now[0] += 3_601  # wall clock moves with the events: the per-account cooldown has passed
    late = coordinator.on_alert(_alert("GS-00000143", risk=0.95, timestamp=1_000 + 3_601))
    assert not any(r.action == "lock_account" and r.outcome == "dry_run" for r in late)
    now[0] += 3_601
    soon = coordinator.on_alert(_alert("GS-00000144", risk=0.95, timestamp=1_000 + 3_700))
    assert any(r.action == "lock_account" and r.outcome == "dry_run" for r in soon)
