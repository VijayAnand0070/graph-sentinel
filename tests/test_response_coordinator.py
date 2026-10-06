"""Automatic response, probed at the seam where an alert becomes an action.

The coordinator is what makes prevention unattended, so these tests ask the
questions an operator would: what runs by itself, what waits, what happens
when I arm it, what happens after a restart, and can anything I did not
approve be carried out.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from graphsentinel.api.schemas import AlertRecord, TacticVerdict
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import NoisyOrConfig, RiskComponents, fuse_risk
from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
from graphsentinel.explain.evidence import build_evidence_bundle
from graphsentinel.response.connectors import Command, PowerShellBackend
from graphsentinel.response.coordinator import (
    ResponseCoordinator,
    coordinator_from_environment,
)
from graphsentinel.response.store import MemoryResponseStore, SQLiteResponseStore


def _alert(
    alert_id: str = "GS-00000001",
    *,
    risk: float = 0.95,
    technique: str | None = "T1021",
    confidence: str = "high",
    user: str = "U66@DOM1",
    timestamp: int = 1_000,
) -> AlertRecord:
    fused = fuse_risk(
        RiskComponents(tgn=risk, novelty=0.5, burst=0.0, pivot=0.0, corroboration=0.0),
        NoisyOrConfig(),
    )
    evidence = build_evidence_bundle(
        alert_id=alert_id,
        timestamp=timestamp,
        user=user,
        source_host="C17693",
        destination_host="C1020",
        risk=fused,
        is_new_pair=True,
        user_fanout_5m=6,
        recent_failures=0,
        path=None,
    )
    tactic = (
        None
        if technique is None
        else TacticVerdict(
            technique_id=technique,
            name="Lateral Movement",
            tactic="lateral-movement",
            score=0.9,
            confidence=confidence,
            evidence=("fan-out",),
        )
    )
    return AlertRecord(
        alert_id=alert_id,
        event_id=1,
        timestamp=timestamp,
        risk=risk,
        evidence=evidence,
        tactic=tactic,
    )


class TestDispatchFromAnAlert:
    def test_a_high_confidence_alert_above_the_gate_runs_only_the_unattended_ceiling(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        records = coordinator.on_alert(_alert(risk=AUTO_EXECUTE_THRESHOLD))
        by_action = {r.action: r.outcome for r in records}
        assert by_action["increase_monitoring"] == "dry_run"
        assert by_action["notify_soc"] == "dry_run"
        assert by_action["force_reauth"] == "dry_run"
        assert by_action["block_network_path"] == "pending_approval"
        assert by_action["isolate_host"] == "pending_approval"
        assert all(r.outcome != "executed" for r in records), "nothing is armed"

    def test_below_the_gate_the_disruptive_step_waits_for_a_person(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        records = coordinator.on_alert(_alert(risk=AUTO_EXECUTE_THRESHOLD - 0.01))
        by_action = {r.action: r.outcome for r in records}
        assert by_action["force_reauth"] == "pending_approval"
        assert by_action["notify_soc"] == "dry_run"

    def test_low_confidence_never_reaches_a_disruptive_step(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        records = coordinator.on_alert(_alert(risk=1.0, confidence="low"))
        assert {r.action for r in records} <= {"increase_monitoring", "notify_soc"}

    def test_the_target_is_the_alert_entities_by_name(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        record = coordinator.on_alert(_alert())[0]
        assert record.target.account == "U66@DOM1"
        assert record.target.source_host == "C17693"
        assert record.target.destination_host == "C1020"

    def test_an_unclassified_alert_dispatches_the_unclassified_plan(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        records = coordinator.on_alert(_alert(technique=None))
        assert all(r.action in {"increase_monitoring", "notify_soc"} for r in records)

    def test_off_mode_records_nothing(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore(), mode="off")
        assert coordinator.on_alert(_alert()) == []
        assert coordinator.status().dispatched == 0


class TestApprovals:
    def test_a_person_can_release_a_pending_action(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        coordinator.on_alert(_alert())
        assert any(r.action == "isolate_host" for r in coordinator.pending())
        record = coordinator.approve("GS-00000001", "isolate_host", approver="analyst")
        assert record.outcome == "dry_run" and record.approved_by == "analyst"
        assert not any(r.action == "isolate_host" for r in coordinator.pending())

    def test_only_a_recommended_action_can_be_approved(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        coordinator.on_alert(_alert())
        with pytest.raises(LookupError, match="no pending approval"):
            coordinator.approve("GS-00000001", "reset_credentials", approver="analyst")
        with pytest.raises(LookupError):
            coordinator.approve("GS-99999999", "isolate_host", approver="analyst")

    def test_an_approval_needs_a_named_person(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        coordinator.on_alert(_alert())
        with pytest.raises(ValueError, match="approver"):
            coordinator.approve("GS-00000001", "isolate_host", approver="  ")


class TestArming:
    def test_the_dry_run_backend_cannot_be_armed(self) -> None:
        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        assert not coordinator.can_arm
        with pytest.raises(ValueError, match="cannot arm"):
            coordinator.set_mode("armed", actor="ops")
        assert coordinator.mode == "dry_run"

    def test_arming_an_executing_backend_is_recorded_and_reversible(self, monkeypatch) -> None:
        import subprocess

        calls: list[list[str]] = []

        class Completed:
            returncode = 0
            stdout = "ok"
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda args, **_: calls.append(args) or Completed())
        coordinator = ResponseCoordinator(store=MemoryResponseStore(), backend=PowerShellBackend())
        status = coordinator.set_mode("armed", actor="ops-lead")
        assert status.armed and status.changed_by == "ops-lead"
        records = coordinator.on_alert(_alert())
        assert {r.action: r.outcome for r in records}["force_reauth"] == "executed"
        assert calls and calls[0][0] == "powershell"
        coordinator.set_mode("dry_run", actor="ops-lead")
        assert not coordinator.status().armed

    def test_constructing_armed_on_a_dry_run_backend_is_refused(self) -> None:
        with pytest.raises(ValueError, match="executing backend"):
            ResponseCoordinator(store=MemoryResponseStore(), mode="armed")

    def test_environment_construction_refuses_unknown_settings(self) -> None:
        with pytest.raises(ValueError, match="GRAPHSENTINEL_AUTO_RESPONSE"):
            coordinator_from_environment(mode="yes", backend="dry_run")
        with pytest.raises(ValueError, match="GRAPHSENTINEL_RESPONSE_BACKEND"):
            coordinator_from_environment(mode="dry_run", backend="bash")
        assert coordinator_from_environment(mode="dry_run", backend="dry_run").mode == "dry_run"


class TestRestartSafety:
    def test_a_restart_does_not_refire_what_already_ran(self, tmp_path: Path) -> None:
        store = SQLiteResponseStore(tmp_path / "response.db")
        first = ResponseCoordinator(store=store)
        first.on_alert(_alert())
        ran = [r for r in first.executions() if r.outcome == "dry_run"]
        assert ran

        second = ResponseCoordinator(store=store)  # a new process
        again = second.on_alert(_alert())
        assert all(r.outcome in {"duplicate", "pending_approval"} for r in again)
        assert not any(r.outcome == "dry_run" for r in again)

    def test_a_pending_approval_survives_a_restart(self, tmp_path: Path) -> None:
        store = SQLiteResponseStore(tmp_path / "response.db")
        ResponseCoordinator(store=store).on_alert(_alert())
        second = ResponseCoordinator(store=store)
        assert any(r.action == "isolate_host" for r in second.pending())
        record = second.approve("GS-00000001", "isolate_host", approver="analyst")
        assert record.outcome == "dry_run"
        assert record.command is not None and "/isolate" in record.command.text

    def test_records_round_trip_through_sqlite_intact(self, tmp_path: Path) -> None:
        store = SQLiteResponseStore(tmp_path / "response.db")
        ResponseCoordinator(store=store).on_alert(_alert())
        loaded = {r.action: r for r in store.all_records()}
        planned = loaded["force_reauth"]
        assert isinstance(planned.command, Command)
        assert "logoff" in planned.command.text
        assert planned.target.account == "U66@DOM1"
        assert loaded["lock_account"].command is None if "lock_account" in loaded else True


class TestServiceIntegration:
    def test_the_detection_service_dispatches_after_persisting_alerts(self) -> None:
        from graphsentinel.api.schemas import (
            RiskComponentInput,
            ScoreBatchRequest,
            ScoreEventRequest,
        )

        coordinator = ResponseCoordinator(store=MemoryResponseStore())
        service = DetectionService(threshold=0.5, responder=coordinator)
        request = ScoreEventRequest(
            event_id=7,
            timestamp=1_000,
            user_id=1,
            source_host_id=2,
            destination_host_id=3,
            user="U1@DOM1",
            source_host="C1",
            destination_host="C2",
            is_new_pair=True,
            user_fanout_5m=6,
            recent_failures=0,
            evidence_support=0.0,
            components=RiskComponentInput(
                tgn=0.99, novelty=1.0, burst=1.0, pivot=1.0, corroboration=0.0
            ),
            tactic=TacticVerdict(
                technique_id="T1021",
                name="Lateral Movement",
                tactic="lateral-movement",
                score=0.9,
                confidence="high",
            ),
        )
        response = service.score_batch(ScoreBatchRequest(events=(request,)))
        assert response.results[0].alerted
        records = coordinator.executions(alert_id="GS-00000007")
        assert records, "the alert must have been dispatched"
        assert {r.action for r in records} >= {"notify_soc", "force_reauth"}

    def test_a_service_without_a_responder_dispatches_nothing(self) -> None:
        service = DetectionService(threshold=0.5)
        assert service.responder is None


class TestUnattendedBudget:
    """The unattended action is bounded by construction (Finding 25): every
    measured false-positive rate is at sampled density, and a cold full-rate
    day showed the chain rule flagging hundreds per 10,000 in its first
    hours. The budget is what makes the worst hour an operator's number."""

    def _coordinator(self, clock, **budget):  # type: ignore[no-untyped-def]
        from graphsentinel.response.coordinator import UnattendedBudget

        return ResponseCoordinator(
            store=MemoryResponseStore(),
            mode="dry_run",
            clock=clock,
            budget=UnattendedBudget(**budget),
        )

    def test_the_hourly_cap_demotes_the_unattended_action_to_approval(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], per_hour=2, cooldown_seconds=None)
        outcomes = []
        for i in range(3):  # three different accounts: no escalation in play
            records = coordinator.on_alert(_alert(f"GS-{i:08d}", risk=0.95, user=f"U{i}@DOM1"))
            outcomes.append({r.action: r.outcome for r in records}["force_reauth"])
        assert outcomes == ["dry_run", "dry_run", "pending_approval"]
        third = next(
            r for r in coordinator.executions(alert_id="GS-00000002") if r.action == "force_reauth"
        )
        assert "budget exhausted" in third.output
        assert coordinator.status().to_dict()["unattended_budget"] == {
            "per_hour": 2,
            "cooldown_seconds": None,
            "used_in_last_hour": 2,
            "refused": 1,
        }
        # The window slides: an hour later the budget is back.
        now[0] += 3_601
        records = coordinator.on_alert(_alert("GS-00000003", risk=0.95, user="U3@DOM1"))
        assert {r.action: r.outcome for r in records}["force_reauth"] == "dry_run"

    def test_one_account_is_not_logged_out_twice_inside_the_cooldown(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], per_hour=None, cooldown_seconds=600)
        first = coordinator.on_alert(_alert("GS-00000010", risk=0.95))
        now[0] += 60
        second = coordinator.on_alert(_alert("GS-00000011", risk=0.95))  # same account U66@DOM1
        assert {r.action: r.outcome for r in first}["force_reauth"] == "dry_run"
        pending = {r.action: r for r in second}["force_reauth"]
        assert pending.outcome == "pending_approval" and "cooldown" in pending.output
        now[0] += 600
        third = coordinator.on_alert(_alert("GS-00000012", risk=0.95))
        assert {r.action: r.outcome for r in third}["force_reauth"] == "dry_run"

    def test_a_demoted_action_can_still_be_approved(self) -> None:
        coordinator = self._coordinator(lambda: 10_000, per_hour=0, cooldown_seconds=None)
        coordinator.on_alert(_alert("GS-00000020", risk=0.95))
        assert any(p.action == "force_reauth" for p in coordinator.pending())
        record = coordinator.approve("GS-00000020", "force_reauth", approver="analyst")
        assert record.outcome == "dry_run" and record.approved_by == "analyst"

    def test_the_budget_is_not_spent_on_alerts_with_nothing_unattended(self) -> None:
        coordinator = self._coordinator(lambda: 10_000, per_hour=1, cooldown_seconds=None)
        coordinator.on_alert(_alert("GS-00000030", risk=0.5, confidence="medium"))
        assert coordinator.status().to_dict()["unattended_budget"]["used_in_last_hour"] == 0

    def test_environment_configures_it(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from graphsentinel.response.coordinator import budget_from_environment

        monkeypatch.setenv("GRAPHSENTINEL_UNATTENDED_PER_HOUR", "5")
        monkeypatch.setenv("GRAPHSENTINEL_UNATTENDED_COOLDOWN_SECONDS", "120")
        budget = budget_from_environment()
        assert (budget.per_hour, budget.cooldown_seconds) == (5, 120)
        monkeypatch.delenv("GRAPHSENTINEL_UNATTENDED_PER_HOUR")
        monkeypatch.delenv("GRAPHSENTINEL_UNATTENDED_COOLDOWN_SECONDS")
        default = budget_from_environment()
        assert (default.per_hour, default.cooldown_seconds) == (20, 3_600)


class TestPreventionLoop:
    """Contain, verify, escalate, revert. A session kill is the cheapest
    containment and the one most likely to fail; the coordinator watches
    whether it held and escalates once, reversibly, on evidence.

    Two clocks: the window is measured on event time (the attacker's clock,
    so a replayed or batched stream escalates exactly as a live one), the
    budget and the auto-revert on wall time."""

    def _coordinator(self, clock, **incidents):  # type: ignore[no-untyped-def]
        from graphsentinel.response.coordinator import UnattendedBudget
        from graphsentinel.response.incidents import IncidentTracker

        return ResponseCoordinator(
            store=MemoryResponseStore(),
            mode="dry_run",
            clock=clock,
            budget=UnattendedBudget(per_hour=None, cooldown_seconds=3_600),
            incidents=IncidentTracker(**incidents),
        )

    def test_a_second_confident_detection_after_a_kill_escalates_to_a_lock(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        first = coordinator.on_alert(_alert("GS-00000100", risk=0.95, timestamp=1_000))
        assert {r.action: r.outcome for r in first}["force_reauth"] == "dry_run"
        assert "lock_account" not in {r.action for r in first}  # not in the T1021 ladder

        now[0] += 300  # the account is moving again, confidently, five minutes later
        second = coordinator.on_alert(_alert("GS-00000101", risk=0.95, timestamp=1_300))
        by_action = {r.action: r for r in second}
        lock = by_action["lock_account"]
        assert lock.outcome == "dry_run" and lock.authority == "escalation"
        assert "did not hold" in lock.output and "GS-00000100" in lock.output
        assert lock.command is not None and lock.command.revert is not None
        # The kill on the second alert still runs? No: the same account is
        # inside the per-account cooldown, so it waits -- the lock is the response.
        assert by_action["force_reauth"].outcome == "pending_approval"
        state = coordinator.incident_view()
        assert state["escalations_total"] == 1
        active = state["active"][0]
        assert active["account"] == "U66@DOM1" and active["revert_at"] == now[0] + 7_200

    def test_the_default_lock_window_is_two_hours(self) -> None:
        # The blast radius of a wrong escalation, stated as a number rather
        # than as prose: one account, two hours, self-healing. An hour was
        # shorter than the gap between hops of the slow campaigns the
        # instrument measures, so a lock could expire mid-campaign.
        from graphsentinel.response.incidents import DEFAULT_AUTO_REVERT_SECONDS, IncidentTracker

        assert DEFAULT_AUTO_REVERT_SECONDS == 7_200
        assert IncidentTracker().auto_revert_seconds == 7_200
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000700", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000701", risk=0.95, timestamp=1_060))
        active = coordinator.incident_view()["active"][0]
        assert active["revert_at"] == now[0] + 7_200
        # Still held at one hour; lifted after two.
        now[0] += 3_600
        assert coordinator.tick() == []
        now[0] += 3_601
        assert [r.outcome for r in coordinator.tick() if r.authority == "revert"] == ["reverted"]

    def test_an_alert_on_a_locked_account_restarts_the_two_hour_clock(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000710", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000711", risk=0.95, timestamp=1_060))
        now[0] += 7_000  # almost out
        coordinator.on_alert(_alert("GS-00000712", risk=0.95, timestamp=8_060))
        assert coordinator.incident_view()["active"][0]["revert_at"] == now[0] + 7_200
        now[0] += 3_600
        assert [r for r in coordinator.tick() if r.authority == "revert"] == []

    def test_the_lock_is_lifted_automatically_unless_kept(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], auto_revert_seconds=600)
        coordinator.on_alert(_alert("GS-00000200", risk=0.95, timestamp=1_000))
        now[0] += 120
        coordinator.on_alert(_alert("GS-00000201", risk=0.95, timestamp=1_120))
        assert coordinator.incident_view()["active"]
        now[0] += 601
        reverted = coordinator.tick()
        assert len(reverted) == 1
        assert reverted[0].outcome == "reverted" and reverted[0].authority == "revert"
        assert "Enable-ADAccount" in (reverted[0].command.text if reverted[0].command else "")
        assert coordinator.incident_view()["active"] == []

    def test_an_analyst_can_keep_the_lock_or_lift_it_now(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], auto_revert_seconds=600)
        coordinator.on_alert(_alert("GS-00000300", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000301", risk=0.95, timestamp=1_060))
        kept = coordinator.keep_escalation("U66@DOM1", actor="analyst")
        assert kept.kept_by == "analyst" and kept.revert_at is None
        now[0] += 10_000
        assert [r for r in coordinator.tick() if r.authority == "revert"] == []  # kept: never auto-reverted
        record = coordinator.revert_escalation("U66@DOM1", actor="analyst")
        assert record is not None and record.outcome == "reverted"
        assert coordinator.incident_view()["active"] == []
        with pytest.raises(LookupError):
            coordinator.revert_escalation("U66@DOM1", actor="analyst")

    def test_a_weak_follow_up_does_not_escalate(self) -> None:
        """Only a second detection that would itself qualify for the unattended
        action counts as evidence the containment failed."""
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000400", risk=0.95, timestamp=1_000))
        now[0] += 60
        weak = coordinator.on_alert(
            _alert("GS-00000401", risk=0.5, confidence="medium", timestamp=1_060)
        )
        assert all(r.authority == "plan" for r in weak)
        assert "lock_account" not in {r.action for r in weak}
        assert coordinator.incident_view()["escalations_total"] == 0

    def test_escalation_never_reaches_an_irreversible_action(self) -> None:
        from graphsentinel.response.connectors import Target
        from graphsentinel.response.executor import Escalation

        coordinator = self._coordinator(lambda: 10_000)
        with pytest.raises(ValueError, match="reversible"):
            coordinator.executor.execute_action(
                "reset_credentials",
                alert_id="GS-1",
                target=Target(
                    account="U66@DOM1", host="C1", source_host="C1", destination_host="C2"
                ),
                unattended=True,
                escalation=Escalation("U66@DOM1", "force_reauth", "GS-0", 9_000, "test"),
            )

    def test_outside_the_window_the_second_detection_is_a_new_contact(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], escalation_window_seconds=600)
        coordinator.on_alert(_alert("GS-00000500", risk=0.95, timestamp=1_000))
        now[0] += 4_000  # window and cooldown both elapsed
        again = coordinator.on_alert(_alert("GS-00000501", risk=0.95, timestamp=5_000))
        by_action = {r.action: r for r in again}
        assert by_action["force_reauth"].outcome == "dry_run"
        assert "lock_account" not in by_action

    def test_the_window_is_measured_on_event_time_not_the_wall_clock(self) -> None:
        """A replayed day arrives in seconds of wall time; a batched hour can
        arrive in one call. The attacker's clock is the one the window is
        measured on, and the auto-revert is scheduled on the wall clock, so a
        replayed lock is not lifted the moment it is applied."""
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], escalation_window_seconds=600)
        # Replay: two detections 300 s apart in event time, 1 s apart on the wall.
        coordinator.on_alert(_alert("GS-00000510", risk=0.95, timestamp=1_000))
        now[0] += 1
        second = coordinator.on_alert(_alert("GS-00000511", risk=0.95, timestamp=1_300))
        lock = {r.action: r for r in second}["lock_account"]
        assert lock.authority == "escalation" and "300s later" in lock.output
        active = coordinator.incident_view()["active"][0]
        assert active["at"] == 1_300 and active["revert_at"] == now[0] + 7_200
        # The same two detections an hour apart in event time are two contacts,
        # however quickly they were replayed.
        coordinator.revert_escalation("U66@DOM1", actor="analyst")
        now[0] += 3_600  # clear the per-account cooldown
        coordinator.on_alert(_alert("GS-00000512", risk=0.95, timestamp=20_000, user="U67@DOM1"))
        now[0] += 1
        again = coordinator.on_alert(
            _alert("GS-00000513", risk=0.95, timestamp=23_600, user="U67@DOM1")
        )
        assert "lock_account" not in {r.action for r in again}

    def _restart(self, coordinator, clock):  # type: ignore[no-untyped-def]
        """A new coordinator over the same durable store, as a restart is."""
        from graphsentinel.response.coordinator import UnattendedBudget
        from graphsentinel.response.incidents import IncidentTracker

        return ResponseCoordinator(
            store=coordinator.store,
            mode="dry_run",
            clock=clock,
            budget=UnattendedBudget(per_hour=None, cooldown_seconds=3_600),
            incidents=IncidentTracker(),
        )

    def test_a_lock_survives_a_restart_and_still_reverts_on_time(self) -> None:
        # Without this the loop forgets the account is disabled, and nothing
        # is left to lift it: an automatic action would become permanent.
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000800", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000801", risk=0.95, timestamp=1_060))
        assert coordinator.incident_view()["active"]

        now[0] += 600
        restarted = self._restart(coordinator, lambda: now[0])
        active = restarted.incident_view()["active"]
        assert len(active) == 1 and active[0]["account"] == "U66@DOM1"
        # Rendered honestly: this one was replayed, not decided live.
        assert active[0]["adopted"] is True and active[0]["prior_alert_id"] == ""
        # The revert time is the one the original escalation chose, not a new
        # two hours from the restart.
        assert active[0]["revert_at"] == 10_060 + 7_200

        now[0] = 10_060 + 7_201
        assert [r.outcome for r in restarted.tick() if r.authority == "revert"] == ["reverted"]
        assert restarted.incident_view()["active"] == []

    def test_a_lock_already_lifted_is_not_adopted_again(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000810", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000811", risk=0.95, timestamp=1_060))
        coordinator.revert_escalation("U66@DOM1", actor="analyst")

        restarted = self._restart(coordinator, lambda: now[0])
        assert restarted.incident_view()["active"] == []

    def test_an_analyst_keep_survives_a_restart(self) -> None:
        # A keep held only in memory would be undone by a restart, re-enabling
        # an account a person decided to hold.
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0])
        coordinator.on_alert(_alert("GS-00000820", risk=0.95, timestamp=1_000))
        now[0] += 60
        coordinator.on_alert(_alert("GS-00000821", risk=0.95, timestamp=1_060))
        coordinator.keep_escalation("U66@DOM1", actor="dana")
        kept = [r for r in coordinator.executions(limit=50) if r.outcome == "kept"]
        assert kept and kept[0].approved_by == "dana"

        now[0] += 20_000  # well past any revert window
        restarted = self._restart(coordinator, lambda: now[0])
        active = restarted.incident_view()["active"]
        assert len(active) == 1
        assert active[0]["kept_by"] == "dana" and active[0]["revert_at"] is None
        assert restarted.tick() == []

    def test_escalation_can_be_switched_off(self) -> None:
        now = [10_000]
        coordinator = self._coordinator(lambda: now[0], enabled=False)
        coordinator.on_alert(_alert("GS-00000600", risk=0.95))
        now[0] += 60
        again = coordinator.on_alert(_alert("GS-00000601", risk=0.95))
        assert "lock_account" not in {r.action for r in again}
        assert coordinator.incident_view()["escalations_total"] == 0

    def test_environment_configures_the_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from graphsentinel.response.coordinator import incidents_from_environment

        monkeypatch.setenv("GRAPHSENTINEL_ESCALATION", "off")
        assert incidents_from_environment().enabled is False
        monkeypatch.setenv("GRAPHSENTINEL_ESCALATION", "on")
        monkeypatch.setenv("GRAPHSENTINEL_ESCALATION_WINDOW_SECONDS", "900")
        monkeypatch.setenv("GRAPHSENTINEL_AUTO_REVERT_SECONDS", "off")
        tracker = incidents_from_environment()
        assert tracker.enabled and tracker.escalation_window_seconds == 900
        assert tracker.auto_revert_seconds is None
