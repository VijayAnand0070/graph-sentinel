"""Tactic-aware response selection.

The property under test is that the technique changes the plan. A response
layer that returns the same escalation for every technique is decoration, and
the specific failure it hides is real: firing ``force_reauth`` at a brute-force
attempt does nothing, because the attacker does not have the password yet.
"""

from __future__ import annotations

from graphsentinel.detection.response import (ACTIONS, TACTIC_PLAYBOOKS,
                                              catalogue, plan_for)


def test_brute_force_locks_rather_than_reprompts() -> None:
    """The central claim of the module: technique determines the useful action."""
    plan = plan_for("T1110", "high", risk=0.95)
    assert "lock_account" in plan.actions
    assert "force_reauth" not in plan.actions


def test_lateral_movement_cuts_the_path() -> None:
    plan = plan_for("T1021", "high", risk=0.95)
    assert "force_reauth" in plan.actions
    assert "block_network_path" in plan.actions


def test_discovery_only_watches() -> None:
    """Enumeration has done no damage; acting loudly burns visibility."""
    plan = plan_for("T1087", "high", risk=0.95)
    assert set(plan.actions) == {"increase_monitoring", "notify_soc"}
    assert plan.needs_approval == ()


def test_credential_theft_rotates_the_secret() -> None:
    plan = plan_for("T1078", "high", risk=0.95)
    assert "reset_credentials" in plan.actions


def test_plans_differ_across_techniques() -> None:
    """If every technique produced the same plan, classification bought nothing."""
    plans = {
        technique_id: plan_for(technique_id, "high", risk=0.95).actions
        for technique_id in TACTIC_PLAYBOOKS
    }
    assert len(set(plans.values())) > 1
    assert plans["T1110"] != plans["T1021"]


def test_unclassified_never_escalates() -> None:
    """Acting on an unattributed alert is acting on an unexplained one."""
    for confidence, risk in (("high", 0.99), ("low", 0.5), ("none", 0.0)):
        plan = plan_for(None, confidence, risk=risk)
        assert plan.playbook == "monitoring"
        assert set(plan.actions) == {"increase_monitoring", "notify_soc"}


def test_unknown_technique_falls_back_safely() -> None:
    plan = plan_for("T9999", "high", risk=0.99)
    assert plan.playbook == "monitoring"


class TestSafetyGates:
    def test_irreversible_actions_are_never_automatic(self) -> None:
        """The hard invariant. A non-reversible action must always need a human."""
        for technique_id in TACTIC_PLAYBOOKS:
            plan = plan_for(technique_id, "high", risk=1.0)
            for name in plan.auto_executable:
                assert ACTIONS[name].reversible, (
                    f"{technique_id}: {name} is irreversible but was marked automatic"
                )

    def test_approval_flagged_actions_are_never_automatic(self) -> None:
        for technique_id in TACTIC_PLAYBOOKS:
            plan = plan_for(technique_id, "high", risk=1.0)
            for name in plan.auto_executable:
                assert not ACTIONS[name].requires_approval

    def test_low_risk_cannot_auto_execute_disruptive_actions(self) -> None:
        """Below the risk gate, only zero-disruption actions may fire alone."""
        plan = plan_for("T1021", "high", risk=0.5)
        for name in plan.auto_executable:
            assert ACTIONS[name].disruption == 0

    def test_low_confidence_truncates_the_escalation(self) -> None:
        high = plan_for("T1021", "high", risk=0.95)
        low = plan_for("T1021", "low", risk=0.95)
        assert len(low.actions) < len(high.actions)
        assert "isolate_host" not in low.actions

    def test_every_action_is_partitioned_exactly_once(self) -> None:
        """No action may be both auto and pending, and none may be dropped."""
        for technique_id in TACTIC_PLAYBOOKS:
            plan = plan_for(technique_id, "high", risk=1.0)
            assert not set(plan.auto_executable) & set(plan.needs_approval)
            assert set(plan.auto_executable) | set(plan.needs_approval) == set(plan.actions)


def test_actions_escalate_in_disruption_order() -> None:
    """Cheap and reversible first, so a wrong call stays recoverable."""
    for technique_id, (_playbook, _rationale, sequence) in TACTIC_PLAYBOOKS.items():
        disruptions = [ACTIONS[name].disruption for name in sequence]
        assert disruptions == sorted(disruptions), (
            f"{technique_id} escalates out of order: {sequence}"
        )


def test_every_referenced_action_exists() -> None:
    for technique_id, (_playbook, _rationale, sequence) in TACTIC_PLAYBOOKS.items():
        for name in sequence:
            assert name in ACTIONS, f"{technique_id} references unknown action {name!r}"


def test_catalogue_states_the_safety_posture() -> None:
    data = catalogue()
    assert data["safety"]["irreversible_actions_never_automatic"] is True
    assert set(data["playbooks"]) == set(TACTIC_PLAYBOOKS)
    assert "does not execute" in data["safety"]["note"]


#: Maximum disruption an action may inflict without a human in the loop.
#: ``force_reauth`` (1) is the intended ceiling: a legitimate user sees one
#: extra authentication prompt. Anything at 2 or above changes account or
#: network state in a way a user would file a ticket about.
MAX_UNATTENDED_DISRUPTION = 1


def test_no_meaningfully_disruptive_action_can_ever_auto_execute() -> None:
    """The safety property the calibration study showed we depend on.

    Measured on the test partition, the 0.85 auto-execution gate corresponds to
    roughly 51% observed precision -- about half of everything auto-actioned is
    benign. That is tolerable *only* because the single action that can fire
    unattended is ``force_reauth``, which costs a legitimate user one extra
    prompt.

    Today that holds because every harsher action happens to carry
    ``requires_approval=True``. That is a property of the table, not a
    guarantee: one new entry added without the flag would silently put account
    lockout behind a coin-flip gate. This pins it as a contract instead.

    Swept over every technique, confidence and risk rather than spot-checked,
    because the failure mode is a single overlooked combination.
    """
    offenders: set[str] = set()
    for technique_id in TACTIC_PLAYBOOKS:
        for confidence in ("high", "medium", "low", "none"):
            for risk in (0.0, 0.5, 0.849, 0.85, 0.8777, 0.8778, 0.99, 1.0):
                plan = plan_for(technique_id, confidence, risk=risk)
                for name in plan.auto_executable:
                    if ACTIONS[name].disruption > MAX_UNATTENDED_DISRUPTION:
                        offenders.add(f"{name} (disruption "
                                      f"{ACTIONS[name].disruption}) via "
                                      f"{technique_id}/{confidence}/risk={risk}")
    assert not offenders, (
        "actions above the unattended disruption ceiling can auto-execute: "
        + "; ".join(sorted(offenders))
    )


def test_irreversible_actions_can_never_auto_execute() -> None:
    """Reversibility is the last line of defence when the gate is wrong."""
    for technique_id in TACTIC_PLAYBOOKS:
        for confidence in ("high", "medium", "low", "none"):
            for risk in (0.0, 0.85, 1.0):
                plan = plan_for(technique_id, confidence, risk=risk)
                for name in plan.auto_executable:
                    assert ACTIONS[name].reversible, (
                        f"{name} is irreversible and auto-executes via "
                        f"{technique_id}/{confidence}/risk={risk}"
                    )


def test_the_risk_gate_actually_gates() -> None:
    """A disruptive action must not slip through just below the threshold.

    Guards the boundary itself: ``>=`` vs ``>`` on the gate is the kind of
    difference that only shows up on the one event sitting exactly on it.
    """
    from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD

    gated_below = set()
    gated_at = set()
    for technique_id in TACTIC_PLAYBOOKS:
        below = plan_for(technique_id, "high", risk=AUTO_EXECUTE_THRESHOLD - 1e-6)
        at = plan_for(technique_id, "high", risk=AUTO_EXECUTE_THRESHOLD)
        gated_below |= {n for n in below.auto_executable if ACTIONS[n].disruption > 0}
        gated_at |= {n for n in at.auto_executable if ACTIONS[n].disruption > 0}
    assert not gated_below, f"disruptive actions auto-fire below the gate: {gated_below}"
    assert gated_at, "the gate admits nothing at all -- it is not a gate, it is a wall"
