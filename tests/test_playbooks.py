import pytest

from graphsentinel.detection.playbooks import (
    CONTAINMENT_PLAYBOOK,
    INVESTIGATION_PLAYBOOK,
    MONITORING_PLAYBOOK,
    PLAYBOOK_CATALOG,
    PlaybookDefinition,
    PlaybookStep,
    execute_playbook,
)


def test_playbook_step_rejects_invalid_minimum_risk() -> None:
    with pytest.raises(ValueError):
        PlaybookStep("isolate_host", minimum_risk=1.5)


def test_playbook_definition_requires_at_least_one_step() -> None:
    with pytest.raises(ValueError):
        PlaybookDefinition(name="empty", description="d", steps=())


def test_playbook_definition_requires_name() -> None:
    with pytest.raises(ValueError):
        PlaybookDefinition(name="", description="d", steps=(PlaybookStep("notify_soc"),))


def test_execute_playbook_rejects_empty_entity() -> None:
    with pytest.raises(ValueError):
        execute_playbook(MONITORING_PLAYBOOK, entity="", entity_kind="host", risk=0.5, now=0)


def test_execute_playbook_rejects_out_of_range_risk() -> None:
    with pytest.raises(ValueError):
        execute_playbook(MONITORING_PLAYBOOK, entity="C1", entity_kind="host", risk=1.5, now=0)


def test_low_risk_only_attempts_the_zero_threshold_step() -> None:
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.1, now=100
    )
    statuses = {s.action: s.status for s in execution.steps}
    assert statuses["increase_monitoring"] == "dry_run"      # attempted, nothing armed
    assert statuses["notify_soc"] == "skipped_condition_not_met"
    assert statuses["isolate_host"] == "skipped_condition_not_met"
    assert statuses["reset_credentials"] == "skipped_condition_not_met"


def test_critical_risk_attempts_every_step_but_executes_none_unarmed() -> None:
    """The record the old version produced here said every step -- including
    the irreversible credential reset -- was executed. Nothing was. Now the
    reversible, unattended-safe steps read dry_run with their planned
    command, and everything the catalogue reserves for a person waits."""
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.95, now=100
    )
    statuses = {s.action: s.status for s in execution.steps}
    assert statuses["increase_monitoring"] == "dry_run"
    assert statuses["notify_soc"] == "dry_run"
    assert statuses["force_reauth"] == "dry_run"
    assert statuses["block_network_path"] == "pending_approval"
    assert statuses["isolate_host"] == "pending_approval"
    assert statuses["reset_credentials"] == "pending_approval"
    assert not any(s.status == "executed" for s in execution.steps)
    planned = next(s for s in execution.steps if s.action == "force_reauth")
    assert "planned, not performed" in planned.detail
    # A host-scoped run logs every session off the host; there is no account to revoke.
    assert "Invoke-Command -ComputerName 'C1'" in planned.detail and "logoff" in planned.detail


def test_partial_risk_attempts_only_steps_up_to_threshold() -> None:
    # 0.75 clears increase_monitoring(0.0), notify_soc(0.5), force_reauth(0.7)
    # but not block_network_path(0.8), isolate_host(0.85), reset_credentials(0.9).
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.75, now=100
    )
    statuses = {s.action: s.status for s in execution.steps}
    assert statuses["force_reauth"] == "dry_run"
    assert statuses["block_network_path"] == "skipped_condition_not_met"


def test_an_approval_releases_a_reserved_step_but_still_only_to_dry_run() -> None:
    from graphsentinel.response.executor import Approval

    execution_id = "playbook:containment:C1:100"
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.95, now=100,
        approvals=[Approval(execution_id, "isolate_host", "analyst")],
        execution_id=execution_id,
    )
    statuses = {s.action: s.status for s in execution.steps}
    assert statuses["isolate_host"] == "dry_run"            # approved, but nothing is armed
    assert statuses["reset_credentials"] == "pending_approval"


def test_executed_appears_only_when_an_armed_backend_ran_the_command() -> None:
    """The only path to the word 'executed' is a backend that ran something."""
    from graphsentinel.response.connectors import Command
    from graphsentinel.response.executor import ResponseExecutor

    class ArmedFake:
        armed = True
        ran: list[Command] = []

        def run(self, command):
            self.ran.append(command)
            return "executed", "ok", ""

    executor = ResponseExecutor(backend=ArmedFake())
    execution = execute_playbook(
        MONITORING_PLAYBOOK, entity="U1@DOM1", entity_kind="user", risk=0.9, now=5,
        executor=executor,
    )
    assert all(s.status == "executed" for s in execution.steps)
    assert len(ArmedFake.ran) == len(execution.steps)


def test_step_order_is_preserved_in_execution() -> None:
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.95, now=100
    )
    actions = [s.action for s in execution.steps]
    expected = [s.action for s in CONTAINMENT_PLAYBOOK.steps]
    assert actions == expected


def test_execution_records_trigger_metadata() -> None:
    execution = execute_playbook(
        INVESTIGATION_PLAYBOOK, entity="alice", entity_kind="user", risk=0.6, now=12345
    )
    assert execution.playbook_name == "investigation"
    assert execution.entity == "alice"
    assert execution.entity_kind == "user"
    assert execution.risk_at_trigger == 0.6
    assert execution.triggered_at == 12345


def test_detail_names_the_entity_and_the_planned_command() -> None:
    execution = execute_playbook(
        MONITORING_PLAYBOOK, entity="C42", entity_kind="host", risk=0.35, now=0
    )
    notify = next(s for s in execution.steps if s.action == "notify_soc")
    assert "C42" in notify.detail
    assert notify.status == "dry_run"


def test_skipped_detail_explains_the_threshold() -> None:
    execution = execute_playbook(
        CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.1, now=0
    )
    skipped = next(s for s in execution.steps if s.status == "skipped_condition_not_met")
    assert "requires risk" in skipped.detail


def test_execution_is_deterministic() -> None:
    first = execute_playbook(CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.6, now=1)
    second = execute_playbook(CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=0.6, now=1)
    assert first == second


def test_catalog_contains_all_three_named_playbooks() -> None:
    assert set(PLAYBOOK_CATALOG) == {"containment", "investigation", "monitoring"}
    assert PLAYBOOK_CATALOG["containment"] is CONTAINMENT_PLAYBOOK
