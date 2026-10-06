"""The executor is the last line between a plan and a directory. It is tested
as an adversary would probe it: can an irreversible action be made to run
without a person, can a duplicate dispatch run twice, does a dry run really
run nothing, and is every command reviewable to the character.
"""

from __future__ import annotations

import pytest

from graphsentinel.detection.response import ACTIONS, TACTIC_PLAYBOOKS, plan_for
from graphsentinel.response.connectors import (Command, ConnectorRegistry,
                                               DirectoryConnector,
                                               DryRunBackend, EndpointConnector,
                                               NetworkConnector,
                                               PowerShellBackend, Target)
from graphsentinel.response.executor import Approval, ResponseExecutor

TARGET = Target(account="U66@DOM1", host="C17693", source_host="C17693", destination_host="C1020")


class TestConnectorPlans:
    def test_every_catalogued_action_has_a_connector(self) -> None:
        registry = ConnectorRegistry()
        for action in ACTIONS:
            assert registry.for_action(action).plan(action, TARGET).text

    def test_a_registry_with_a_gap_is_refused(self) -> None:
        with pytest.raises(ValueError, match="no connector serves"):
            ConnectorRegistry(connectors=(DirectoryConnector(),))

    def test_reversible_actions_carry_a_revert_and_irreversible_ones_do_not(self) -> None:
        registry = ConnectorRegistry()
        for action, meta in ACTIONS.items():
            command = registry.for_action(action).plan(action, TARGET)
            if action == "force_reauth":
                continue                       # reversible by expiry, not by command
            assert (command.revert is not None) == meta.reversible, action

    def test_lock_account_is_the_documented_cmdlet_with_the_account_quoted(self) -> None:
        command = DirectoryConnector().plan("lock_account", Target(account="O'Brien@DOM1"))
        assert command.text == "Disable-ADAccount -Identity 'O''Brien@DOM1'"
        assert command.revert is not None
        assert command.revert.text == "Enable-ADAccount -Identity 'O''Brien@DOM1'"

    def test_force_reauth_states_its_on_prem_limitation(self) -> None:
        """The one unattended disruptive action must not overclaim."""
        command = DirectoryConnector().plan("force_reauth", TARGET)
        assert "Kerberos tickets remain valid" in " ".join(command.limitations)
        assert "logoff" in command.text and "Revoke-MgUserSignInSession" in command.text

    def test_reset_credentials_is_marked_irreversible(self) -> None:
        command = DirectoryConnector().plan("reset_credentials", TARGET)
        assert command.revert is None
        assert any("Irreversible" in note for note in command.limitations)

    def test_block_path_needs_both_ends(self) -> None:
        with pytest.raises(ValueError, match="source and a destination"):
            NetworkConnector().plan("block_network_path", Target(source_host="C1"))
        command = NetworkConnector().plan("block_network_path", TARGET)
        assert "New-NetFirewallRule" in command.text and "Remove-NetFirewallRule" in command.revert.text

    def test_isolate_host_is_an_api_call_with_a_release(self) -> None:
        command = EndpointConnector().plan("isolate_host", TARGET)
        assert command.kind == "http" and "/isolate" in command.text
        assert "/unisolate" in command.revert.text


class TestExecutorSafety:
    def test_dry_run_is_the_default_and_runs_nothing(self) -> None:
        executor = ResponseExecutor()
        assert not executor.armed
        record = executor.execute_action("notify_soc", alert_id="a1", target=TARGET, unattended=True)
        assert record.outcome == "dry_run"
        assert record.command is not None and record.command.kind == "internal"

    def test_an_irreversible_action_never_runs_without_a_person(self) -> None:
        """Even when a caller claims it is unattended-safe."""
        executor = ResponseExecutor()
        record = executor.execute_action("reset_credentials", alert_id="a1", target=TARGET,
                                         unattended=True)
        assert record.outcome == "pending_approval"
        assert record.command is None
        assert not executor.backend.planned

    def test_approval_required_actions_wait_for_a_matching_approval(self) -> None:
        executor = ResponseExecutor()
        record = executor.execute_action("lock_account", alert_id="a1", target=TARGET,
                                         unattended=True)
        assert record.outcome == "pending_approval"
        with pytest.raises(ValueError, match="does not match"):
            executor.execute_action("lock_account", alert_id="a1", target=TARGET, unattended=True,
                                    approval=Approval("a2", "lock_account", "analyst"))
        record = executor.execute_action("lock_account", alert_id="a1", target=TARGET,
                                         unattended=True,
                                         approval=Approval("a1", "lock_account", "analyst"))
        assert record.outcome == "dry_run" and record.approved_by == "analyst"

    def test_the_same_dispatch_is_not_carried_out_twice(self) -> None:
        executor = ResponseExecutor()
        first = executor.execute_action("force_reauth", alert_id="a1", target=TARGET, unattended=True)
        second = executor.execute_action("force_reauth", alert_id="a1", target=TARGET, unattended=True)
        assert first.outcome == "dry_run" and second.outcome == "duplicate"
        assert len(executor.backend.planned) == 1

    def test_every_dispatch_is_audited_including_the_ones_that_ran_nothing(self) -> None:
        seen = []
        executor = ResponseExecutor(audit=seen.append)
        executor.execute_action("isolate_host", alert_id="a1", target=TARGET, unattended=True)
        executor.execute_action("notify_soc", alert_id="a1", target=TARGET, unattended=True)
        assert [r.outcome for r in seen] == ["pending_approval", "dry_run"]

    def test_a_plan_is_dispatched_by_its_partition(self) -> None:
        plan = plan_for("T1110", "high", risk=1.0)
        executor = ResponseExecutor()
        records = executor.execute_plan(plan, alert_id="a1", target=TARGET)
        by_action = {r.action: r.outcome for r in records}
        for action in plan.auto_executable:
            assert by_action[action] == "dry_run"
        for action in plan.needs_approval:
            assert by_action[action] == "pending_approval"

    def test_no_plan_for_any_technique_can_run_a_disruptive_action_unattended(self) -> None:
        """The response-layer invariant, re-proven at the execution seam."""
        for technique in TACTIC_PLAYBOOKS:
            executor = ResponseExecutor()
            executor.execute_plan(plan_for(technique, "high", risk=1.0), alert_id="x", target=TARGET)
            ran = [r.action for r in executor.records if r.outcome == "dry_run"]
            assert all(ACTIONS[a].disruption <= 1 for a in ran), (technique, ran)

    def test_unknown_actions_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown action"):
            ResponseExecutor().execute_action("format_disk", alert_id="a", target=TARGET,
                                              unattended=False)


class TestPowerShellBackend:
    def test_unarmed_backend_never_spawns_a_process(self, monkeypatch) -> None:
        import subprocess

        def boom(*_args, **_kwargs):
            raise AssertionError("subprocess.run must not be called while unarmed")
        monkeypatch.setattr(subprocess, "run", boom)
        status, _, _ = PowerShellBackend().run(Command("powershell", "Get-Date", "x"))
        assert status == "dry_run"

    def test_armed_backend_reports_failure_rather_than_raising(self, monkeypatch) -> None:
        import subprocess

        def missing(*_args, **_kwargs):
            raise OSError("no such executable")
        monkeypatch.setattr(subprocess, "run", missing)
        status, _, error = PowerShellBackend(armed=True).run(Command("powershell", "Get-Date", "x"))
        assert status == "failed" and "no such executable" in error

    def test_armed_backend_refuses_non_powershell_commands(self) -> None:
        status, _, error = PowerShellBackend(armed=True).run(Command("http", "POST /x", "x"))
        assert status == "unsupported" and "http" in error


def test_force_reauth_on_a_host_logs_every_session_off_that_host() -> None:
    """A host-scoped containment must mean something: the old playbook record
    said 'Forced re-authentication issued for C1' with nothing behind it."""
    command = DirectoryConnector().plan("force_reauth", Target(host="C1"))
    assert "Invoke-Command -ComputerName 'C1'" in command.text
    assert "logoff" in command.text
    assert "Revoke-MgUserSignInSession" not in command.text     # no account to revoke
    with pytest.raises(ValueError, match="account or a host"):
        DirectoryConnector().plan("force_reauth", Target())
