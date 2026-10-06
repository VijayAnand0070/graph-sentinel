"""The single path through which any response action is carried out.

The executor takes a :class:`ResponsePlan` -- already partitioned by the
detection layer into what may run unattended and what needs a person -- and
dispatches it. Its job is to make the partition binding at the moment of
execution, where it matters, rather than trusting that every caller respected
it. Three rules, none of which a caller can relax:

1. An action in ``needs_approval`` runs only with an :class:`Approval` naming
   that alert and that action -- or, for a *reversible* action, with an
   :class:`Escalation`: the coordinator's record that a cheaper unattended
   containment on the same account already ran and the account kept moving.
   An escalation never reaches an irreversible action. The same holds for
   an approval *timeout*: when the approval window closes with no decision,
   the coordinator may apply a reversible block on the timeout's authority;
   an irreversible action is never applied that way.
2. An action the catalogue marks irreversible runs only with an approval,
   whatever the plan or an escalation said. The catalogue outranks both.
3. Every dispatch, including one that ran nothing, produces an
   :class:`ExecutionRecord` that says on whose authority it ran; the same
   (alert, action, target) is dispatched at most once.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from graphsentinel.detection.response import ACTIONS, ResponsePlan
from graphsentinel.response.connectors import (
    Backend,
    Command,
    ConnectorRegistry,
    DryRunBackend,
    Target,
)

Outcome = Literal[
    "dry_run",
    "executed",
    "failed",
    "pending_approval",
    "duplicate",
    "unsupported",
    "reverted",
    #: An analyst decided an automatic lock stays. Recorded rather than held
    #: in memory so a restart does not silently lift it (the loop's state is
    #: replayed from these records).
    "kept",
    #: A person declined a pending action inside its approval window.
    "rejected",
    #: The approval window closed with no decision and the action was not
    #: applied (the timeout policy does not block, or the budget refused).
    "expired",
]
#: On whose authority an action ran: the plan's unattended partition, a
#: person's approval, or an escalation after a failed containment.
#: ``timeout``: the approval window closed with no decision and the policy
#: applies the reversible block rather than letting the attacker keep moving.
#: ``auto_lock``: the immediate two-hour lock applied on detection, without a
#: person, because the alert cleared the execution gate.
Authority = Literal["plan", "approval", "escalation", "revert", "timeout", "auto_lock"]
#: Authorities under which the system itself locked an account; such a lock
#: lifts automatically unless an analyst keeps it.
LOCK_AUTHORITIES: frozenset[str] = frozenset({"escalation", "auto_lock"})
#: ``Escalation.prior_action`` value that marks an immediate lock on detection.
DETECTION = "detection"


@dataclass(frozen=True, slots=True)
class Approval:
    """A person's decision to allow one action on one alert."""

    alert_id: str
    action: str
    approver: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class Escalation:
    """Why a reserved, reversible action may run without a person: the account
    was already contained by a cheaper unattended action and kept moving."""

    account: str
    prior_action: str
    prior_alert_id: str
    prior_at: int
    reason: str


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    alert_id: str
    action: str
    target: Target
    outcome: Outcome
    reversible: bool
    requires_approval: bool
    approved_by: str | None
    command: Command | None
    output: str
    error: str
    timestamp: int
    authority: Authority = "plan"

    @property
    def idempotency_key(self) -> str:
        return f"{self.alert_id}|{self.action}|{self.target.describe()}"

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "action": self.action,
            "target": self.target.describe(),
            "outcome": self.outcome,
            "reversible": self.reversible,
            "requires_approval": self.requires_approval,
            "approved_by": self.approved_by,
            "command": self.command.to_dict() if self.command else None,
            "output": self.output,
            "error": self.error,
            "timestamp": self.timestamp,
            "authority": self.authority,
        }


AuditHook = Callable[[ExecutionRecord], None]


@dataclass
class ResponseExecutor:
    registry: ConnectorRegistry = field(default_factory=ConnectorRegistry)
    backend: Backend = field(default_factory=DryRunBackend)
    audit: AuditHook | None = None
    clock: Callable[[], int] = lambda: int(time.time())
    _seen: set[str] = field(default_factory=set)
    records: list[ExecutionRecord] = field(default_factory=list)

    @property
    def armed(self) -> bool:
        return bool(getattr(self.backend, "armed", False))

    def remember(self, alert_id: str, action: str, target: Target) -> None:
        """Register a dispatch that already ran, so it is never carried out again.

        Idempotency is otherwise per process; the coordinator replays the
        durable store through this on start-up.
        """
        self._seen.add(f"{alert_id}|{action}|{target.describe()}")

    def execute_plan(
        self,
        plan: ResponsePlan,
        *,
        alert_id: str,
        target: Target,
        approvals: Iterable[Approval] = (),
        notes: Mapping[str, str] | None = None,
    ) -> list[ExecutionRecord]:
        """Dispatch a plan's actions in order, honouring its partition.

        ``notes`` are recorded on the named actions' records (as ``output``
        when nothing ran), so a caller that demoted an action can say why.
        """
        granted = {a.action: a for a in approvals if a.alert_id == alert_id}
        records = []
        for action in plan.actions:
            unattended = action in plan.auto_executable
            records.append(
                self.execute_action(
                    action,
                    alert_id=alert_id,
                    target=target,
                    unattended=unattended,
                    approval=granted.get(action),
                    note=(notes or {}).get(action, ""),
                )
            )
        return records

    def execute_action(
        self,
        action: str,
        *,
        alert_id: str,
        target: Target,
        unattended: bool,
        approval: Approval | None = None,
        note: str = "",
        escalation: Escalation | None = None,
        timeout_reason: str = "",
    ) -> ExecutionRecord:
        if action not in ACTIONS:
            raise ValueError(f"unknown action {action!r}")
        catalogue = ACTIONS[action]
        if approval is not None and (approval.alert_id != alert_id or approval.action != action):
            raise ValueError("approval does not match this alert and action")
        if escalation is not None and (
            not catalogue.reversible or escalation.account != target.account
        ):
            raise ValueError(
                "an escalation can only authorise a reversible action on its own account"
            )
        if timeout_reason and not catalogue.reversible:
            raise ValueError("an approval timeout can only apply a reversible action")

        # The catalogue outranks the plan: an irreversible action, or one the
        # catalogue flags for approval, is never carried out on the strength
        # of an "unattended" marking alone. An escalation stands in for the
        # approval on a reversible action; nothing stands in for it on an
        # irreversible one.
        authority: Authority = (
            "approval"
            if approval is not None
            else (
                ("auto_lock" if escalation.prior_action == DETECTION else "escalation")
                if escalation is not None
                else ("timeout" if timeout_reason else "plan")
            )
        )
        needs_person = catalogue.requires_approval or not catalogue.reversible or not unattended
        if (
            needs_person
            and approval is None
            and not ((escalation is not None or timeout_reason) and catalogue.reversible)
        ):
            return self._record(
                alert_id, action, target, "pending_approval", None, note, "", None, "plan"
            )

        record_key = f"{alert_id}|{action}|{target.describe()}"
        if record_key in self._seen:
            return self._record(
                alert_id, action, target, "duplicate", None, "", "", approval, authority
            )
        self._seen.add(record_key)

        try:
            command = self.registry.for_action(action).plan(action, target)
        except ValueError as unsupported:
            return self._record(
                alert_id,
                action,
                target,
                "unsupported",
                None,
                "",
                str(unsupported),
                approval,
                authority,
            )
        status, output, stderr = self.backend.run(command)
        detail = output
        if not detail:
            detail = escalation.reason if escalation is not None else timeout_reason
        return self._record(
            alert_id, action, target, status, command, detail, stderr, approval, authority
        )

    def revert_action(self, record: ExecutionRecord, *, reason: str) -> ExecutionRecord:
        """Undo a settled reversible action with its command's revert."""
        if record.command is None or record.command.revert is None:
            raise ValueError(f"{record.action} on {record.target.describe()} has no revert")
        if not record.reversible:
            raise ValueError(f"{record.action} is irreversible")
        status, output, stderr = self.backend.run(record.command.revert)
        outcome: Outcome = "reverted" if status in ("dry_run", "executed") else status
        return self._record(
            record.alert_id,
            record.action,
            record.target,
            outcome,
            record.command.revert,
            output or reason,
            stderr,
            None,
            "revert",
        )

    def _record(
        self,
        alert_id: str,
        action: str,
        target: Target,
        outcome: Outcome,
        command: Command | None,
        output: str,
        error: str,
        approval: Approval | None,
        authority: Authority = "plan",
    ) -> ExecutionRecord:
        catalogue = ACTIONS[action]
        record = ExecutionRecord(
            alert_id=alert_id,
            action=action,
            target=target,
            outcome=outcome,
            reversible=catalogue.reversible,
            requires_approval=catalogue.requires_approval,
            approved_by=approval.approver if approval else None,
            command=command,
            output=output,
            error=error,
            timestamp=self.clock(),
            authority=authority,
        )
        self.records.append(record)
        if self.audit is not None:
            self.audit(record)
        return record
