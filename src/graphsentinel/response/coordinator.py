"""Automatic response: from a persisted alert to dispatched actions, unattended.

What "automatic" means here, precisely
--------------------------------------
When the detection service persists an alert, the coordinator builds the
response plan for it (``plan_for``: technique, confidence, fused risk) and
dispatches that plan through the :class:`ResponseExecutor`. The executor's
rules are unchanged and are what make this safe to leave running:

* only actions the plan marked unattended-safe run without a person, and the
  catalogue caps those at ``force_reauth`` (one extra login prompt);
* everything the catalogue reserves for approval is recorded as
  ``pending_approval`` and waits, visibly, in the console;
* an irreversible action never runs unattended, whatever any plan says.

Three modes, chosen at start-up and switchable at runtime by an audited call:

``off``
    Alerts are persisted, nothing is dispatched. The plan endpoint still shows
    what *would* be recommended.
``dry_run`` (default)
    Every dispatch is planned, recorded with its literal command, and
    performed by nothing. This is the mode to run in until the plans have
    been reviewed against the estate. It produces the same records, approvals
    and console views as ``armed``, so an operator learns the system's
    behaviour without it doing anything.
``armed``
    The executing backend runs the commands. Arming requires a backend that
    *can* execute -- the dry-run backend refuses -- and is recorded with the
    actor who did it.

Restart safety
--------------
The executor's idempotency is per process. On construction the coordinator
replays the store and re-registers every settled dispatch, so a restart cannot
re-fire an action that already ran, and a pending approval survives to be
approved later. It also re-adopts every lock the loop applied and has not
lifted, with the revert time the original escalation chose: an automatic
action that stops being tracked stops being automatic, and an account would
stay disabled with nothing left to lift it. An analyst's decision to keep a
lock is recorded for the same reason.

The loop: contain, verify, escalate, revert
-------------------------------------------
A session kill is the cheapest containment and the one most likely to fail
(issued Kerberos tickets stay valid). So the coordinator keeps watching:
if an account it contained qualifies for an unattended action *again*
inside the escalation window, the containment did not hold, and it
escalates one rung to ``lock_account`` on its own authority -- reversible,
budgeted, recorded with the evidence -- and lifts the lock automatically two
hours later unless an analyst keeps it. ``response/incidents.py`` holds the
state; ``tick()`` performs due reverts and is called on every dispatch and
status read.

Immediate lock: two hours without a person, everything else waits
----------------------------------------------------------------
With ``immediate_lock`` on (the product default), an alert that clears the
execution gate locks the account at once, on the authority ``auto_lock``,
inside the unattended budget, together with the session kill. The lock is
the same reversible rung the escalation uses and lifts automatically after
two hours unless an analyst keeps it. Every further action of the plan --
network-path block, host isolation, credential reset -- waits for a person.

The approval window: two hours for a person
-------------------------------------------
Every action the catalogue reserves for a person opens an approval window
(two hours by default) the moment it is recorded as ``pending_approval``.
Inside the window an analyst approves it (it runs) or rejects it (it is
recorded as ``rejected`` and never runs). A pending action nobody answers
must not wait forever while the attacker keeps moving, so when the window
closes the :class:`ApprovalWindow` policy decides:

* ``wait`` (default): nothing is applied and the action stays pending,
  marked overdue, until a person approves or rejects it. The account lock
  already holds the attacker for the two hours.
* ``block``: a *blocking* action that is reversible
  (``lock_account``, ``block_network_path``) is applied on the timeout's
  authority, inside the unattended budget, and recorded as such; an analyst
  lifts it with one call. Anything irreversible or more disruptive
  (``reset_credentials``, ``isolate_host``) is never applied this way and
  is recorded as ``expired``.
* ``expire``: nothing is applied; every unanswered action becomes ``expired``.

The deadline is derived from the durable record's timestamp, so a restart
neither forgets a window nor restarts its clock.

Bounded by construction
-----------------------
Every measured false-positive rate for the unattended action was taken at the
corpus's sampled density; at full rate a cold day showed the chain rule
flagging hundreds of events per 10,000 in its first hours (Finding 25). A
rate that is not known within an order of magnitude cannot be the only thing
between an alert and an automatic logout, so the coordinator also holds an
:class:`UnattendedBudget`: at most ``per_hour`` unattended actions estate-wide
in any sliding hour, and at most one per account per ``cooldown_seconds``.
When the budget refuses, the action is not dropped -- it is recorded as
``pending_approval`` with the reason, exactly as an action the catalogue
reserves for a person. The worst hour is then a number an operator chose,
not one the estate's traffic decides.
"""

from __future__ import annotations

import os
import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from threading import RLock
from typing import Literal

from graphsentinel.detection.response import ACTIONS, ResponsePlan, plan_for
from graphsentinel.response.connectors import (
    Backend,
    ConnectorRegistry,
    DryRunBackend,
    PowerShellBackend,
    Target,
)
from graphsentinel.response.executor import (
    DETECTION,
    LOCK_AUTHORITIES,
    Approval,
    Escalation,
    ExecutionRecord,
    ResponseExecutor,
)
from graphsentinel.response.incidents import (
    ESCALATION_RUNG,
    Containment,
    EscalationState,
    IncidentTracker,
)
from graphsentinel.response.store import SETTLED, MemoryResponseStore, ResponseStore

Mode = Literal["off", "dry_run", "armed"]
MODES: tuple[Mode, ...] = ("off", "dry_run", "armed")


class AlertLike:
    """The shape the coordinator reads off an alert; structural, not nominal."""

    alert_id: str
    #: Event time, the attacker's clock: the loop's window is measured on it.
    timestamp: int
    risk: float
    tactic: object | None
    evidence: object


DEFAULT_UNATTENDED_PER_HOUR = 20
DEFAULT_APPROVAL_WINDOW_SECONDS = 7_200
#: Product default for the immediate lock's corroboration: two earlier alerts on the
#: same account within the hour. On LANL's development days this cut innocent locks
#: four to seven times at every action budget and locked the same attack-days
#: (scripts/lock_policy_sim.py).
DEFAULT_LOCK_PRIOR_ALERTS = 2
#: Reversible actions that stop movement and may be applied when nobody
#: answers in time. Anything outside this set only ever expires.
TIMEOUT_BLOCKABLE: frozenset[str] = frozenset({"lock_account", "block_network_path"})
TimeoutPolicy = Literal["wait", "block", "expire"]


@dataclass(frozen=True, slots=True)
class ApprovalWindow:
    """How long a person has to decide a pending action, and what happens after."""

    seconds: int = DEFAULT_APPROVAL_WINDOW_SECONDS
    on_timeout: TimeoutPolicy = "wait"
    blockable: frozenset[str] = TIMEOUT_BLOCKABLE

    def __post_init__(self) -> None:
        if self.seconds <= 0:
            raise ValueError("the approval window must be positive")
        if self.on_timeout not in ("wait", "block", "expire"):
            raise ValueError(f"unknown timeout policy {self.on_timeout!r}")
        for action in self.blockable:
            if action not in ACTIONS or not ACTIONS[action].reversible:
                raise ValueError(f"{action!r} cannot be applied on a timeout")

    def deadline(self, record: ExecutionRecord) -> int:
        return record.timestamp + self.seconds

    def applies_on_timeout(self, action: str) -> bool:
        return self.on_timeout == "block" and action in self.blockable

    def describe(self, action: str) -> str:
        hours = self.seconds / 3_600
        window = f"{hours:g} hour{'s' if hours != 1 else ''}"
        if self.on_timeout == "wait":
            return f"never runs without a person; decision requested within {window}"
        if self.applies_on_timeout(action):
            return f"applied automatically (reversible) if nobody decides within {window}"
        return f"expires unapplied if nobody decides within {window}"

    def to_dict(self) -> dict[str, object]:
        return {
            "seconds": self.seconds,
            "on_timeout": self.on_timeout,
            "blockable": sorted(self.blockable),
        }
DEFAULT_UNATTENDED_COOLDOWN_SECONDS = 3_600


@dataclass
class UnattendedBudget:
    """How many unattended actions the estate will tolerate, whatever the rate.

    ``per_hour`` is a sliding-window cap across every account; ``cooldown``
    stops one account being logged out repeatedly by a burst of alerts on the
    same movement. ``None`` for either disables that limit.
    """

    per_hour: int | None = DEFAULT_UNATTENDED_PER_HOUR
    cooldown_seconds: int | None = DEFAULT_UNATTENDED_COOLDOWN_SECONDS
    _recent: deque[int] = field(default_factory=deque, repr=False)
    _last_by_account: dict[str, int] = field(default_factory=dict, repr=False)
    refused: int = 0

    def __post_init__(self) -> None:
        if self.per_hour is not None and self.per_hour < 0:
            raise ValueError("per_hour cannot be negative")
        if self.cooldown_seconds is not None and self.cooldown_seconds < 0:
            raise ValueError("cooldown_seconds cannot be negative")

    def allow(self, account: str | None, now: int, *, escalation: bool = False) -> tuple[bool, str]:
        """Whether one more unattended action may run now, and why not if not.

        An escalation is a different rung on an account already acted on, so
        the per-account cooldown does not apply to it; the hourly cap does.
        """
        while self._recent and self._recent[0] <= now - 3_600:
            self._recent.popleft()
        if self.per_hour is not None and len(self._recent) >= self.per_hour:
            self.refused += 1
            return False, f"unattended budget exhausted: {self.per_hour} per hour"
        if account and self.cooldown_seconds and not escalation:
            last = self._last_by_account.get(account)
            if last is not None and now - last < self.cooldown_seconds:
                self.refused += 1
                return False, (
                    f"account already acted on {now - last}s ago; cooldown {self.cooldown_seconds}s"
                )
        return True, ""

    def spend(self, account: str | None, now: int) -> None:
        self._recent.append(now)
        if account:
            self._last_by_account[account] = now

    def to_dict(self) -> dict[str, object]:
        return {
            "per_hour": self.per_hour,
            "cooldown_seconds": self.cooldown_seconds,
            "used_in_last_hour": len(self._recent),
            "refused": self.refused,
        }


def incidents_from_environment() -> IncidentTracker:
    enabled = os.getenv("GRAPHSENTINEL_ESCALATION", "on").strip().lower() not in {
        "off",
        "0",
        "false",
    }
    window = os.getenv("GRAPHSENTINEL_ESCALATION_WINDOW_SECONDS", "").strip()
    revert = os.getenv("GRAPHSENTINEL_AUTO_REVERT_SECONDS", "").strip()
    return IncidentTracker(
        enabled=enabled,
        escalation_window_seconds=int(window)
        if window
        else IncidentTracker.escalation_window_seconds,
        auto_revert_seconds=(None if revert.lower() in {"off", "0", "none"} else int(revert))
        if revert
        else IncidentTracker.auto_revert_seconds,
    )


def approval_window_from_environment() -> ApprovalWindow:
    seconds = os.getenv("GRAPHSENTINEL_APPROVAL_WINDOW_SECONDS", "").strip()
    policy = os.getenv("GRAPHSENTINEL_APPROVAL_TIMEOUT", "").strip().lower() or "wait"
    if policy not in ("wait", "block", "expire"):
        raise ValueError(
            f"GRAPHSENTINEL_APPROVAL_TIMEOUT must be 'wait', 'block' or 'expire', not {policy!r}"
        )
    return ApprovalWindow(
        seconds=int(seconds) if seconds else DEFAULT_APPROVAL_WINDOW_SECONDS,
        on_timeout=policy,  # type: ignore[arg-type]
    )


def budget_from_environment() -> UnattendedBudget:
    per_hour = os.getenv("GRAPHSENTINEL_UNATTENDED_PER_HOUR", "").strip()
    cooldown = os.getenv("GRAPHSENTINEL_UNATTENDED_COOLDOWN_SECONDS", "").strip()
    return UnattendedBudget(
        per_hour=int(per_hour) if per_hour else DEFAULT_UNATTENDED_PER_HOUR,
        cooldown_seconds=int(cooldown) if cooldown else DEFAULT_UNATTENDED_COOLDOWN_SECONDS,
    )


@dataclass(frozen=True, slots=True)
class ResponseStatus:
    mode: Mode
    backend: str
    armed: bool
    can_arm: bool
    dispatched: int
    executed: int
    dry_run: int
    pending_approval: int
    failed: int
    last_dispatch_at: int | None
    changed_by: str | None
    changed_at: int | None
    budget: dict[str, object] = field(default_factory=dict)
    incidents: dict[str, object] = field(default_factory=dict)
    approval_window: dict[str, object] = field(default_factory=dict)
    immediate_lock: bool = False
    timed_out_blocks: int = 0
    rejected: int = 0
    expired: int = 0

    def _lock_clause(self) -> str:
        """How the escalation's lock ends, in the loop's own configured terms."""
        seconds = self.incidents.get("auto_revert_seconds")
        if not isinstance(seconds, int):
            return "reversible account lock that holds until an analyst lifts it"
        if seconds % 3_600 == 0:
            hours = seconds // 3_600
            window = f"{hours} hour{'s' if hours != 1 else ''}"
        else:
            window = f"{round(seconds / 60)} minutes"
        return (
            f"reversible account lock and lifts it again after {window} "
            "unless an analyst keeps it"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "backend": self.backend,
            "armed": self.armed,
            "can_arm": self.can_arm,
            "counts": {
                "dispatched": self.dispatched,
                "executed": self.executed,
                "dry_run": self.dry_run,
                "pending_approval": self.pending_approval,
                "failed": self.failed,
                "rejected": self.rejected,
                "expired": self.expired,
                "blocked_on_timeout": self.timed_out_blocks,
            },
            "approval_window": self.approval_window,
            "last_dispatch_at": self.last_dispatch_at,
            "changed_by": self.changed_by,
            "changed_at": self.changed_at,
            "unattended_budget": self.budget,
            "escalation": self.incidents,
            "unattended_ceiling": {
                "action": "force_reauth",
                "disruption": ACTIONS["force_reauth"].disruption,
                # Read the lock's duration from the loop itself rather than
                # restating it: a configured window and the sentence an
                # analyst reads must not be able to disagree.
                "note": (
                    (
                        "On a confident detection the system logs the account out and applies a "
                        f"{self._lock_clause()} at once, without a person; every further "
                        "action, and anything irreversible, waits for an approval."
                    )
                    if self.immediate_lock
                    else (
                        "The only action that runs without a person on first contact. If "
                        "the account keeps moving after it, the system escalates once to a "
                        f"{self._lock_clause()}; everything harsher, and anything "
                        "irreversible, waits for an approval."
                    )
                ),
                "immediate_lock": self.immediate_lock,
            },
        }


def _target_for(alert: AlertLike) -> Target:
    event = alert.evidence.event  # type: ignore[attr-defined]
    return Target(
        account=event.user,
        host=event.source_host,
        source_host=event.source_host,
        destination_host=event.destination_host,
    )


def _technique(alert: AlertLike) -> tuple[str | None, str]:
    tactic = alert.tactic
    if tactic is None:
        return None, "none"
    return getattr(tactic, "technique_id", None), getattr(tactic, "confidence", "none")


@dataclass
class ResponseCoordinator:
    store: ResponseStore
    mode: Mode = "dry_run"
    backend: Backend | None = None
    registry: ConnectorRegistry | None = None
    audit: Callable[[ExecutionRecord], None] | None = None
    clock: Callable[[], int] = lambda: int(time.time())
    budget: UnattendedBudget | None = None
    incidents: IncidentTracker | None = None
    approval_window: ApprovalWindow = field(default_factory=ApprovalWindow)
    #: Lock the account for the auto-revert period (two hours) as soon as an
    #: alert clears the execution gate, without waiting for a person.
    immediate_lock: bool = False
    #: Corroboration for the immediate lock: earlier alerts required within
    #: ``lock_prior_window`` seconds (event time) from the same account
    #: (``lock_prior_scope="account"``) or the same source host ("host").
    #: 0 locks on the first alert that clears the gate.
    lock_prior_alerts: int = 0
    lock_prior_scope: str = "account"
    lock_prior_window: int = 3_600

    def __post_init__(self) -> None:
        if self.lock_prior_scope not in ("account", "host"):
            raise ValueError("lock_prior_scope must be 'account' or 'host'")
        if self.lock_prior_alerts < 0:
            raise ValueError("lock_prior_alerts cannot be negative")
        self._recent_alerts: dict[str, deque[int]] = {}
        if self.budget is None:
            self.budget = UnattendedBudget()
        if self.incidents is None:
            self.incidents = IncidentTracker()
        if self.mode not in MODES:
            raise ValueError(f"unknown response mode {self.mode!r}")
        self._lock = RLock()
        self._backend: Backend = self.backend or DryRunBackend()
        self.backend = self._backend
        if self.mode == "armed" and not self.can_arm:
            raise ValueError("armed mode requires an executing backend")
        self._backend.armed = self.mode == "armed"
        self.executor = ResponseExecutor(
            registry=self.registry or ConnectorRegistry(),
            backend=self._backend,
            audit=self._persist,
            clock=self.clock,
        )
        self._changed_by: str | None = None
        self._changed_at: int | None = None
        # Restart safety: re-register everything that already ran, and re-adopt
        # every lock the loop applied and has not yet lifted. Without the
        # second half a restart inside the revert window would leave an
        # account disabled with nothing left to lift it -- the opposite of a
        # self-healing action.
        for record in self.store.all_records():
            if record.outcome in SETTLED:
                self.executor.remember(record.alert_id, record.action, record.target)
        self._adopt_active_locks()

    def _adopt_active_locks(self) -> None:
        """Replay the durable records into the loop's state."""
        if self.incidents is None:
            return
        locks: dict[str, ExecutionRecord] = {}
        ended: dict[str, tuple[int, str, str | None]] = {}
        for record in self.store.all_records():
            account = record.target.account
            if not account or record.action != ESCALATION_RUNG:
                continue
            if record.authority in LOCK_AUTHORITIES and record.outcome in SETTLED:
                locks[account] = record
            elif record.outcome == "reverted":
                ended[account] = (record.timestamp, "reverted", None)
            elif record.outcome == "kept":
                ended[account] = (record.timestamp, "kept", record.approved_by)
        for account, record in locks.items():
            when, kind, actor = ended.get(account, (-1, "", None))
            if kind == "reverted" and when >= record.timestamp:
                continue  # already lifted
            kept_by = actor if kind == "kept" and when >= record.timestamp else None
            self.incidents.adopt(
                account=account,
                alert_id=record.alert_id,
                at=record.timestamp,
                prior_alert_id="",
                reason=record.output or "lock adopted from the durable record after a restart",
                revert_at=(
                    record.timestamp + self.incidents.auto_revert_seconds
                    if self.incidents.auto_revert_seconds
                    else None
                ),
                kept_by=kept_by,
            )

    # ------------------------------------------------------------ properties
    @property
    def can_arm(self) -> bool:
        return not isinstance(self._backend, DryRunBackend)

    @property
    def backend_name(self) -> str:
        return type(self._backend).__name__.replace("Backend", "").lower() or "unknown"

    # ------------------------------------------------------------ dispatch
    def plan(self, alert: AlertLike) -> ResponsePlan:
        technique, confidence = _technique(alert)
        return plan_for(technique, confidence, risk=float(alert.risk))

    def on_alert(self, alert: AlertLike) -> list[ExecutionRecord]:
        """Dispatch the alert's plan. In ``off`` mode, record nothing.

        The budget is spent per alert, not per action: an alert whose plan
        carries the unattended action costs one unit, and when the budget
        refuses, the plan's unattended actions are demoted to approval before
        the executor sees it, so the record says why.
        """
        if self.mode == "off":
            return []
        plan = self.plan(alert)
        target = _target_for(alert)
        # Only actions that disrupt someone draw on the budget; monitoring and
        # notification are free and always run.
        disruptive = tuple(a for a in plan.auto_executable if ACTIONS[a].disruption > 0)
        with self._lock:
            assert self.budget is not None and self.incidents is not None
            now = self.clock()
            # The loop's window is measured on the attacker's clock -- event
            # time -- so a replayed or batched stream escalates exactly as a
            # live one would; the budget and the auto-revert run on wall time.
            event_time = int(alert.timestamp)
            self._tick_locked(now)
            if disruptive and target.account:
                self.incidents.note_alert_after_escalation(target.account, alert.alert_id, now)
            records: list[ExecutionRecord] = []
            corroborated = self._note_for_corroboration(target, event_time)
            # ---- verify: did a cheaper containment on this account already fail?
            # With the immediate lock on, the escalation obeys the same
            # corroboration rule, so the measured lock policy is the only one.
            prior = (
                self.incidents.failed_containment(target.account, event_time)
                if disruptive and target.account and (not self.immediate_lock or corroborated)
                else None
            )
            if prior is not None:
                allowed, reason = self.budget.allow(target.account, now, escalation=True)
                if allowed:
                    evidence = (
                        f"{prior.action} on {target.account} at t={prior.at} (alert "
                        f"{prior.alert_id}) did not hold: the account qualified for an "
                        f"unattended action again {event_time - prior.at}s later (alert "
                        f"{alert.alert_id}); escalating to {ESCALATION_RUNG}"
                    )
                    record = self.executor.execute_action(
                        ESCALATION_RUNG,
                        alert_id=alert.alert_id,
                        target=target,
                        unattended=True,
                        escalation=Escalation(
                            account=target.account or "",
                            prior_action=prior.action,
                            prior_alert_id=prior.alert_id,
                            prior_at=prior.at,
                            reason=evidence,
                        ),
                    )
                    records.append(record)
                    if record.outcome in SETTLED:
                        self.budget.spend(target.account, now)
                        self.incidents.record_escalation(
                            account=target.account or "",
                            alert_id=alert.alert_id,
                            at=event_time,
                            prior=prior,
                            reason=evidence,
                            revert_from=now,
                        )
                    # The rung already taken is not repeated by the plan.
                    plan = replace(
                        plan,
                        actions=tuple(a for a in plan.actions if a != ESCALATION_RUNG),
                        auto_executable=tuple(
                            a for a in plan.auto_executable if a != ESCALATION_RUNG
                        ),
                        needs_approval=tuple(
                            a for a in plan.needs_approval if a != ESCALATION_RUNG
                        ),
                    )
            # ---- contain: the plan's own unattended action, under the budget
            lock_now = (
                self.immediate_lock
                and corroborated
                and bool(disruptive)
                and bool(target.account)
                and self.incidents.escalation_for(target.account or "") is None
            )
            if disruptive:
                allowed, reason = self.budget.allow(target.account, now)
                if not allowed:
                    held = (*disruptive, ESCALATION_RUNG) if lock_now else disruptive
                    demoted = replace(
                        plan,
                        actions=tuple(dict.fromkeys((*plan.actions, *held))),
                        auto_executable=tuple(
                            a for a in plan.auto_executable if a not in disruptive
                        ),
                        needs_approval=tuple(dict.fromkeys((*plan.needs_approval, *held))),
                    )
                    reasons = dict.fromkeys(held, reason)
                    records.extend(
                        self.executor.execute_plan(
                            demoted,
                            alert_id=alert.alert_id,
                            target=target,
                            notes=reasons,
                        )
                    )
                    return records
                self.budget.spend(target.account, now)
                if lock_now:
                    records.extend(self._lock_on_detection(alert, target, event_time, now))
                    plan = replace(
                        plan,
                        actions=tuple(a for a in plan.actions if a != ESCALATION_RUNG),
                        auto_executable=tuple(
                            a for a in plan.auto_executable if a != ESCALATION_RUNG
                        ),
                        needs_approval=tuple(
                            a for a in plan.needs_approval if a != ESCALATION_RUNG
                        ),
                    )
            records.extend(self.executor.execute_plan(plan, alert_id=alert.alert_id, target=target))
            for record in records:
                if (
                    record.outcome in SETTLED
                    and record.authority == "plan"
                    and ACTIONS[record.action].disruption > 0
                    and target.account
                ):
                    self.incidents.record_containment(
                        Containment(
                            account=target.account,
                            action=record.action,
                            alert_id=alert.alert_id,
                            at=event_time,
                            host=target.source_host,
                        )
                    )
            return records

    def _note_for_corroboration(self, target: Target, event_time: int) -> bool:
        """Record this alert; True when enough earlier alerts back an immediate lock."""
        key = (target.source_host if self.lock_prior_scope == "host" else target.account) or ""
        if not key:
            return self.lock_prior_alerts == 0
        q = self._recent_alerts.setdefault(key, deque())
        while q and q[0] <= event_time - self.lock_prior_window:
            q.popleft()
        prior = len(q)
        q.append(event_time)
        return prior >= self.lock_prior_alerts

    def _lock_on_detection(
        self, alert: AlertLike, target: Target, event_time: int, now: int
    ) -> list[ExecutionRecord]:
        """Lock the account at once: reversible, two hours, no person needed."""
        assert self.incidents is not None
        account = target.account or ""
        hours = (self.incidents.auto_revert_seconds or 0) / 3_600
        reason = (
            f"alert {alert.alert_id} cleared the execution gate (risk {float(alert.risk):.4f}): "
            f"{account} locked at once"
            + (f" for {hours:g} hours unless an analyst keeps or lifts the lock" if hours else "")
            + "; further actions wait for a person"
        )
        record = self.executor.execute_action(
            ESCALATION_RUNG,
            alert_id=alert.alert_id,
            target=target,
            unattended=True,
            escalation=Escalation(
                account=account,
                prior_action=DETECTION,
                prior_alert_id=alert.alert_id,
                prior_at=event_time,
                reason=reason,
            ),
        )
        if record.outcome in SETTLED:
            self.incidents.record_escalation(
                account=account,
                alert_id=alert.alert_id,
                at=event_time,
                prior=Containment(
                    account=account,
                    action=DETECTION,
                    alert_id=alert.alert_id,
                    at=event_time,
                    host=target.source_host,
                ),
                reason=reason,
                revert_from=now,
            )
        return [record]

    # ------------------------------------------------------------ the loop's clock
    def tick(self, now: int | None = None) -> list[ExecutionRecord]:
        """Perform every auto-revert that has come due. Safe to call often."""
        with self._lock:
            return self._tick_locked(self.clock() if now is None else now)

    def _tick_locked(self, now: int) -> list[ExecutionRecord]:
        assert self.incidents is not None
        done: list[ExecutionRecord] = []
        for state in self.incidents.due_reverts(now):
            record = self._revert_escalation(state, reason="auto-revert: no analyst kept the lock")
            if record is not None:
                done.append(record)
        done.extend(self._close_expired_windows(now))
        return done

    def _close_expired_windows(self, now: int) -> list[ExecutionRecord]:
        """Settle every pending action whose approval window has closed."""
        assert self.budget is not None
        closed: list[ExecutionRecord] = []
        window = self.approval_window
        if window.on_timeout == "wait":
            return closed  # pending actions wait for a person, however long
        for pending in self._pending_records():
            deadline = window.deadline(pending)
            if now < deadline:
                continue
            waited = f"no decision within {window.seconds}s (deadline t={deadline})"
            if self.mode != "off" and window.applies_on_timeout(pending.action):
                allowed, refusal = self.budget.allow(pending.target.account, now, escalation=True)
                if allowed:
                    record = self.executor.execute_action(
                        pending.action,
                        alert_id=pending.alert_id,
                        target=pending.target,
                        unattended=True,
                        timeout_reason=(
                            f"approval timeout: {waited}; reversible block applied, "
                            "an analyst can lift it"
                        ),
                    )
                    if record.outcome in SETTLED:
                        self.budget.spend(pending.target.account, now)
                        closed.append(record)
                        continue
                    waited = f"{waited}; block not applied ({record.outcome}: {record.error})"
                else:
                    waited = f"{waited}; block refused by the budget ({refusal})"
            expired = replace(
                pending,
                outcome="expired",
                output=f"expired: {waited}",
                timestamp=now,
                authority="timeout",
            )
            self._persist(expired)
            closed.append(expired)
        return closed

    def _revert_escalation(self, state: EscalationState, *, reason: str) -> ExecutionRecord | None:
        assert self.incidents is not None
        original = next(
            (
                r
                for r in self.store.records(alert_id=state.alert_id)
                if r.action == state.action
                and r.outcome in SETTLED
                and r.authority in LOCK_AUTHORITIES
            ),
            None,
        )
        record = None
        if original is not None and original.command is not None and original.command.revert:
            record = self.executor.revert_action(original, reason=reason)
        self.incidents.mark_reverted(state.account, self.clock())
        return record

    def keep_escalation(self, account: str, *, actor: str) -> EscalationState:
        """An analyst decides the lock stays: no auto-revert."""
        if not actor.strip():
            raise ValueError("keeping an escalation needs an actor")
        with self._lock:
            assert self.incidents is not None
            state = self.incidents.keep(account, actor=actor.strip())
            # Recorded, not just remembered: a restart must not lift a lock a
            # person decided to hold.
            original = next(
                (
                    r
                    for r in self.store.records(alert_id=state.alert_id)
                    if r.action == state.action and r.authority in LOCK_AUTHORITIES
                ),
                None,
            )
            if original is not None:
                self._persist(
                    replace(
                        original,
                        outcome="kept",
                        approved_by=actor.strip(),
                        authority="approval",
                        output=f"kept by {actor.strip()}: no automatic revert",
                        timestamp=self.clock(),
                    )
                )
            return state

    def revert_escalation(self, account: str, *, actor: str) -> ExecutionRecord | None:
        """An analyst lifts the lock now."""
        if not actor.strip():
            raise ValueError("reverting an escalation needs an actor")
        with self._lock:
            assert self.incidents is not None
            state = self.incidents.escalation_for(account)
            if state is None:
                raise LookupError(f"no active escalation on {account}")
            return self._revert_escalation(state, reason=f"reverted by {actor.strip()}")

    def incident_view(self) -> dict[str, object]:
        with self._lock:
            assert self.incidents is not None
            self._tick_locked(self.clock())
            return self.incidents.to_dict()

    def on_alerts(self, alerts: Iterable[AlertLike]) -> None:
        for alert in alerts:
            self.on_alert(alert)

    def approve(
        self, alert_id: str, action: str, *, approver: str, note: str = ""
    ) -> ExecutionRecord:
        """A person releases one reserved action on one alert.

        Only an action that was planned for that alert -- and is still waiting
        -- can be approved; approving something never recommended is refused.
        """
        if not approver.strip():
            raise ValueError("an approval needs an approver")
        pending = {(r.alert_id, r.action): r for r in self.pending()}
        record = pending.get((alert_id, action))
        if record is None:
            raise LookupError(f"no pending approval for {action} on {alert_id}")
        if self.mode == "off":
            raise ValueError("response is off; nothing can be dispatched")
        with self._lock:
            if self.approval_window.on_timeout != "wait" and self.clock() >= (
                self.approval_window.deadline(record)
            ):
                self._tick_locked(self.clock())
                raise LookupError(
                    f"the approval window for {action} on {alert_id} has closed; "
                    "see the response history for what the timeout did"
                )
            return self.executor.execute_action(
                action,
                alert_id=alert_id,
                target=record.target,
                unattended=False,
                approval=Approval(alert_id, action, approver.strip(), note),
            )

    def reject(
        self, alert_id: str, action: str, *, approver: str, note: str = ""
    ) -> ExecutionRecord:
        """A person declines one pending action: it is recorded and never runs,
        not even when its approval window closes."""
        if not approver.strip():
            raise ValueError("a rejection needs an approver")
        with self._lock:
            self._tick_locked(self.clock())
            pending = {(r.alert_id, r.action): r for r in self._pending_records()}
            record = pending.get((alert_id, action))
            if record is None:
                raise LookupError(f"no pending approval for {action} on {alert_id}")
            rejected = replace(
                record,
                outcome="rejected",
                approved_by=approver.strip(),
                authority="approval",
                output=f"rejected by {approver.strip()}" + (f": {note}" if note else ""),
                timestamp=self.clock(),
            )
            self._persist(rejected)
            return rejected

    def unblock(self, alert_id: str, action: str, *, actor: str) -> ExecutionRecord:
        """Lift a block applied by an approval or by an approval timeout."""
        if not actor.strip():
            raise ValueError("lifting a block needs an actor")
        with self._lock:
            latest: ExecutionRecord | None = None
            for record in self.store.all_records():
                if record.alert_id == alert_id and record.action == action:
                    latest = record
            if latest is None or latest.outcome not in SETTLED:
                raise LookupError(f"no applied {action} on {alert_id} to lift")
            if latest.command is None or latest.command.revert is None:
                raise ValueError(f"{action} on {alert_id} has no revert command")
            assert self.incidents is not None
            account = latest.target.account or ""
            state = self.incidents.escalation_for(account) if account else None
            if state is not None and state.action == action and latest.authority in LOCK_AUTHORITIES:
                # A lock the system applied: lift it through the loop so the
                # account stops being shown as locked and no revert is left due.
                record = self._revert_escalation(state, reason=f"lifted by {actor.strip()}")
                if record is not None:
                    return record
            return self.executor.revert_action(latest, reason=f"lifted by {actor.strip()}")

    # ------------------------------------------------------------ mode
    def set_mode(self, mode: Mode, *, actor: str) -> ResponseStatus:
        if mode not in MODES:
            raise ValueError(f"unknown response mode {mode!r}")
        if not actor.strip():
            raise ValueError("a mode change needs an actor")
        with self._lock:
            if mode == "armed" and not self.can_arm:
                raise ValueError(
                    "cannot arm: the configured backend performs nothing. Configure an "
                    "executing backend (GRAPHSENTINEL_RESPONSE_BACKEND=powershell) first."
                )
            self.mode = mode
            self._backend.armed = mode == "armed"
            self._changed_by = actor.strip()
            self._changed_at = self.clock()
        return self.status()

    # ------------------------------------------------------------ views
    def pending(self) -> list[ExecutionRecord]:
        """Latest record per (alert, action) whose outcome is still pending,
        after closing every approval window that has run out."""
        with self._lock:
            self._tick_locked(self.clock())
            return self._pending_records()

    def pending_view(self) -> list[dict[str, object]]:
        """Pending actions with their approval deadline and timeout behaviour."""
        window = self.approval_window
        pending = self.pending()
        now = self.clock()
        return [
            {
                **record.to_dict(),
                "approval_deadline": window.deadline(record),
                "seconds_left": max(0, window.deadline(record) - now),
                "overdue": now >= window.deadline(record),
                "on_timeout": (
                    "wait"
                    if window.on_timeout == "wait"
                    else ("block" if window.applies_on_timeout(record.action) else "expire")
                ),
                "on_timeout_note": window.describe(record.action),
            }
            for record in pending
        ]

    def _pending_records(self) -> list[ExecutionRecord]:
        latest: dict[tuple[str, str], ExecutionRecord] = {}
        for record in self.store.all_records():
            latest[(record.alert_id, record.action)] = record
        return sorted(
            (r for r in latest.values() if r.outcome == "pending_approval"),
            key=lambda r: r.timestamp,
            reverse=True,
        )

    def executions(self, *, limit: int = 200, alert_id: str | None = None) -> list[ExecutionRecord]:
        return self.store.records(limit=limit, alert_id=alert_id)

    def status(self) -> ResponseStatus:
        self.tick()
        records = list(self.store.all_records())
        counts = {
            o: sum(1 for r in records if r.outcome == o) for o in ("executed", "dry_run", "failed")
        }
        return ResponseStatus(
            mode=self.mode,
            backend=self.backend_name,
            armed=bool(getattr(self._backend, "armed", False)),
            can_arm=self.can_arm,
            dispatched=len(records),
            executed=counts["executed"],
            dry_run=counts["dry_run"],
            pending_approval=len(self.pending()),
            failed=counts["failed"],
            approval_window=self.approval_window.to_dict(),
            immediate_lock=self.immediate_lock,
            timed_out_blocks=sum(
                1 for r in records if r.authority == "timeout" and r.outcome in SETTLED
            ),
            rejected=sum(1 for r in records if r.outcome == "rejected"),
            expired=sum(1 for r in records if r.outcome == "expired"),
            last_dispatch_at=max((r.timestamp for r in records), default=None),
            changed_by=self._changed_by,
            changed_at=self._changed_at,
            budget=self.budget.to_dict() if self.budget is not None else {},
            incidents=self.incidents.to_dict() if self.incidents is not None else {},
        )

    # ------------------------------------------------------------ internals
    def _persist(self, record: ExecutionRecord) -> None:
        self.store.append(record)
        if self.audit is not None:
            self.audit(record)


def coordinator_from_environment(
    *,
    mode: str,
    backend: str,
    store: ResponseStore | None = None,
) -> ResponseCoordinator:
    """Build the coordinator the API runs with, from its configuration strings.

    An unknown mode or backend is a configuration error and is refused loudly;
    silently falling back to ``dry_run`` would make an operator believe the
    system was armed when it was not, or the reverse.
    """
    if mode not in MODES:
        raise ValueError(f"GRAPHSENTINEL_AUTO_RESPONSE must be one of {MODES}, not {mode!r}")
    if backend == "dry_run":
        chosen: Backend = DryRunBackend()
    elif backend == "powershell":
        chosen = PowerShellBackend()
    else:
        raise ValueError(
            f"GRAPHSENTINEL_RESPONSE_BACKEND must be 'dry_run' or 'powershell', not {backend!r}"
        )
    return ResponseCoordinator(
        store=store or MemoryResponseStore(),
        mode=mode,
        backend=chosen,
        budget=budget_from_environment(),
        incidents=incidents_from_environment(),
        approval_window=approval_window_from_environment(),
        immediate_lock=os.getenv("GRAPHSENTINEL_IMMEDIATE_LOCK", "on").strip().lower()
        not in {"off", "0", "false", "no"},
        lock_prior_alerts=int(os.getenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", str(DEFAULT_LOCK_PRIOR_ALERTS))),
        lock_prior_scope=os.getenv("GRAPHSENTINEL_LOCK_PRIOR_SCOPE", "account").strip().lower(),
    )


__all__: Sequence[str] = (
    "DEFAULT_APPROVAL_WINDOW_SECONDS",
    "TIMEOUT_BLOCKABLE",
    "ApprovalWindow",
    "approval_window_from_environment",
    "DEFAULT_UNATTENDED_COOLDOWN_SECONDS",
    "DEFAULT_UNATTENDED_PER_HOUR",
    "MODES",
    "Mode",
    "ResponseCoordinator",
    "ResponseStatus",
    "UnattendedBudget",
    "budget_from_environment",
    "coordinator_from_environment",
    "incidents_from_environment",
)
