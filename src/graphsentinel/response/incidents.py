"""The prevention loop, per account: contain, verify, escalate, revert.

One session kill is the only thing the product does to an account without a
person (``docs/AUTOMATIC_RESPONSE.md``). It is cheap and reversible, and it
is also the action most likely to fail: on-premises Kerberos tickets already
issued stay valid until they expire, so an attacker holding one keeps
moving. A system that stops at the kill is not preventing; it is hoping.

This module is the part that watches whether the kill worked. After an
unattended containment on an account, the account is under observation for
``escalation_window_seconds``. If, inside that window, the same account
qualifies for an unattended action *again* -- a second confident detection,
by the model or the chain rule, the same evidence that justified the first --
the containment demonstrably did not hold, and the coordinator escalates
one rung to ``lock_account``: reversible, budgeted, one escalation per
account per window, and recorded with the evidence it rests on.

Because a lock is disruptive, it does not stay on by itself. A lock the
system applied on its own is reverted automatically after
``auto_revert_seconds`` (default two hours) unless an analyst keeps it (or
the account moves again, which restarts the clock). The blast radius of a
wrong escalation is therefore one account for one window, and the record
says so.

Two hours rather than one: the revert is the *upper* bound on how long a
wrong lock hurts, not a target. An hour is shorter than the interval between
hops of the slow campaigns the instrument measures (15 min to 1 h), so a
lock could expire while the attacker was still mid-campaign and simply
waiting; and an hour is short against the time a real shift takes to pick up
a queued incident out of hours. Two hours keeps the account contained across
that gap while remaining a bounded, self-healing action a wrong detection
cannot turn into an outage. An analyst can lift it at any moment, and every
alert on a locked account restarts the clock, so a genuinely active attacker
never runs it out.

Two clocks. The window is measured on event time -- the attacker's clock --
so a replayed day or a batched hour escalates exactly as a live stream
would; the auto-revert is scheduled on wall time, so a lock applied during
a replay is not lifted the moment it is applied.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

DEFAULT_ESCALATION_WINDOW_SECONDS = 1_800
DEFAULT_AUTO_REVERT_SECONDS = 7_200
ESCALATION_RUNG = "lock_account"


@dataclass(frozen=True, slots=True)
class Containment:
    account: str
    action: str
    alert_id: str
    at: int
    host: str | None


@dataclass
class EscalationState:
    account: str
    action: str
    alert_id: str
    at: int
    prior_alert_id: str
    reason: str
    #: When the lock will be lifted by the system unless kept; None once kept
    #: or reverted.
    revert_at: int | None
    kept_by: str | None = None
    reverted_at: int | None = None
    #: Alerts on this account after the escalation: evidence the lock held
    #: (a locked account cannot authenticate) or did not.
    later_alerts: list[str] = field(default_factory=list)
    #: True when this state was replayed from the durable records at start
    #: rather than decided live: ``at`` is then the dispatch's wall-clock
    #: time and there is no separate prior alert to point at.
    adopted: bool = False

    @property
    def active(self) -> bool:
        return self.reverted_at is None

    def to_dict(self) -> dict[str, object]:
        return {
            "account": self.account,
            "action": self.action,
            "alert_id": self.alert_id,
            "at": self.at,
            "prior_alert_id": self.prior_alert_id,
            "reason": self.reason,
            "revert_at": self.revert_at,
            "kept_by": self.kept_by,
            "reverted_at": self.reverted_at,
            "active": self.active,
            "later_alerts": list(self.later_alerts),
            "adopted": self.adopted,
        }


@dataclass
class IncidentTracker:
    escalation_window_seconds: int = DEFAULT_ESCALATION_WINDOW_SECONDS
    auto_revert_seconds: int | None = DEFAULT_AUTO_REVERT_SECONDS
    enabled: bool = True
    _containments: dict[str, list[Containment]] = field(default_factory=dict)
    _escalations: dict[str, EscalationState] = field(default_factory=dict)
    history: list[EscalationState] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.escalation_window_seconds <= 0:
            raise ValueError("escalation_window_seconds must be positive")
        if self.auto_revert_seconds is not None and self.auto_revert_seconds <= 0:
            raise ValueError("auto_revert_seconds must be positive when set")

    # ------------------------------------------------------------ containment
    def record_containment(self, containment: Containment) -> None:
        self._containments.setdefault(containment.account, []).append(containment)

    def failed_containment(self, account: str, event_time: int) -> Containment | None:
        """The containment this account has already had inside the window
        (measured on event time), if it is still under observation and not
        yet escalated."""
        if not self.enabled:
            return None
        if self.escalation_for(account) is not None:
            return None  # already escalated; the caller notes the alert instead
        cutoff = event_time - self.escalation_window_seconds
        recent = [c for c in self._containments.get(account, []) if cutoff <= c.at <= event_time]
        return recent[-1] if recent else None

    # ------------------------------------------------------------ escalation
    def record_escalation(
        self,
        *,
        account: str,
        alert_id: str,
        at: int,
        prior: Containment,
        reason: str,
        revert_from: int | None = None,
    ) -> EscalationState:
        """``at`` is event time (the attacker's clock, which the window is
        measured on); ``revert_from`` is wall-clock time, from which the
        auto-revert is scheduled, so a replayed stream does not lift a lock
        the moment it is applied."""
        base = at if revert_from is None else revert_from
        state = EscalationState(
            account=account,
            action=ESCALATION_RUNG,
            alert_id=alert_id,
            at=at,
            prior_alert_id=prior.alert_id,
            reason=reason,
            revert_at=(base + self.auto_revert_seconds) if self.auto_revert_seconds else None,
        )
        self._escalations[account] = state
        self.history.append(state)
        return state

    def adopt(
        self,
        *,
        account: str,
        alert_id: str,
        at: int,
        prior_alert_id: str,
        reason: str,
        revert_at: int | None,
        kept_by: str | None = None,
    ) -> EscalationState:
        """Re-register a lock that is already in force (restart recovery).

        Unlike :meth:`record_escalation` this does not schedule anything: the
        revert time is the one the original escalation chose, so a restart
        inside the window lifts the lock when it was always going to be
        lifted, and a restart after it lifts it at the next tick.
        """
        state = EscalationState(
            account=account,
            action=ESCALATION_RUNG,
            alert_id=alert_id,
            at=at,
            prior_alert_id=prior_alert_id,
            reason=reason,
            revert_at=None if kept_by else revert_at,
            kept_by=kept_by,
            adopted=True,
        )
        self._escalations[account] = state
        self.history.append(state)
        return state

    def escalation_for(self, account: str) -> EscalationState | None:
        state = self._escalations.get(account)
        return state if state is not None and state.active else None

    def note_alert_after_escalation(self, account: str, alert_id: str, now: int) -> None:
        """An alert on a locked account: evidence, and the clock restarts."""
        state = self.escalation_for(account)
        if state is None:
            return
        state.later_alerts.append(alert_id)
        if state.revert_at is not None and state.kept_by is None and self.auto_revert_seconds:
            state.revert_at = now + self.auto_revert_seconds

    def keep(self, account: str, *, actor: str) -> EscalationState:
        state = self.escalation_for(account)
        if state is None:
            raise LookupError(f"no active escalation on {account}")
        state.kept_by = actor
        state.revert_at = None
        return state

    def due_reverts(self, now: int) -> list[EscalationState]:
        return [
            s
            for s in self._escalations.values()
            if s.active and s.kept_by is None and s.revert_at is not None and s.revert_at <= now
        ]

    def mark_reverted(self, account: str, now: int) -> EscalationState:
        state = self._escalations.get(account)
        if state is None or not state.active:
            raise LookupError(f"no active escalation on {account}")
        state.reverted_at = now
        state.revert_at = None
        return state

    def active(self) -> Iterable[EscalationState]:
        return [s for s in self._escalations.values() if s.active]

    def to_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "escalation_window_seconds": self.escalation_window_seconds,
            "auto_revert_seconds": self.auto_revert_seconds,
            "rung": ESCALATION_RUNG,
            "active": [s.to_dict() for s in self.active()],
            "escalations_total": len(self.history),
            "accounts_under_observation": len(self._containments),
        }


__all__ = [
    "DEFAULT_AUTO_REVERT_SECONDS",
    "DEFAULT_ESCALATION_WINDOW_SECONDS",
    "ESCALATION_RUNG",
    "Containment",
    "EscalationState",
    "IncidentTracker",
]
