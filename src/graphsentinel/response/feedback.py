"""Analyst decisions as training labels.

Every decision an analyst makes in the response workflow says something about
the alert it was made on. Approving a disruptive action, or keeping a lock the
system applied, confirms the activity as an attack. Rejecting every action
that waited, or lifting the system's lock by hand, marks it as benign. An alert
nobody decided on carries no label.

These labels are what an estate-trained detector learns from: on LANL a
gradient-boosted model trained on the estate's own confirmed incidents was the
strongest detector of the final window. ``feedback_labels`` turns the durable
response records into one verdict per alert; ``feedback_rows`` joins them with
the alerts so the offline pipeline can attach the 30 causal features by event
and retrain (``scripts/retrain_from_feedback.py``).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from graphsentinel.detection.response import ACTIONS
from graphsentinel.response.executor import ExecutionRecord

Label = Literal[0, 1]
SETTLED_OUTCOMES = frozenset({"dry_run", "executed"})


@dataclass(frozen=True, slots=True)
class Verdict:
    alert_id: str
    label: Label
    #: Which decision produced the label.
    source: str
    decided_by: str | None
    decided_at: int

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_id": self.alert_id,
            "label": self.label,
            "source": self.source,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }


def _analyst_lift(record: ExecutionRecord) -> str | None:
    """The actor who lifted a system lock by hand, or None for an automatic lift."""
    if record.outcome != "reverted":
        return None
    text = record.output or ""
    for prefix in ("lifted by ", "reverted by "):
        if text.startswith(prefix):
            return text[len(prefix):].strip() or None
    return None


def feedback_labels(records: Iterable[ExecutionRecord]) -> dict[str, Verdict]:
    """One verdict per alert from the response records; a confirmation wins."""
    confirmed: dict[str, Verdict] = {}
    benign: dict[str, Verdict] = {}
    pending: dict[str, set[str]] = {}
    rejected: dict[str, list[ExecutionRecord]] = {}
    for r in records:
        disruptive = ACTIONS[r.action].disruption > 0 if r.action in ACTIONS else False
        if r.outcome == "pending_approval":
            pending.setdefault(r.alert_id, set()).add(r.action)
        elif r.outcome == "rejected":
            rejected.setdefault(r.alert_id, []).append(r)
        elif r.authority == "approval" and r.outcome in SETTLED_OUTCOMES and disruptive:
            confirmed[r.alert_id] = Verdict(r.alert_id, 1, f"approved {r.action}", r.approved_by, r.timestamp)
        elif r.outcome == "kept":
            confirmed[r.alert_id] = Verdict(r.alert_id, 1, "kept the lock", r.approved_by, r.timestamp)
        else:
            actor = _analyst_lift(r)
            if actor is not None:
                benign[r.alert_id] = Verdict(r.alert_id, 0, f"lifted {r.action}", actor, r.timestamp)
    for alert_id, rows in rejected.items():
        if alert_id in benign or alert_id in confirmed:
            continue
        if {r.action for r in rows} >= pending.get(alert_id, set()):
            last = max(rows, key=lambda r: r.timestamp)
            benign[alert_id] = Verdict(alert_id, 0, "rejected every action", last.approved_by, last.timestamp)
    out = dict(benign)
    out.update(confirmed)  # an approval or a kept lock outranks a lift on another action
    return out


def feedback_rows(alerts: Sequence[Any], verdicts: dict[str, Verdict]) -> list[dict[str, object]]:
    """Labelled rows the offline pipeline joins with features by ``event_id``."""
    rows = []
    for alert in alerts:
        verdict = verdicts.get(str(alert.alert_id))
        if verdict is None:
            continue
        event = alert.evidence.event
        rows.append({
            "alert_id": alert.alert_id,
            "event_id": int(alert.event_id),
            "timestamp": int(alert.timestamp),
            "user": event.user,
            "source_host": event.source_host,
            "destination_host": event.destination_host,
            "risk": float(alert.risk),
            **verdict.to_dict(),
        })
    return rows


__all__ = ["Verdict", "feedback_labels", "feedback_rows"]
