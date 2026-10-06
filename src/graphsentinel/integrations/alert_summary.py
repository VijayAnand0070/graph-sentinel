"""The minimal, integration-agnostic view of an alert every exporter shares."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class WebhookAlertSummary:
    alert_id: str
    risk: float
    user: str
    source_host: str
    destination_host: str
    timestamp: int
    severity: Severity
    #: Actions planned for this alert that wait for a person, and the time by
    #: which they must be decided before the approval window closes.
    pending_actions: tuple[str, ...] = ()
    decision_due: int | None = None

    def __post_init__(self) -> None:
        if not self.alert_id:
            raise ValueError("alert_id must be non-empty")
        if not 0 <= self.risk <= 1:
            raise ValueError("risk must be in [0, 1]")
        if not self.user or not self.source_host or not self.destination_host:
            raise ValueError("user, source_host, and destination_host must be non-empty")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")


def severity_from_risk(risk: float) -> Severity:
    if not 0 <= risk <= 1:
        raise ValueError("risk must be in [0, 1]")
    if risk >= 0.85:
        return "critical"
    if risk >= 0.7:
        return "high"
    if risk >= 0.5:
        return "medium"
    return "low"
