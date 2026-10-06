"""Deterministic construction of defensible alert evidence bundles."""

from __future__ import annotations

from typing import Literal

from graphsentinel.detection.fusion import FusedRisk
from graphsentinel.detection.path_ranker import SuspiciousPath
from graphsentinel.explain.schemas import (
    AlertEvent,
    AttackMapping,
    EvidenceBundle,
    EvidenceItem,
    ScoreBundle,
    TelemetrySource,
)


def build_evidence_bundle(
    *,
    alert_id: str,
    timestamp: int,
    user: str,
    source_host: str,
    destination_host: str,
    risk: FusedRisk,
    is_new_pair: bool,
    user_fanout_5m: int,
    recent_failures: int,
    path: SuspiciousPath | None = None,
    telemetry_sources: tuple[TelemetrySource, ...] = ("auth",),
) -> EvidenceBundle:
    evidence = [
        EvidenceItem(
            evidence_id="E-001",
            category="observed",
            statement=(
                f"User {user} authenticated from {source_host} to {destination_host} "
                f"at dataset time {timestamp}."
            ),
            value=timestamp,
        ),
        EvidenceItem(
            evidence_id="E-002",
            category="derived",
            statement="The user-destination relationship was new before this event.",
            value=is_new_pair,
        ),
        EvidenceItem(
            evidence_id="E-003",
            category="derived",
            statement="Distinct destinations reached by the user in the prior five minutes.",
            value=user_fanout_5m,
        ),
        EvidenceItem(
            evidence_id="E-004",
            category="derived",
            statement="Failed authentications by the user in the prior fifteen minutes.",
            value=recent_failures,
        ),
        EvidenceItem(
            evidence_id="E-005",
            category="model",
            statement="Pre-update Temporal Graph Network event probability.",
            value=risk.components.tgn,
        ),
        EvidenceItem(
            evidence_id="E-006",
            category="model",
            statement="Configured evidence-fusion risk score.",
            value=risk.score,
        ),
    ]
    mapping_ids = ["E-001", "E-002", "E-005"]
    if path is not None:
        evidence.append(
            EvidenceItem(
                evidence_id="E-007",
                category="derived",
                statement="Destination participated in a strictly time-increasing pivot path.",
                value=path.path_id,
            )
        )
        mapping_ids.append("E-007")
    confidence: Literal["low", "medium", "high"] = (
        "medium" if path is not None and risk.score >= 0.8 else "low"
    )
    return EvidenceBundle(
        alert_id=alert_id,
        event=AlertEvent(
            timestamp=timestamp,
            user=user,
            source_host=source_host,
            destination_host=destination_host,
        ),
        scores=ScoreBundle(
            **risk.components.to_dict(),
            fused=risk.score,
        ),
        evidence=tuple(evidence),
        path_id=path.path_id if path else None,
        path_hosts=tuple(str(host) for host in path.host_ids) if path else (),
        telemetry_sources=telemetry_sources,
        attack_mapping=AttackMapping(
            tactic="Lateral Movement",
            technique_id="T1021",
            technique="Remote Services",
            subtechnique=None,
            confidence=confidence,
            justification_evidence_ids=tuple(mapping_ids),
            limitation=(
                "Authentication behavior is consistent with lateral movement, but de-identified "
                "telemetry does not establish a specific remote-service sub-technique."
            ),
        ),
    )
