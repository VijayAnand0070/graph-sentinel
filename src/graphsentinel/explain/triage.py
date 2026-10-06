"""Provider-neutral triage with deterministic fallback and citation guardrails."""

from __future__ import annotations

from typing import Protocol

from graphsentinel.explain.schemas import (
    CitedStatement,
    EvidenceBundle,
    TimelineItem,
    TriageReport,
)


class TriageProvider(Protocol):
    name: str
    version: str

    def generate(self, evidence: EvidenceBundle) -> TriageReport: ...


def validate_report_grounding(evidence: EvidenceBundle, report: TriageReport) -> TriageReport:
    if report.alert_id != evidence.alert_id:
        raise ValueError("triage report alert ID does not match evidence")
    allowed = {item.evidence_id for item in evidence.evidence}
    referenced: set[str] = set()
    statements = (*report.executive_summary, *report.why_suspicious, *report.uncertainty)
    for statement in statements:
        referenced.update(statement.evidence_ids)
    for item in report.timeline:
        referenced.update(item.evidence_ids)
    unknown = referenced - allowed
    if unknown:
        raise ValueError(f"triage report cites unknown evidence: {sorted(unknown)}")
    if report.attack_mapping != evidence.attack_mapping:
        raise ValueError("triage report altered the detector's ATT&CK mapping")
    return report


class DeterministicTriageProvider:
    """Offline, reproducible report generator used when no approved LLM is configured."""

    name = "deterministic-template"
    version = "1"

    def generate(self, evidence: EvidenceBundle) -> TriageReport:
        suspicious = tuple(
            CitedStatement(text=item.statement, evidence_ids=(item.evidence_id,))
            for item in evidence.evidence
            if item.category in {"derived", "model"}
        )
        # Cite IDs that are actually present in THIS bundle rather than the
        # literals "E-001"/"E-006". Those happen to exist in the bundles the
        # live gateway currently emits, but hardcoding them made the
        # deterministic provider raise on any other evidence layout -- and
        # this provider is the system's fallback of last resort (the agent
        # provider degrades to it), so it must never be the thing that fails.
        first_id = evidence.evidence[0].evidence_id
        model_ids = tuple(
            item.evidence_id for item in evidence.evidence if item.category == "model"
        )
        summary_ids = (first_id, *model_ids[-1:]) if model_ids else (first_id,)
        # why_suspicious has min_length=1: a bundle of purely "observed" items
        # would otherwise produce an empty tuple and fail schema validation.
        if not suspicious:
            suspicious = (
                CitedStatement(
                    text=evidence.evidence[0].statement,
                    evidence_ids=(first_id,),
                ),
            )
        report = TriageReport(
            alert_id=evidence.alert_id,
            executive_summary=(
                CitedStatement(
                    text=(
                        f"GraphSentinel ranked authentication from "
                        f"{evidence.event.source_host} to {evidence.event.destination_host} "
                        f"at fused risk {evidence.scores.fused:.3f}."
                    ),
                    evidence_ids=summary_ids,
                ),
            ),
            why_suspicious=suspicious,
            timeline=(
                TimelineItem(
                    timestamp=evidence.event.timestamp,
                    description=evidence.evidence[0].statement,
                    evidence_ids=(first_id,),
                ),
            ),
            affected_entities=(
                evidence.event.user,
                evidence.event.source_host,
                evidence.event.destination_host,
            ),
            attack_mapping=evidence.attack_mapping,
            recommended_actions=(
                f"Verify expected activity for account {evidence.event.user}.",
                f"Review authentication and process context on {evidence.event.destination_host}.",
                "Review adjacent path events before considering containment under local policy.",
            ),
            uncertainty=(
                CitedStatement(
                    text=evidence.attack_mapping.limitation,
                    evidence_ids=evidence.attack_mapping.justification_evidence_ids,
                ),
            ),
        )
        return validate_report_grounding(evidence, report)
