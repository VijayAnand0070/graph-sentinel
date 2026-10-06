"""Strict evidence, ATT&CK, and analyst-report schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

TelemetrySource = Literal["auth", "process", "flow", "dns"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AlertEvent(StrictModel):
    timestamp: int = Field(ge=0)
    user: str = Field(min_length=1, max_length=128)
    source_host: str = Field(min_length=1, max_length=128)
    destination_host: str = Field(min_length=1, max_length=128)


class ScoreBundle(StrictModel):
    tgn: float = Field(ge=0, le=1)
    novelty: float = Field(ge=0, le=1)
    burst: float = Field(ge=0, le=1)
    pivot: float = Field(ge=0, le=1)
    corroboration: float = Field(ge=0, le=1)
    fused: float = Field(ge=0, le=1)


class EvidenceItem(StrictModel):
    evidence_id: str = Field(pattern=r"^E-[0-9]{3,}$")
    category: Literal["observed", "derived", "model"]
    statement: str = Field(min_length=1, max_length=500)
    value: int | float | str | bool


class AttackMapping(StrictModel):
    tactic: Literal["Lateral Movement"]
    technique_id: Literal["T1021"]
    technique: Literal["Remote Services"]
    subtechnique: str | None = None
    confidence: Literal["low", "medium", "high"]
    justification_evidence_ids: tuple[str, ...]
    limitation: str = Field(min_length=1, max_length=500)


class EvidenceBundle(StrictModel):
    schema_version: Literal[1] = 1
    alert_id: str = Field(pattern=r"^GS-[A-Z0-9-]+$")
    event: AlertEvent
    scores: ScoreBundle
    evidence: tuple[EvidenceItem, ...] = Field(min_length=1)
    path_id: str | None = None
    path_hosts: tuple[str, ...] = ()
    telemetry_sources: tuple[TelemetrySource, ...] = ("auth",)
    attack_mapping: AttackMapping

    @model_validator(mode="after")
    def evidence_references_exist(self) -> EvidenceBundle:
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique")
        unknown = set(self.attack_mapping.justification_evidence_ids) - set(evidence_ids)
        if unknown:
            raise ValueError(f"ATT&CK mapping references unknown evidence: {sorted(unknown)}")
        return self


class CitedStatement(StrictModel):
    text: str = Field(min_length=1, max_length=800)
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class TimelineItem(StrictModel):
    timestamp: int = Field(ge=0)
    description: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[str, ...] = Field(min_length=1)


class TriageReport(StrictModel):
    schema_version: Literal[1] = 1
    alert_id: str
    executive_summary: tuple[CitedStatement, ...] = Field(min_length=1, max_length=4)
    why_suspicious: tuple[CitedStatement, ...] = Field(min_length=1)
    timeline: tuple[TimelineItem, ...] = Field(min_length=1)
    affected_entities: tuple[str, ...] = Field(min_length=1)
    attack_mapping: AttackMapping
    recommended_actions: tuple[str, ...] = Field(min_length=1)
    uncertainty: tuple[CitedStatement, ...] = Field(min_length=1)
