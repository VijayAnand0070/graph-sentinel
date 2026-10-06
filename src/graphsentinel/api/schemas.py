"""Request and response contracts for scoring and analyst workflows."""

from __future__ import annotations

from itertools import pairwise
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from graphsentinel.explain.schemas import EvidenceBundle, StrictModel, TriageReport


class RiskComponentInput(StrictModel):
    tgn: float | None = Field(default=None, ge=0, le=1)
    novelty: float = Field(ge=0, le=1)
    burst: float = Field(ge=0, le=1)
    pivot: float = Field(ge=0, le=1)
    corroboration: float = Field(ge=0, le=1)


class TacticVerdict(StrictModel):
    """One ATT&CK technique attributed to an event, with its supporting evidence.

    Carried alongside the risk score rather than derived from it: risk answers
    "how suspicious", this answers "suspicious of what", and an analyst needs
    both to choose a response. ``evidence`` is the list of rule clauses that
    actually fired, so a wrong attribution can be argued with at the clause
    level instead of being an opaque label.
    """

    technique_id: str = Field(min_length=2, max_length=16)
    name: str = Field(min_length=1, max_length=96)
    tactic: str = Field(min_length=1, max_length=96)
    score: float = Field(ge=0, le=1)
    confidence: Literal["none", "low", "medium", "high"] = "low"
    evidence: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()


class ScoreEventRequest(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    event_id: int = Field(ge=0)
    timestamp: int = Field(ge=0)
    user_id: int = Field(ge=0)
    source_host_id: int = Field(ge=0)
    destination_host_id: int = Field(ge=0)
    user: str = Field(min_length=1, max_length=128)
    source_host: str = Field(min_length=1, max_length=128)
    destination_host: str = Field(min_length=1, max_length=128)
    is_new_pair: bool
    user_fanout_5m: int = Field(ge=0)
    recent_failures: int = Field(ge=0)
    evidence_support: float = Field(ge=0, le=1, default=0)
    label_redteam: int = Field(ge=0, le=1, default=0)
    message: tuple[float, ...] | None = Field(default=None, min_length=1, max_length=1_024)
    components: RiskComponentInput
    tactic: TacticVerdict | None = None
    #: A deterministic multi-hop chain was detected for this account. Carried
    #: as an explicit flag rather than inferred from the pivot channel, because
    #: that channel also reaches 1.0 on fan-out and the two must not be
    #: confused: one is a rule firing, the other is a continuous signal.
    chain_detected: bool = False
    #: The fan-out rule fired: this source host is reaching new hosts with
    #: several accounts (``detection/signals.py``, :class:`FanOutTracker`).
    fanout_detected: bool = False

    @model_validator(mode="after")
    def source_destination_differ(self) -> ScoreEventRequest:
        if self.source_host_id == self.destination_host_id:
            raise ValueError("source and destination hosts must differ for lateral movement")
        if (self.message is None) == (self.components.tgn is None):
            raise ValueError("provide exactly one of message or components.tgn")
        return self


class ScoreBatchRequest(StrictModel):
    events: tuple[ScoreEventRequest, ...] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def chronological(self) -> ScoreBatchRequest:
        if any(
            current.timestamp < previous.timestamp for previous, current in pairwise(self.events)
        ):
            raise ValueError("batch events must be chronological")
        event_ids = [event.event_id for event in self.events]
        if len(event_ids) != len(set(event_ids)):
            raise ValueError("event IDs must be unique within a batch")
        return self


class ScoreEventResponse(StrictModel):
    alert_id: str
    event_id: int
    risk: float = Field(ge=0, le=1)
    alerted: bool
    threshold: float = Field(ge=0, le=1)
    severity: Literal["low", "medium", "high", "critical"] = "low"
    confidence: float = Field(default=0, ge=0, le=1)
    uncertainty: float = Field(default=1, ge=0, le=1)
    dominant_signals: tuple[str, ...] = ()
    tactic: TacticVerdict | None = None
    #: Names the deterministic rule that raised this score, if any.
    rule_floor: str | None = None
    #: Per-channel inputs behind ``risk``, before fusion.
    #:
    #: Exposed because the fused score alone cannot answer "which channel
    #: decided this", and because comparing a deployment against an offline
    #: reference requires comparing the same quantity -- fused risk against a
    #: raw model probability is not a like-for-like test, and treating it as
    #: one produces a confounded answer.
    components: dict[str, float] | None = None


class ScoreBatchResponse(StrictModel):
    results: tuple[ScoreEventResponse, ...]
    paths_created: int = Field(ge=0)


class LiveAuthEvent(StrictModel):
    """Vendor-neutral authentication event accepted by the live gateway."""

    timestamp: int = Field(ge=0)
    user: str = Field(min_length=1, max_length=128)
    source_host: str = Field(min_length=1, max_length=128)
    destination_host: str = Field(min_length=1, max_length=128)
    destination_user: str | None = Field(default=None, max_length=128)
    auth_type: str = Field(default="unknown", min_length=1, max_length=64)
    logon_type: str = Field(default="unknown", min_length=1, max_length=64)
    orientation: str = Field(default="logon", min_length=1, max_length=64)
    success: bool
    corroboration: float = Field(default=0, ge=0, le=1)
    source: str = Field(default="generic", min_length=1, max_length=64)


class LiveAuthBatch(StrictModel):
    batch_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    )
    events: tuple[LiveAuthEvent, ...] = Field(min_length=1, max_length=5_000)

    @model_validator(mode="after")
    def chronological(self) -> LiveAuthBatch:
        if any(
            current.timestamp < previous.timestamp for previous, current in pairwise(self.events)
        ):
            raise ValueError("live events must be chronological")
        return self


class LiveDetectionStatus(StrictModel):
    mode: Literal["temporal_model", "explainable_fallback", "configuration_error"]
    accepted_events: int = Field(ge=0)
    rejected_batches: int = Field(ge=0)
    duplicate_batches: int = Field(ge=0)
    last_timestamp: int | None = Field(default=None, ge=0)
    sources: dict[str, int]
    oov_identifiers: dict[str, int] = Field(default_factory=dict)
    frozen_entity_dictionary: bool
    model_contract_ready: bool
    entity_dictionary_sha256: str | None = None
    model_generation: int = Field(ge=0)
    state_reset_count: int = Field(ge=0)
    idempotency_capacity: int = Field(gt=0)


class TrainingStartRequest(StrictModel):
    epochs: int = Field(default=12, ge=1, le=100)
    patience: int = Field(default=3, ge=1, le=20)
    max_events: int | None = Field(default=None, ge=100, le=50_000_000)
    device: Literal["cpu", "cuda"] = "cpu"


class TrainingStatus(StrictModel):
    state: Literal["idle", "running", "completed", "rejected", "failed"]
    epoch: int = Field(ge=0)
    total_epochs: int = Field(ge=0)
    progress: float = Field(ge=0, le=1)
    train_loss: float | None = Field(default=None, ge=0)
    validation_pr_auc: float | None = Field(default=None, ge=0, le=1)
    message: str
    checkpoint_path: str | None = None
    report_path: str | None = None
    started_at: int | None = Field(default=None, ge=0)
    completed_at: int | None = Field(default=None, ge=0)


class DataReadiness(StrictModel):
    raw_auth_registered: bool
    raw_labels_registered: bool
    normalized_dataset_ready: bool
    feature_dataset_ready: bool
    feature_report_ready: bool
    entity_dictionary_ready: bool
    checkpoint_ready: bool
    training_ready: bool


class Phase16StartRequest(StrictModel):
    """Bounded configuration for the real-data accuracy pipeline."""

    max_events: int | None = Field(default=250_000, ge=100, le=50_000_000)
    epochs: int = Field(default=12, ge=1, le=100)
    patience: int = Field(default=3, ge=1, le=20)
    device: Literal["cpu", "cuda", "auto"] = "auto"


class Phase16TimeRange(StrictModel):
    start: float | None = None
    end: float | None = None


class Phase16Provenance(StrictModel):
    mode: Literal["real", "demo", "unregistered"]
    label: str
    dataset_id: str | None = None
    dataset_version: str | None = None
    source: str | None = None
    registered_at: str | None = None
    immutable: bool
    file_count: int = Field(ge=0)
    event_count: int = Field(ge=0)
    positive_events: int | None = Field(default=None, ge=0)
    dataset_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    time_range: Phase16TimeRange
    notice: str


class Phase16PipelineStage(StrictModel):
    key: Literal["register", "normalize", "features", "train", "validate", "test", "promote"]
    label: str
    status: Literal["complete", "running", "blocked", "pending", "failed"]
    detail: str
    updated_at: str | None = None


class Phase16JobConfig(StrictModel):
    max_events: int | None = Field(default=None, ge=100, le=50_000_000)
    epochs: int = Field(ge=1, le=100)
    patience: int = Field(ge=1, le=20)
    device: Literal["cpu", "cuda", "auto"]


class Phase16Job(StrictModel):
    job_id: str | None = None
    state: Literal["idle", "queued", "running", "completed", "failed", "rejected"]
    progress: float = Field(ge=0, le=1)
    stage: str | None = None
    epoch: int = Field(ge=0)
    total_epochs: int = Field(ge=0)
    started_at: str | None = None
    finished_at: str | None = None
    message: str
    config: Phase16JobConfig


class Phase16SplitPartition(StrictModel):
    events: int = Field(ge=0)
    positive_events: int = Field(ge=0)
    positive_rate: float | None = Field(default=None, ge=0, le=1)
    start: float | None = None
    end: float | None = None


class Phase16LeakageCheck(StrictModel):
    name: str
    passed: bool
    detail: str


class Phase16Split(StrictModel):
    strategy: Literal["chronological"] = "chronological"
    train: Phase16SplitPartition
    validation: Phase16SplitPartition
    test: Phase16SplitPartition
    leakage_checks: tuple[Phase16LeakageCheck, ...]


class Phase16MetricSet(StrictModel):
    pr_auc: float | None = Field(default=None, ge=0, le=1)
    recall_at_k: float | None = Field(default=None, ge=0, le=1)
    precision_at_k: float | None = Field(default=None, ge=0, le=1)
    false_positives_per_10k: float | None = Field(default=None, ge=0)
    brier_score: float | None = Field(default=None, ge=0, le=1)
    threshold: float | None = Field(default=None, ge=0, le=1)


class Phase16BaselineMetrics(Phase16MetricSet):
    name: str


class Phase16Metrics(StrictModel):
    model_name: str
    k: int = Field(gt=0)
    validation: Phase16MetricSet
    test: Phase16MetricSet
    baseline: Phase16BaselineMetrics


class Phase16PromotionGate(StrictModel):
    name: str
    actual: float | None = None
    target: float | None = None
    operator: Literal[">=", "<=", ">", "<", "=="]
    passed: bool | None = None
    detail: str


class Phase16Promotion(StrictModel):
    status: Literal["promoted", "rejected", "blocked", "not_evaluated"]
    eligible: bool
    decision: str
    gates: tuple[Phase16PromotionGate, ...]
    promoted_at: str | None = None
    current_checkpoint_id: str | None = None
    previous_checkpoint_id: str | None = None


class Phase16Checkpoint(StrictModel):
    checkpoint_id: str
    created_at: str
    model_type: str
    epoch: int = Field(ge=0)
    dictionary_sha256: str
    dataset_sha256: str
    code_version: str
    feature_contract_version: str
    normalization_fit_scope: Literal["train_only"] = "train_only"
    parameter_count: int = Field(ge=0)
    device: str
    oov_user_buckets: int = Field(default=0, ge=0)
    oov_host_buckets: int = Field(default=0, ge=0)


class Phase16Overview(StrictModel):
    phase: Literal["phase_16"] = "phase_16"
    generated_at: float = Field(ge=0)
    provenance: Phase16Provenance
    pipeline: tuple[Phase16PipelineStage, ...]
    job: Phase16Job | None
    split: Phase16Split | None
    metrics: Phase16Metrics | None
    promotion: Phase16Promotion
    checkpoint: Phase16Checkpoint | None


class SecurityPosture(StrictModel):
    write_authentication: Literal["api_key", "not_configured"]
    authentication_scope: Literal["all_requests", "write_requests", "not_configured"]
    api_key_required: bool
    cors_restricted: bool
    allowed_origins: tuple[str, ...]
    persistent_repository: bool
    configured_workers: int = Field(gt=0)
    ordered_stream_safe: bool


class AlertRecord(StrictModel):
    alert_id: str
    event_id: int
    timestamp: int
    risk: float = Field(ge=0, le=1)
    status: Literal["new", "reviewed", "closed"] = "new"
    evidence: EvidenceBundle
    tactic: TacticVerdict | None = None
    triage: TriageReport | None = None


class AlertStatusUpdate(StrictModel):
    """Bounded analyst workflow transition."""

    status: Literal["new", "reviewed", "closed"]


class GraphNode(StrictModel):
    id: str
    label: str
    kind: Literal["user", "host"]
    risk: float = Field(ge=0, le=1)
    alert_count: int = Field(ge=0)


class GraphEdge(StrictModel):
    id: str
    source: str
    target: str
    relationship: Literal["session", "authentication"]
    risk: float = Field(ge=0, le=1)
    alert_id: str
    timestamp: int = Field(ge=0)
    path_id: str | None = None


class AttackGraph(StrictModel):
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    generated_at: int = Field(ge=0)


class EntityRisk(StrictModel):
    entity: str
    kind: Literal["user", "host"]
    maximum_risk: float = Field(ge=0, le=1)
    alert_count: int = Field(ge=0)


class EntityRiskLeaderboardEntry(StrictModel):
    entity: str
    kind: Literal["user", "host"]
    score: float = Field(ge=0, le=1)
    decayed_risk: float = Field(ge=0, le=1)
    fanout: int = Field(ge=0)
    alert_count: int = Field(ge=0)
    last_seen: int = Field(ge=0)


class EntityRiskLeaderboard(StrictModel):
    generated_at: int = Field(ge=0)
    half_life_seconds: float = Field(gt=0)
    entries: tuple[EntityRiskLeaderboardEntry, ...]


class PropagatedRiskEntry(StrictModel):
    entity: str
    kind: Literal["user", "host"]
    propagated_risk: float = Field(ge=0, le=1)
    seed_risk: float = Field(ge=0, le=1)
    hop_distance: int | None = Field(default=None, ge=0)
    is_seed: bool


class RiskPropagationResult(StrictModel):
    generated_at: int = Field(ge=0)
    seed_count: int = Field(ge=0)
    seed_threshold: float = Field(ge=0, le=1)
    entries: tuple[PropagatedRiskEntry, ...]


class EmbeddingSimilarityMatch(StrictModel):
    entity: str
    kind: Literal["user", "host"]
    similarity: float = Field(ge=-1, le=1)
    magnitude: float = Field(ge=0)


class EmbeddingSimilarityResult(StrictModel):
    generated_at: int = Field(ge=0)
    query_entity: str
    query_kind: Literal["user", "host"]
    matches: tuple[EmbeddingSimilarityMatch, ...]


class KillChainNodeEntry(StrictModel):
    entity: str
    kind: Literal["user", "host"]
    layer: int = Field(ge=0)
    first_seen: int = Field(ge=0)
    max_risk: float = Field(ge=0, le=1)


class KillChainEdgeEntry(StrictModel):
    alert_id: str
    source: str
    source_kind: Literal["user", "host"]
    target: str
    target_kind: Literal["user", "host"]
    timestamp: int = Field(ge=0)
    risk: float = Field(ge=0, le=1)
    on_primary_path: bool


class KillChainResult(StrictModel):
    generated_at: int = Field(ge=0)
    requested_alert_count: int = Field(ge=0)
    resolved_alert_count: int = Field(ge=0)
    nodes: tuple[KillChainNodeEntry, ...]
    edges: tuple[KillChainEdgeEntry, ...]
    primary_path: tuple[str, ...]
    depth: int = Field(ge=0)


class CaseNote(StrictModel):
    timestamp: int = Field(ge=0)
    author: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=4_000)


class CaseRecord(StrictModel):
    case_id: str
    title: str = Field(min_length=1, max_length=200)
    status: Literal["open", "investigating", "closed"] = "open"
    alert_ids: tuple[str, ...]
    created_at: int = Field(ge=0)
    updated_at: int = Field(ge=0)
    closed_reason: str | None = Field(default=None, max_length=2_000)
    notes: tuple[CaseNote, ...] = ()


class CreateCaseRequest(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    alert_ids: tuple[str, ...] = Field(min_length=1)


class CaseStatusUpdate(StrictModel):
    status: Literal["open", "investigating", "closed"]
    closed_reason: str | None = Field(default=None, max_length=2_000)


class CaseNoteRequest(StrictModel):
    author: str = Field(min_length=1, max_length=128)
    text: str = Field(min_length=1, max_length=4_000)


class CaseAlertLinkRequest(StrictModel):
    alert_ids: tuple[str, ...] = Field(min_length=1)


class PlaybookStepEntry(StrictModel):
    action: Literal[
        "isolate_host",
        "reset_credentials",
        "force_reauth",
        "block_network_path",
        "increase_monitoring",
        "notify_soc",
    ]
    status: Literal["executed", "dry_run", "pending_approval", "failed", "skipped_condition_not_met"]
    detail: str


class PlaybookExecutionRecord(StrictModel):
    execution_id: str
    playbook_name: Literal["containment", "investigation", "monitoring"]
    entity: str
    entity_kind: Literal["user", "host"]
    risk_at_trigger: float = Field(ge=0, le=1)
    steps: tuple[PlaybookStepEntry, ...]
    triggered_at: int = Field(ge=0)


class ResponseModeRequest(StrictModel):
    """Switch automatic response between off, dry_run and armed."""

    mode: Literal["off", "dry_run", "armed"]
    actor: str = Field(min_length=1, max_length=128)


class EscalationDecisionRequest(StrictModel):
    """An analyst keeps an automatic lock, or lifts it now."""

    account: str = Field(min_length=1, max_length=128)
    actor: str = Field(min_length=1, max_length=128)


class ResponseUnblockRequest(StrictModel):
    """A person lifts a block applied by an approval or an approval timeout."""

    alert_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    actor: str = Field(min_length=1, max_length=128)


class ResponseApprovalRequest(StrictModel):
    """A person releases one reserved action on one alert."""

    alert_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    approver: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=512)


class RunPlaybookRequest(StrictModel):
    entity: str = Field(min_length=1)
    entity_kind: Literal["user", "host"]
    risk: float = Field(ge=0, le=1)
    #: Actions the caller explicitly approves for this run. Anything the
    #: catalogue reserves for a person and not listed here is left pending.
    approved_actions: tuple[str, ...] = ()
    approver: str = ""


class PlaybookCatalogEntry(StrictModel):
    name: Literal["containment", "investigation", "monitoring"]
    description: str
    steps: tuple[str, ...]


class WebhookConfigResponse(StrictModel):
    url: str | None
    enabled: bool
    format: Literal["slack", "generic"]
    minimum_severity: Literal["low", "medium", "high", "critical"]


class WebhookConfigRequest(StrictModel):
    url: str | None = Field(default=None, max_length=2_000)
    enabled: bool
    format: Literal["slack", "generic"] = "slack"
    minimum_severity: Literal["low", "medium", "high", "critical"] = "high"


class WebhookTestResult(StrictModel):
    success: bool
    status_code: int | None
    error: str | None


class ComplianceAlertEntry(StrictModel):
    alert_id: str
    timestamp: int = Field(ge=0)
    risk: float = Field(ge=0, le=1)
    severity: Literal["low", "medium", "high", "critical"]
    user: str
    source_host: str
    destination_host: str


class ComplianceExportRecord(StrictModel):
    case_id: str
    title: str
    status: Literal["open", "investigating", "closed"]
    created_at: int = Field(ge=0)
    updated_at: int = Field(ge=0)
    closed_reason: str | None
    alerts: tuple[ComplianceAlertEntry, ...]
    unresolved_alert_ids: tuple[str, ...]
    notes: tuple[CaseNote, ...]
    generated_at: int = Field(ge=0)
    disclaimer: str


class DriftReportResponse(StrictModel):
    generated_at: int = Field(ge=0)
    psi: float = Field(ge=0)
    ks_statistic: float = Field(ge=0, le=1)
    severity: Literal["stable", "moderate", "significant"]
    baseline_size: int = Field(ge=0)
    current_size: int = Field(ge=0)
    baseline_mean: float = Field(ge=0, le=1)
    current_mean: float = Field(ge=0, le=1)
    insufficient_data: bool


class ProductOverview(StrictModel):
    scored_events: int = Field(ge=0)
    alerts: int = Field(ge=0)
    paths: int = Field(ge=0)
    alert_rate: float = Field(ge=0)
    open_alerts: int = Field(ge=0)
    critical_alerts: int = Field(ge=0)
    reviewed_alerts: int = Field(ge=0)
    triaged_alerts: int = Field(ge=0)
    mean_risk: float = Field(ge=0, le=1)
    severity_counts: dict[str, int]
    risk_histogram: tuple[int, ...]
    top_entities: tuple[EntityRisk, ...]
    model_loaded: bool
    threshold: float = Field(ge=0, le=1)


class TelemetryCoverage(StrictModel):
    source_id: Literal["auth", "identity", "process", "flow", "dns", "asset"]
    name: str = Field(min_length=1, max_length=80)
    state: Literal["available", "missing"]
    security_value: str = Field(min_length=1, max_length=240)


class TechniqueCoverage(StrictModel):
    tactic_id: str = Field(pattern=r"^TA[0-9]{4}$")
    tactic: str = Field(min_length=1, max_length=80)
    technique_id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    technique: str = Field(min_length=1, max_length=120)
    state: Literal["evidence_backed", "behavioral_signal", "telemetry_gap"]
    observed_alerts: int = Field(ge=0)
    required_telemetry: tuple[str, ...]
    analytic: str = Field(min_length=1, max_length=400)
    limitation: str = Field(min_length=1, max_length=400)


class HuntPlaybook(StrictModel):
    hunt_id: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    title: str = Field(min_length=1, max_length=120)
    hypothesis: str = Field(min_length=1, max_length=320)
    technique_ids: tuple[str, ...]
    priority: Literal["low", "medium", "high"]
    query_logic: str = Field(min_length=1, max_length=400)
    matched_alerts: int = Field(ge=0)
    matched_alert_ids: tuple[str, ...]


class DetectionEngineeringOverview(StrictModel):
    generated_at: int = Field(ge=0)
    scope: Literal["authentication_lateral_movement"]
    evidence_backed_techniques: int = Field(ge=0)
    behavioral_signal_techniques: int = Field(ge=0)
    telemetry_gaps: int = Field(ge=0)
    active_hunt_matches: int = Field(ge=0)
    techniques: tuple[TechniqueCoverage, ...]
    telemetry: tuple[TelemetryCoverage, ...]
    hunts: tuple[HuntPlaybook, ...]


class InvestigationTimelineItem(StrictModel):
    timestamp: int = Field(ge=0)
    alert_id: str
    title: str = Field(min_length=1, max_length=160)
    detail: str = Field(min_length=1, max_length=320)
    risk: float = Field(ge=0, le=1)
    status: Literal["new", "reviewed", "closed"]


class TechniqueAssessment(StrictModel):
    technique_id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    technique: str = Field(min_length=1, max_length=120)
    disposition: Literal["evidence_backed", "hypothesis", "telemetry_gap"]
    rationale: str = Field(min_length=1, max_length=400)
    evidence_ids: tuple[str, ...] = ()


class InvestigationContext(StrictModel):
    alert_id: str
    related_alert_ids: tuple[str, ...]
    first_seen: int = Field(ge=0)
    last_seen: int = Field(ge=0)
    timeline: tuple[InvestigationTimelineItem, ...]
    techniques: tuple[TechniqueAssessment, ...]
    analyst_questions: tuple[str, ...]
    recommended_hunts: tuple[str, ...]
    response_guardrail: str = Field(min_length=1, max_length=400)


class HealthResponse(StrictModel):
    status: Literal["ok"] = "ok"
    version: str
    model_loaded: bool
    #: Named reasons this instance is serving at reduced quality.
    #:
    #: Readiness stays 200 while degraded, deliberately: a first deployment
    #: with no backfill yet is legitimately cold, and failing the probe would
    #: stop it starting at all. But cold state costs 54% of achievable PR-AUC
    #: while ROC-AUC barely moves, so nothing in ordinary monitoring reveals
    #: it. Naming the degradation here is what makes it noticeable.
    degraded: tuple[str, ...] = ()
