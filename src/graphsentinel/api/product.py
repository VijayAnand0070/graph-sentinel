"""Product-level projections for the analyst console."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from graphsentinel.api.schemas import (
    AlertRecord,
    AttackGraph,
    CaseRecord,
    ComplianceAlertEntry,
    ComplianceExportRecord,
    DetectionEngineeringOverview,
    DriftReportResponse,
    EmbeddingSimilarityMatch,
    EmbeddingSimilarityResult,
    EntityRisk,
    EntityRiskLeaderboard,
    EntityRiskLeaderboardEntry,
    GraphEdge,
    GraphNode,
    HuntPlaybook,
    InvestigationContext,
    InvestigationTimelineItem,
    KillChainEdgeEntry,
    KillChainNodeEntry,
    KillChainResult,
    ProductOverview,
    PropagatedRiskEntry,
    RiskPropagationResult,
    TechniqueAssessment,
    TechniqueCoverage,
    TelemetryCoverage,
)
from graphsentinel.api.live import LiveDetectionEngine
from graphsentinel.api.service import DetectionService
from graphsentinel.api.store import AlertRepository, CaseStore, SQLiteCaseStore
from graphsentinel.detection.embedding_search import (
    EntityEmbedding,
    find_similar_entities,
)
from graphsentinel.detection.entity_risk import (
    AlertSignal,
    EntityRiskConfig,
    compute_entity_risk_scores,
)
from graphsentinel.detection.kill_chain import ChainHop, reconstruct_kill_chain
from graphsentinel.detection.risk_propagation import (
    PropagationConfig,
    PropagationEdge,
    SeedRisk,
    propagate_risk,
)
from graphsentinel.ingestion.id_map import UNKNOWN_TOKEN
from graphsentinel.integrations.alert_summary import severity_from_risk


@dataclass(slots=True)
class _MutableNode:
    label: str
    kind: Literal["user", "host"]
    risk: float
    count: int


def severity_for(risk: float) -> str:
    """Severity bands, matching the contract published at /api/v1/threshold-config.

    These cut points must stay identical in three places: this function (which
    produces the overview KPI counts), the ``bands`` block the API publishes,
    and ``alert_summary.severity_from_risk``. They had drifted -- this function
    used 0.90/0.75 while the other two used 0.85/0.70 -- so the console painted
    an alert red at 0.72 while the KPI tile counted it as medium, and a run
    with two alerts above 0.85 still reported "critical: 0".
    """
    if risk >= 0.85:
        return "critical"
    if risk >= 0.70:
        return "high"
    if risk >= 0.50:
        return "medium"
    return "low"


def build_overview(
    store: AlertRepository, *, model_loaded: bool, threshold: float
) -> ProductOverview:
    metrics = store.metrics()
    alerts = store.list_alerts(limit=1_000)
    severity_counts = {name: 0 for name in ("critical", "high", "medium", "low")}
    histogram = [0, 0, 0, 0, 0]
    entities: dict[tuple[str, Literal["user", "host"]], list[float]] = defaultdict(list)
    for alert in alerts:
        severity_counts[severity_for(alert.risk)] += 1
        histogram[min(int(alert.risk * 5), 4)] += 1
        event = alert.evidence.event
        entities[(event.user, "user")].append(alert.risk)
        entities[(event.source_host, "host")].append(alert.risk)
        entities[(event.destination_host, "host")].append(alert.risk)
    top_entities = sorted(
        (
            EntityRisk(
                entity=entity,
                kind=kind,
                maximum_risk=max(risks),
                alert_count=len(risks),
            )
            for (entity, kind), risks in entities.items()
        ),
        key=lambda item: (-item.maximum_risk, -item.alert_count, item.entity),
    )[:8]
    return ProductOverview(
        scored_events=int(metrics["scored_events"]),
        alerts=int(metrics["alerts"]),
        paths=int(metrics["paths"]),
        alert_rate=float(metrics["alert_rate"]),
        open_alerts=sum(alert.status != "closed" for alert in alerts),
        critical_alerts=severity_counts["critical"],
        reviewed_alerts=sum(alert.status == "reviewed" for alert in alerts),
        triaged_alerts=sum(alert.triage is not None for alert in alerts),
        mean_risk=sum(alert.risk for alert in alerts) / len(alerts) if alerts else 0,
        severity_counts=severity_counts,
        risk_histogram=tuple(histogram),
        top_entities=tuple(top_entities),
        model_loaded=model_loaded,
        threshold=threshold,
    )


def build_entity_risk_leaderboard(
    store: AlertRepository,
    *,
    limit: int = 1_000,
    config: EntityRiskConfig | None = None,
) -> EntityRiskLeaderboard:
    """Project persisted alerts into the entity-risk module's composite ranking."""

    alerts = store.list_alerts(limit=limit)
    resolved_config = config or EntityRiskConfig()
    signals = tuple(
        AlertSignal(
            timestamp=alert.timestamp,
            risk=alert.risk,
            user=alert.evidence.event.user,
            source_host=alert.evidence.event.source_host,
            destination_host=alert.evidence.event.destination_host,
        )
        for alert in alerts
    )
    # Decay must be measured in the SAME clock as the signal timestamps.
    # Alert timestamps come from the event stream, which is dataset-relative
    # (LANL counts seconds from the start of the capture, so a recent event is
    # ~2.6e6), while time.time() is a Unix epoch (~1.79e9). Mixing them made
    # every entity look ~495,000 half-lives old, so decayed_risk collapsed to
    # 0.0 for every row and the leaderboard's decay ranking was inert -- and
    # the console rendered "last seen 47919d ago".
    #
    # The stream's own latest observed timestamp is the meaningful "now": it
    # keeps decay correct whether the source is live telemetry (timestamps
    # track wall-clock anyway) or a replayed historical dataset.
    now = max((signal.timestamp for signal in signals), default=int(time.time()))
    scores = compute_entity_risk_scores(signals, now=now, config=resolved_config)
    return EntityRiskLeaderboard(
        # Reported in the same clock as last_seen so the console can render a
        # correct age as (generated_at - last_seen).
        generated_at=now,
        half_life_seconds=resolved_config.half_life_seconds,
        entries=tuple(
            EntityRiskLeaderboardEntry(
                entity=score.entity,
                kind=score.kind,
                score=score.score,
                decayed_risk=score.decayed_risk,
                fanout=score.fanout,
                alert_count=score.alert_count,
                last_seen=score.last_seen,
            )
            for score in scores
        ),
    )


def build_risk_propagation(
    store: AlertRepository,
    *,
    limit: int = 1_000,
    seed_threshold: float = 0.85,
    config: PropagationConfig | None = None,
) -> RiskPropagationResult:
    """Diffuse risk outward from confirmed high-risk entities across the auth graph.

    Seeds are entities whose highest observed alert risk clears
    ``seed_threshold`` — a "confirmed" bar, deliberately higher than the
    detection threshold used for alerting itself, since seeds inject risk
    into neighbors that have no alert of their own yet.
    """

    alerts = store.list_alerts(limit=limit)
    resolved_config = config or PropagationConfig()

    edges: list[PropagationEdge] = []
    max_risk: dict[tuple[str, Literal["user", "host"]], float] = {}

    for alert in alerts:
        event = alert.evidence.event
        edges.append(
            PropagationEdge(
                source=event.user,
                source_kind="user",
                destination=event.source_host,
                destination_kind="host",
            )
        )
        edges.append(
            PropagationEdge(
                source=event.source_host,
                source_kind="host",
                destination=event.destination_host,
                destination_kind="host",
            )
        )
        for key in (
            (event.user, "user"),
            (event.source_host, "host"),
            (event.destination_host, "host"),
        ):
            max_risk[key] = max(max_risk.get(key, 0.0), alert.risk)

    seeds = [
        SeedRisk(entity=entity, kind=kind, risk=risk)
        for (entity, kind), risk in max_risk.items()
        if risk >= seed_threshold
    ]

    scores = propagate_risk(edges, seeds, config=resolved_config)
    entries = [
        PropagatedRiskEntry(
            entity=s.entity,
            kind=s.kind,
            # A seed's own confirmed risk is authoritative; diffusion mass is
            # a measure of graph concentration, not total knowledge, so it
            # must never make a confirmed entity look less risky than it
            # actually is.
            propagated_risk=max(s.propagated_risk, s.seed_risk),
            seed_risk=s.seed_risk,
            hop_distance=s.hop_distance,
            is_seed=s.is_seed,
        )
        for s in scores
    ]
    entries.sort(key=lambda e: (-e.propagated_risk, e.entity))
    return RiskPropagationResult(
        generated_at=int(time.time()),
        seed_count=len(seeds),
        seed_threshold=seed_threshold,
        entries=tuple(entries),
    )


def build_embedding_similarity(
    detection: DetectionService,
    live: LiveDetectionEngine,
    *,
    query_entity: str,
    query_kind: Literal["user", "host"],
    top_k: int = 10,
) -> EmbeddingSimilarityResult:
    """Rank entities by cosine similarity to ``query_entity`` in TGN embedding space.

    Raises ``ValueError`` for both "no model loaded" and "unknown entity" —
    distinct, route-level concerns the caller maps to the appropriate HTTP
    status rather than this module taking a FastAPI dependency.
    """

    memory = detection.memory_snapshot()
    if memory is None:
        raise ValueError("no frozen model checkpoint loaded")

    provenance = detection.model_provenance() or {}
    user_capacity = int(provenance.get("user_capacity", 0))  # type: ignore[arg-type]

    names = live.entity_names()
    embeddings: list[EntityEmbedding] = []
    for local_id, name in enumerate(names["users"]):
        if name == UNKNOWN_TOKEN or local_id >= user_capacity or local_id >= len(memory):
            continue
        embeddings.append(EntityEmbedding(entity=name, kind="user", vector=memory[local_id]))
    for local_id, name in enumerate(names["hosts"]):
        global_id = user_capacity + local_id
        if name == UNKNOWN_TOKEN or global_id >= len(memory):
            continue
        embeddings.append(EntityEmbedding(entity=name, kind="host", vector=memory[global_id]))

    query = next(
        (e for e in embeddings if e.entity == query_entity and e.kind == query_kind), None
    )
    if query is None:
        raise ValueError(f"unknown {query_kind} entity: {query_entity!r}")

    matches = find_similar_entities(query, embeddings, top_k=top_k)
    return EmbeddingSimilarityResult(
        generated_at=int(time.time()),
        query_entity=query_entity,
        query_kind=query_kind,
        matches=tuple(
            EmbeddingSimilarityMatch(
                entity=m.entity, kind=m.kind, similarity=m.similarity, magnitude=m.magnitude
            )
            for m in matches
        ),
    )


def build_kill_chain(store: AlertRepository, alert_ids: Sequence[str]) -> KillChainResult:
    """Reconstruct a layered kill-chain DAG from a caller-selected set of alerts.

    Each alert contributes two hops — user reaching its source host, then
    that host authenticating onward — mirroring ``build_attack_graph``'s edge
    model, so an alert missing from the store (already closed, purged, or a
    stale client-side ID) is silently skipped rather than failing the whole
    reconstruction.
    """

    hops: list[ChainHop] = []
    resolved = 0
    for alert_id in dict.fromkeys(alert_ids):  # de-duplicate, preserve order
        alert = store.get_alert(alert_id)
        if alert is None:
            continue
        resolved += 1
        event = alert.evidence.event
        hops.append(
            ChainHop(
                alert_id=f"session:{alert.alert_id}",
                timestamp=alert.timestamp,
                actor=event.user,
                actor_kind="user",
                target=event.source_host,
                target_kind="host",
                risk=alert.risk,
            )
        )
        hops.append(
            ChainHop(
                alert_id=f"auth:{alert.alert_id}",
                timestamp=alert.timestamp,
                actor=event.source_host,
                actor_kind="host",
                target=event.destination_host,
                target_kind="host",
                risk=alert.risk,
            )
        )

    graph = reconstruct_kill_chain(hops)
    return KillChainResult(
        generated_at=int(time.time()),
        requested_alert_count=len(set(alert_ids)),
        resolved_alert_count=resolved,
        nodes=tuple(
            KillChainNodeEntry(
                entity=n.entity, kind=n.kind, layer=n.layer,
                first_seen=n.first_seen, max_risk=n.max_risk,
            )
            for n in graph.nodes
        ),
        edges=tuple(
            KillChainEdgeEntry(
                alert_id=e.alert_id, source=e.source, source_kind=e.source_kind,
                target=e.target, target_kind=e.target_kind, timestamp=e.timestamp,
                risk=e.risk, on_primary_path=e.on_primary_path,
            )
            for e in graph.edges
        ),
        primary_path=graph.primary_path,
        depth=graph.depth,
    )


def build_drift_report(detection: DetectionService) -> DriftReportResponse:
    report = detection.drift_report()
    return DriftReportResponse(
        generated_at=int(time.time()),
        psi=report.psi,
        ks_statistic=report.ks_statistic,
        severity=report.severity,
        baseline_size=report.baseline_size,
        current_size=report.current_size,
        baseline_mean=report.baseline_mean,
        current_mean=report.current_mean,
        insufficient_data=report.insufficient_data,
    )


_COMPLIANCE_DISCLAIMER = (
    "This record was compiled automatically from persisted alert and case data "
    "for investigation and compliance handoff. Risk scores and technique mappings "
    "are model-generated and require human review before being relied upon as a "
    "sole basis for legal or disciplinary action."
)


def build_compliance_export(
    case_store: CaseStore | SQLiteCaseStore,
    alert_store: AlertRepository,
    case_id: str,
) -> ComplianceExportRecord:
    """Bundle a case's full record — linked alerts, notes, status history context —
    into a single exportable, attestable document for legal/compliance handoff.

    Raises ``KeyError`` for an unknown case, a route-level concern the caller
    maps to a 404 rather than this module taking a FastAPI dependency.
    """

    case: CaseRecord | None = case_store.get_case(case_id)
    if case is None:
        raise KeyError(case_id)

    resolved: list[ComplianceAlertEntry] = []
    unresolved: list[str] = []
    for alert_id in case.alert_ids:
        alert = alert_store.get_alert(alert_id)
        if alert is None:
            unresolved.append(alert_id)
            continue
        event = alert.evidence.event
        resolved.append(
            ComplianceAlertEntry(
                alert_id=alert.alert_id,
                timestamp=alert.timestamp,
                risk=alert.risk,
                severity=severity_from_risk(alert.risk),
                user=event.user,
                source_host=event.source_host,
                destination_host=event.destination_host,
            )
        )

    return ComplianceExportRecord(
        case_id=case.case_id,
        title=case.title,
        status=case.status,
        created_at=case.created_at,
        updated_at=case.updated_at,
        closed_reason=case.closed_reason,
        alerts=tuple(resolved),
        unresolved_alert_ids=tuple(unresolved),
        notes=case.notes,
        generated_at=int(time.time()),
        disclaimer=_COMPLIANCE_DISCLAIMER,
    )


def build_attack_graph(alerts: tuple[AlertRecord, ...]) -> AttackGraph:
    node_values: dict[str, _MutableNode] = {}
    edges: list[GraphEdge] = []

    def add_node(identifier: str, label: str, kind: Literal["user", "host"], risk: float) -> None:
        current = node_values.get(identifier)
        if current is None:
            node_values[identifier] = _MutableNode(label, kind, risk, 1)
            return
        current.risk = max(current.risk, risk)
        current.count += 1

    for alert in alerts:
        event = alert.evidence.event
        user_id = f"user:{event.user}"
        source_id = f"host:{event.source_host}"
        destination_id = f"host:{event.destination_host}"
        add_node(user_id, event.user, "user", alert.risk)
        add_node(source_id, event.source_host, "host", alert.risk)
        add_node(destination_id, event.destination_host, "host", alert.risk)
        edges.append(
            GraphEdge(
                id=f"session:{alert.alert_id}",
                source=user_id,
                target=source_id,
                relationship="session",
                risk=alert.risk,
                alert_id=alert.alert_id,
                timestamp=alert.timestamp,
                path_id=alert.evidence.path_id,
            )
        )
        edges.append(
            GraphEdge(
                id=f"auth:{alert.alert_id}",
                source=source_id,
                target=destination_id,
                relationship="authentication",
                risk=alert.risk,
                alert_id=alert.alert_id,
                timestamp=alert.timestamp,
                path_id=alert.evidence.path_id,
            )
        )
    nodes = tuple(
        GraphNode(
            id=identifier,
            label=value.label,
            kind=value.kind,
            risk=value.risk,
            alert_count=value.count,
        )
        for identifier, value in sorted(node_values.items())
    )
    return AttackGraph(nodes=nodes, edges=tuple(edges), generated_at=int(time.time()))


def _evidence_value(alert: AlertRecord, evidence_id: str) -> object | None:
    item = next((item for item in alert.evidence.evidence if item.evidence_id == evidence_id), None)
    return item.value if item is not None else None


def _integer_evidence(alert: AlertRecord, evidence_id: str) -> int:
    value = _evidence_value(alert, evidence_id)
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _hunt(
    *,
    hunt_id: str,
    title: str,
    hypothesis: str,
    technique_ids: tuple[str, ...],
    priority: Literal["low", "medium", "high"],
    query_logic: str,
    alerts: tuple[AlertRecord, ...],
) -> HuntPlaybook:
    return HuntPlaybook(
        hunt_id=hunt_id,
        title=title,
        hypothesis=hypothesis,
        technique_ids=technique_ids,
        priority=priority,
        query_logic=query_logic,
        matched_alerts=len(alerts),
        matched_alert_ids=tuple(alert.alert_id for alert in alerts[:250]),
    )


def build_detection_engineering(store: AlertRepository) -> DetectionEngineeringOverview:
    """Project honest ATT&CK coverage, telemetry gaps, and executable hunt hypotheses."""

    alerts = store.list_alerts(limit=1_000)
    new_relationships = tuple(alert for alert in alerts if _evidence_value(alert, "E-002") is True)
    recent_failures = tuple(alert for alert in alerts if _integer_evidence(alert, "E-004") > 0)
    fanout = tuple(alert for alert in alerts if _integer_evidence(alert, "E-003") >= 3)
    pivots = tuple(alert for alert in alerts if alert.evidence.path_id is not None)
    multi_signal = tuple(
        alert
        for alert in alerts
        if sum(
            value >= 0.6
            for name, value in alert.evidence.scores.model_dump().items()
            if name != "fused"
        )
        >= 3
    )
    techniques = (
        TechniqueCoverage(
            tactic_id="TA0008",
            tactic="Lateral Movement",
            technique_id="T1021",
            technique="Remote Services",
            state="evidence_backed",
            observed_alerts=len(alerts),
            required_telemetry=("Authentication",),
            analytic=(
                "Temporal user-to-host authentication anomaly with novelty, burst, pivot, "
                "corroboration, and time-respecting graph paths."
            ),
            limitation=(
                "Authentication alone does not establish the RDP, SMB, SSH, WinRM, or cloud "
                "remote-service sub-technique."
            ),
        ),
        TechniqueCoverage(
            tactic_id="TA0001",
            tactic="Initial Access",
            technique_id="T1078",
            technique="Valid Accounts",
            state="behavioral_signal",
            observed_alerts=len(new_relationships),
            required_telemetry=("Authentication", "Identity context"),
            analytic="New or rare identity-to-destination relationships and unusual fan-out.",
            limitation=(
                "Signals are hypotheses until identity privilege, device, geography, MFA, and "
                "session context corroborate account abuse."
            ),
        ),
        TechniqueCoverage(
            tactic_id="TA0006",
            tactic="Credential Access",
            technique_id="T1110",
            technique="Brute Force",
            state="behavioral_signal",
            observed_alerts=len(recent_failures),
            required_telemetry=("Authentication",),
            analytic="Prior authentication failures, burst rate, and subsequent remote activity.",
            limitation=(
                "The current user-centric feature contract does not prove password spraying "
                "across a broad account population."
            ),
        ),
        TechniqueCoverage(
            tactic_id="TA0008",
            tactic="Lateral Movement",
            technique_id="T1550",
            technique="Use Alternate Authentication Material",
            state="telemetry_gap",
            observed_alerts=0,
            required_telemetry=("Kerberos ticket or token telemetry", "Process"),
            analytic=(
                "Not implemented; no ticket, token, or credential-material fields are ingested."
            ),
            limitation=(
                "Pass-the-hash and pass-the-ticket cannot be concluded from generic auth metadata."
            ),
        ),
        TechniqueCoverage(
            tactic_id="TA0008",
            tactic="Lateral Movement",
            technique_id="T1210",
            technique="Exploitation of Remote Services",
            state="telemetry_gap",
            observed_alerts=0,
            required_telemetry=("Network flow", "Vulnerability context", "Process"),
            analytic="Not implemented; authentication does not observe exploitation behavior.",
            limitation="Requires network, vulnerability, and endpoint execution correlation.",
        ),
        TechniqueCoverage(
            tactic_id="TA0008",
            tactic="Lateral Movement",
            technique_id="T1563",
            technique="Remote Service Session Hijacking",
            state="telemetry_gap",
            observed_alerts=0,
            required_telemetry=("Session lifecycle", "Process", "Endpoint"),
            analytic=(
                "Not implemented; session takeover indicators are outside the auth-only schema."
            ),
            limitation=(
                "Requires session and endpoint telemetry to distinguish hijacking from login."
            ),
        ),
    )
    hunts = (
        _hunt(
            hunt_id="new-remote-relationship",
            title="First-seen remote relationships",
            hypothesis=(
                "A compromised identity is reaching hosts absent from its prior graph history."
            ),
            technique_ids=("T1078", "T1021"),
            priority="high",
            query_logic=(
                "is_new_pair = true; review identity, source, destination, and peer history."
            ),
            alerts=new_relationships,
        ),
        _hunt(
            hunt_id="failures-before-remote-activity",
            title="Failures before remote activity",
            hypothesis="Credential guessing or misuse preceded suspicious authentication activity.",
            technique_ids=("T1110", "T1078"),
            priority="high",
            query_logic="failures_before_success_15m > 0 and fused risk exceeded threshold.",
            alerts=recent_failures,
        ),
        _hunt(
            hunt_id="rapid-host-fanout",
            title="Rapid destination fan-out",
            hypothesis="One identity is enumerating or laterally accessing several hosts.",
            technique_ids=("T1021",),
            priority="medium",
            query_logic="user_unique_dst_5m >= 3; validate administrative change windows.",
            alerts=fanout,
        ),
        _hunt(
            hunt_id="time-respecting-pivots",
            title="Time-respecting pivot chains",
            hypothesis="A reached destination became the source of subsequent remote movement.",
            technique_ids=("T1021",),
            priority="high",
            query_logic="path_id exists; inspect strictly increasing, cycle-free host sequence.",
            alerts=pivots,
        ),
        _hunt(
            hunt_id="multi-signal-consensus",
            title="Multi-signal consensus",
            hypothesis="Several independent graph and behavioral channels agree on elevated risk.",
            technique_ids=("T1021", "T1078"),
            priority="medium",
            query_logic="At least three non-fused risk components are >= 0.60.",
            alerts=multi_signal,
        ),
    )
    return DetectionEngineeringOverview(
        generated_at=int(time.time()),
        scope="authentication_lateral_movement",
        evidence_backed_techniques=sum(
            technique.state == "evidence_backed" for technique in techniques
        ),
        behavioral_signal_techniques=sum(
            technique.state == "behavioral_signal" for technique in techniques
        ),
        telemetry_gaps=sum(technique.state == "telemetry_gap" for technique in techniques),
        active_hunt_matches=len(
            {alert_id for hunt in hunts for alert_id in hunt.matched_alert_ids}
        ),
        techniques=techniques,
        telemetry=(
            TelemetryCoverage(
                source_id="auth",
                name="Authentication",
                state="available",
                security_value=(
                    "Identity, source, destination, outcome, protocol, and temporal behavior."
                ),
            ),
            TelemetryCoverage(
                source_id="identity",
                name="Identity and privilege context",
                state="missing",
                security_value=(
                    "Privilege, role, peer group, MFA, service-account, and account lifecycle."
                ),
            ),
            TelemetryCoverage(
                source_id="process",
                name="Endpoint process",
                state="missing",
                security_value=(
                    "Post-login commands, remote tooling, credential access, and execution."
                ),
            ),
            TelemetryCoverage(
                source_id="flow",
                name="Network flow",
                state="missing",
                security_value=(
                    "Remote-service ports, scanning, exploitation, and east-west movement."
                ),
            ),
            TelemetryCoverage(
                source_id="dns",
                name="DNS",
                state="missing",
                security_value=(
                    "Resolution context, infrastructure pivots, and command-and-control clues."
                ),
            ),
            TelemetryCoverage(
                source_id="asset",
                name="Asset and vulnerability",
                state="missing",
                security_value=(
                    "Criticality, ownership, exposure, vulnerabilities, and remediation priority."
                ),
            ),
        ),
        hunts=hunts,
    )


def build_investigation_context(store: AlertRepository, alert_id: str) -> InvestigationContext:
    target = store.get_alert(alert_id)
    if target is None:
        raise KeyError(alert_id)
    event = target.evidence.event
    target_entities = {
        ("user", event.user),
        ("host", event.source_host),
        ("host", event.destination_host),
    }
    related = tuple(
        alert
        for alert in store.list_alerts(limit=1_000)
        if target_entities
        & {
            ("user", alert.evidence.event.user),
            ("host", alert.evidence.event.source_host),
            ("host", alert.evidence.event.destination_host),
        }
    )
    chronological = tuple(sorted(related, key=lambda alert: (alert.timestamp, alert.alert_id)))
    techniques: list[TechniqueAssessment] = [
        TechniqueAssessment(
            technique_id="T1021",
            technique="Remote Services",
            disposition="evidence_backed",
            rationale=target.evidence.attack_mapping.limitation,
            evidence_ids=target.evidence.attack_mapping.justification_evidence_ids,
        )
    ]
    if _evidence_value(target, "E-002") is True:
        techniques.append(
            TechniqueAssessment(
                technique_id="T1078",
                technique="Valid Accounts",
                disposition="hypothesis",
                rationale=(
                    "The relationship was first-seen, which supports an account-abuse hunt but "
                    "does not prove credential compromise."
                ),
                evidence_ids=("E-002",),
            )
        )
    failure_count = _integer_evidence(target, "E-004")
    if failure_count > 0:
        techniques.append(
            TechniqueAssessment(
                technique_id="T1110",
                technique="Brute Force",
                disposition="hypothesis",
                rationale=(
                    f"{failure_count} prior failures support credential-guessing investigation; "
                    "confirm across the wider account population."
                ),
                evidence_ids=("E-004",),
            )
        )
    techniques.append(
        TechniqueAssessment(
            technique_id="T1550",
            technique="Use Alternate Authentication Material",
            disposition="telemetry_gap",
            rationale=(
                "No hashes, Kerberos tickets, tokens, or endpoint process telemetry are ingested."
            ),
        )
    )
    return InvestigationContext(
        alert_id=alert_id,
        related_alert_ids=tuple(
            alert.alert_id for alert in chronological if alert.alert_id != alert_id
        ),
        first_seen=chronological[0].timestamp,
        last_seen=chronological[-1].timestamp,
        timeline=tuple(
            InvestigationTimelineItem(
                timestamp=alert.timestamp,
                alert_id=alert.alert_id,
                title=(
                    f"{alert.evidence.event.source_host} → {alert.evidence.event.destination_host}"
                ),
                detail=(
                    f"{alert.evidence.event.user} · fused risk {alert.risk:.3f} · {alert.status}"
                ),
                risk=alert.risk,
                status=alert.status,
            )
            for alert in chronological[-20:]
        ),
        techniques=tuple(techniques),
        analyst_questions=(
            "Is this identity authorized to access the destination from this source host?",
            "Does the activity align with a maintenance window or an administrative tool?",
            "What endpoint process, parent process, and command followed the remote login?",
            "Did the identity exhibit MFA anomalies, privilege changes, or peer-group deviation?",
            "Did the destination initiate later connections that expand the blast radius?",
        ),
        recommended_hunts=(
            f"Search all recent activity for identity {event.user}.",
            f"Pivot on source host {event.source_host} for destination fan-out.",
            f"Review inbound and outbound activity for {event.destination_host}.",
            "Correlate endpoint process creation and network flow before containment.",
        ),
        response_guardrail=(
            "GraphSentinel provides investigation guidance only. Validate identity, endpoint, "
            "asset criticality, and business context before any containment action."
        ),
    )
