"""Application service coordinating fusion, paths, evidence, and triage."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from threading import RLock
from typing import Any, Protocol

from graphsentinel.api.monitoring import OperationalMonitor
from graphsentinel.api.schemas import (
    AlertRecord,
    ScoreBatchRequest,
    ScoreBatchResponse,
    ScoreEventRequest,
    ScoreEventResponse,
)
from graphsentinel.api.store import AlertRepository, AlertStore
from graphsentinel.detection.drift import DriftConfig, DriftReport, compute_drift
from graphsentinel.detection.fusion import (
    CHAIN_RULE_FLOOR,
    DEFAULT_FUSION_CONFIG,
    FusedRisk,
    FusionConfig,
    NoisyOrConfig,
    RiskComponents,
    apply_rule_floor,
    fuse_risk,
)
from graphsentinel.detection.intelligence import interpret_risk
from graphsentinel.detection.path_ranker import (
    PathRanker,
    ScoredAuthEvent,
    StreamingPathTracker,
    SuspiciousPath,
)
from graphsentinel.explain.evidence import build_evidence_bundle
from graphsentinel.explain.soc_report import (
    DeterministicSocReportProvider,
    SocIncidentReport,
    SocReportProvider,
    build_soc_incident_bundle,
)
from graphsentinel.explain.triage import DeterministicTriageProvider, TriageProvider
from graphsentinel.models.serving import InferenceEvent, TGNInferenceSession
from graphsentinel.models.transfer_serving import (
    ALERT_RISK,
    PASS_THROUGH_FUSION,
    TransferInferenceSession,
)

ModelSession = TGNInferenceSession | TransferInferenceSession


class Responder(Protocol):
    """What the service needs from automatic response: one call per batch."""

    def on_alerts(self, alerts: Iterable[AlertRecord]) -> None: ...


class DetectionService:
    def __init__(
        self,
        *,
        threshold: float = 0.75,
        store: AlertRepository | None = None,
        triage_provider: TriageProvider | None = None,
        soc_report_provider: SocReportProvider | None = None,
        model_session: ModelSession | None = None,
        monitor: OperationalMonitor | None = None,
        fusion: FusionConfig | NoisyOrConfig | None = None,
        responder: Responder | None = None,
        chain_rule_floor: float = CHAIN_RULE_FLOOR,
    ) -> None:
        if not 0 <= threshold <= 1:
            raise ValueError("threshold must be in [0, 1]")
        if not 0 <= chain_rule_floor <= 1:
            raise ValueError("chain_rule_floor must be in [0, 1]")
        self.threshold = threshold
        self.store = store or AlertStore()
        #: Automatic response. Called with every alert the batch persisted,
        #: after the batch is committed, so a dispatch can never precede the
        #: alert it responds to. None means alerts are recorded and nothing
        #: is dispatched.
        self.responder = responder
        #: Called with every committed batch of alerts after the responder, so
        #: a notification can name the actions now waiting for approval. A
        #: failing listener is logged and never fails the batch.
        self.alert_listeners: list[Callable[[Sequence[AlertRecord]], None]] = []
        self.triage_provider = triage_provider or DeterministicTriageProvider()
        #: Writes the per-account handover report (``explain/soc_report.py``).
        self.soc_report_provider = soc_report_provider or DeterministicSocReportProvider()
        # Populated on every triage() call; read by the API layer to stamp
        # provenance headers on the response.
        self.last_triage_provenance: dict[str, str | bool] = {}
        #: Same, for the SOC handover report.
        self.last_soc_provenance: dict[str, str | bool] = {}
        self.path_ranker = PathRanker()
        self.path_tracker = StreamingPathTracker(self.path_ranker)
        self._model_session = model_session
        # The fusion operator and the decision threshold are a matched pair:
        # changing one without the other silently changes the alert rate.
        # select_fusion() returns both together for exactly this reason.
        self.fusion = fusion or DEFAULT_FUSION_CONFIG
        #: The fused risk a rule-detected chain is raised to. The alert-only
        #: policy's 0.60 sits below the execution gate; the unattended policy
        #: raises it to the gate (``detection/policy.py``).
        self.chain_rule_floor = chain_rule_floor
        #: Under the corroborated policy the floor applies only to a chain the
        #: model already scored over the alert threshold (set by the live
        #: engine from its policy).
        self.chain_rule_requires_alert = False
        #: The fan-out rule raises a score to the same floor as the chain rule.
        #: On for the label-free transfer model, whose calibration budgets
        #: account for it; off for the first model, whose operating point was
        #: fitted without it.
        self.fanout_rule_enabled = False
        self._scoring_lock = RLock()
        self.monitor = monitor or OperationalMonitor()
        if isinstance(model_session, TransferInferenceSession):
            self._configure_transfer()

    def _configure_transfer(self) -> None:
        """Label-free operation: the calibrated risk passes through; rules floor it."""
        self.fusion = PASS_THROUGH_FUSION
        self.threshold = ALERT_RISK
        self.fanout_rule_enabled = True

    @property
    def model_kind(self) -> str | None:
        if self._model_session is None:
            return None
        return "transfer" if isinstance(self._model_session, TransferInferenceSession) else "tgn"

    @property
    def requires_frozen_dictionary(self) -> bool:
        """Only the first model reads a frozen training dictionary."""
        return self.model_kind == "tgn"

    @property
    def model_session(self) -> ModelSession | None:
        return self._model_session

    @property
    def model_loaded(self) -> bool:
        return self._model_session is not None

    def fusion_profile(self) -> dict[str, object]:
        """Which fusion operator is live, and at what threshold."""
        return {
            "operator": "noisy_or" if isinstance(self.fusion, NoisyOrConfig) else "linear",
            "weights": self.fusion.to_dict(),
            "threshold": self.threshold,
            "chain_rule_floor": self.chain_rule_floor,
            "chain_rule_requires_alert": self.chain_rule_requires_alert,
        }

    def memory_coverage(self) -> dict[str, object] | None:
        """How many entities the loaded model actually has memory for.

        Node memory is cumulative state that starts at zero on every process
        load, so this distinguishes a warm deployment from one that is
        silently scoring every entity as unknown.
        """
        if self._model_session is None:
            return None
        return self._model_session.memory_coverage()

    def save_memory(self, path: Path) -> dict[str, object] | None:
        """Persist the model's node memory; ``None`` when no model is loaded.

        Taken under the scoring lock so the snapshot cannot interleave with a
        batch commit and capture half of one.
        """
        if self._model_session is None:
            return None
        with self._scoring_lock:
            return self._model_session.save_memory(path)

    def model_provenance(self) -> dict[str, object] | None:
        if self._model_session is None:
            return None
        provenance: dict[str, object] = dict(self._model_session.provenance.to_dict())
        return provenance

    def memory_snapshot(self) -> tuple[tuple[float, ...], ...] | None:
        """Current per-node temporal memory, or None if no model is loaded."""

        if self._model_session is None:
            return None
        return self._model_session.memory_snapshot()

    def drift_report(self, *, config: DriftConfig | None = None) -> DriftReport:
        """Compare the earliest vs most recent retained score windows for drift."""

        baseline, current = self.monitor.score_windows()
        return compute_drift(baseline, current, config=config or DriftConfig())

    def install_model(
        self, session: ModelSession, *, threshold: float | None = None
    ) -> None:
        """Atomically replace the model and start a clean temporal generation."""

        if threshold is not None and not 0 <= threshold <= 1:
            raise ValueError("threshold must be in [0, 1]")
        with self._scoring_lock:
            self._model_session = session
            if isinstance(session, TransferInferenceSession):
                self._configure_transfer()
            if threshold is not None:
                self.threshold = threshold
            self.path_tracker.reset()

    @staticmethod
    def _components(request: ScoreEventRequest, *, tgn: float) -> RiskComponents:
        values = request.components.model_dump(exclude={"tgn"})
        return RiskComponents(tgn=tgn, **values)

    @staticmethod
    def _scored_event(request: ScoreEventRequest, risk: float) -> ScoredAuthEvent:
        return ScoredAuthEvent(
            event_id=request.event_id,
            timestamp=request.timestamp,
            user_id=request.user_id,
            source_host_id=request.source_host_id,
            destination_host_id=request.destination_host_id,
            risk=risk,
            is_new_relationship=request.is_new_pair,
            evidence_support=request.evidence_support,
            label_redteam=request.label_redteam,
        )

    def _floored(self, fused: FusedRisk, request: ScoreEventRequest) -> FusedRisk:
        fired = request.chain_detected or (self.fanout_rule_enabled and request.fanout_detected)
        rule = fired and (not self.chain_rule_requires_alert or fused.score >= self.threshold)
        return apply_rule_floor(fused, chain_detected=rule, floor=self.chain_rule_floor)

    def score_batch(self, batch: ScoreBatchRequest) -> ScoreBatchResponse:
        started = time.perf_counter()
        try:
            with self._scoring_lock:
                response = self._score_batch_locked(batch)
        except Exception:
            self.monitor.record_failure(latency_ms=(time.perf_counter() - started) * 1_000)
            raise
        self.monitor.record_success(
            latency_ms=(time.perf_counter() - started) * 1_000,
            scores=[result.risk for result in response.results],
        )
        return response

    def _score_batch_locked(self, batch: ScoreBatchRequest) -> ScoreBatchResponse:
        preview = None
        if self._model_session is None:
            if any(request.components.tgn is None for request in batch.events):
                raise ValueError("no frozen TGN checkpoint is loaded; components.tgn is required")
            external_probabilities: list[float] = []
            for request in batch.events:
                if request.components.tgn is None:
                    raise AssertionError("TGN component validation was bypassed")
                external_probabilities.append(request.components.tgn)
            probabilities = tuple(external_probabilities)
        else:
            if any(request.message is None for request in batch.events):
                raise ValueError("loaded model requires a message vector for every event")
            inference_events = [
                InferenceEvent(
                    event_id=request.event_id,
                    timestamp=request.timestamp,
                    user_id=request.user_id,
                    source_host_id=request.source_host_id,
                    destination_host_id=request.destination_host_id,
                    message=request.message or (),
                    user_name=request.user,
                    source_name=request.source_host,
                    destination_name=request.destination_host,
                )
                for request in batch.events
            ]
            preview = self._model_session.preview(inference_events)
            probabilities = preview.probabilities
        fused = [
            self._floored(
                fuse_risk(self._components(request, tgn=probability), self.fusion), request
            )
            for request, probability in zip(batch.events, probabilities, strict=True)
        ]
        scored = [
            self._scored_event(request, risk.score)
            for request, risk in zip(batch.events, fused, strict=True)
        ]
        path_preview = self.path_tracker.preview(scored)
        paths = list(path_preview.new_paths)
        path_by_event: dict[int, SuspiciousPath] = {}
        for path in paths:
            for event_id in path.event_ids:
                path_by_event.setdefault(event_id, path)
        responses = []
        alerts = []
        for request, risk in zip(batch.events, fused, strict=True):
            alerted = risk.score >= self.threshold
            alert_id = f"GS-{request.event_id:08d}"
            intelligence = interpret_risk(risk)
            if alerted:
                evidence = build_evidence_bundle(
                    alert_id=alert_id,
                    timestamp=request.timestamp,
                    user=request.user,
                    source_host=request.source_host,
                    destination_host=request.destination_host,
                    risk=risk,
                    is_new_pair=request.is_new_pair,
                    user_fanout_5m=request.user_fanout_5m,
                    recent_failures=request.recent_failures,
                    path=path_by_event.get(request.event_id),
                )
                alerts.append(
                    AlertRecord(
                        alert_id=alert_id,
                        event_id=request.event_id,
                        timestamp=request.timestamp,
                        risk=risk.score,
                        evidence=evidence,
                        tactic=request.tactic,
                    )
                )
            responses.append(
                ScoreEventResponse(
                    alert_id=alert_id,
                    event_id=request.event_id,
                    risk=risk.score,
                    alerted=alerted,
                    threshold=self.threshold,
                    severity=intelligence.severity,
                    confidence=intelligence.confidence,
                    uncertainty=intelligence.uncertainty,
                    dominant_signals=intelligence.dominant_signals,
                    tactic=request.tactic,
                    components=risk.components.to_dict(),
                    rule_floor=risk.rule_floor,
                )
            )
        self.store.commit_detection_batch(
            scored_count=len(batch.events), alerts=alerts, paths=paths
        )
        if preview is not None and self._model_session is not None:
            self._model_session.commit(preview)
        self.path_tracker.commit(path_preview)
        if self.responder is not None and alerts:
            self.responder.on_alerts(alerts)
        if alerts:
            for listener in self.alert_listeners:
                try:
                    listener(alerts)
                except Exception:  # noqa: BLE001 - notification must never fail detection
                    logging.getLogger("graphsentinel.alerts").exception("alert listener failed")
        return ScoreBatchResponse(results=tuple(responses), paths_created=len(paths))

    def score_event(self, request: ScoreEventRequest) -> ScoreEventResponse:
        return self.score_batch(ScoreBatchRequest(events=(request,))).results[0]

    # ---------------------------------------------------------------- SOC
    def _alerts_for_account(self, account: str, *, limit: int = 1_000) -> list[AlertRecord]:
        return [
            alert
            for alert in self.store.list_alerts(limit=limit)
            if alert.evidence.event.user == account
        ]

    def soc_incidents(self, *, limit: int = 20, scan: int = 1_000) -> list[dict[str, object]]:
        """Accounts worth a handover report, worst first.

        An incident here is an account, not a time window: the prevention
        loop, the budget and the analyst's decisions are all per account, so
        that is the unit a report has to cover to be actionable.
        """
        grouped: dict[str, list[AlertRecord]] = {}
        for alert in self.store.list_alerts(limit=scan):
            grouped.setdefault(alert.evidence.event.user, []).append(alert)
        escalations = self._escalations_by_account()
        records = self._executions_by_account(grouped)
        incidents: list[dict[str, object]] = []
        for account, alerts in grouped.items():
            highest = max(a.risk for a in alerts)
            acted = [
                r
                for r in records.get(account, [])
                if r.action not in {"notify_soc", "increase_monitoring"}
            ]
            incidents.append(
                {
                    "account": account,
                    "alerts": len(alerts),
                    "highest_risk": highest,
                    "first_seen": min(a.timestamp for a in alerts),
                    "last_seen": max(a.timestamp for a in alerts),
                    "hosts": len(
                        {a.evidence.event.destination_host for a in alerts}
                        | {a.evidence.event.source_host for a in alerts}
                    ),
                    "actions": len(acted),
                    "pending": sum(1 for r in acted if r.outcome == "pending_approval"),
                    "escalated": account in escalations,
                }
            )
        def rank(incident: dict[str, object]) -> tuple[bool, float, int]:
            return (
                bool(incident["escalated"]),
                float(str(incident["highest_risk"])),
                int(str(incident["alerts"])),
            )

        incidents.sort(key=rank, reverse=True)
        return incidents[:limit]

    def _escalations_by_account(self) -> dict[str, object]:
        tracker = getattr(self.responder, "incidents", None)
        active = getattr(tracker, "active", None)
        if not callable(active):
            return {}
        return {state.account: state for state in active()}

    def _executions_by_account(
        self, grouped: dict[str, list[AlertRecord]]
    ) -> dict[str, list[Any]]:
        executions = getattr(self.responder, "executions", None)
        if not callable(executions):
            return {}
        owner = {
            alert.alert_id: account for account, alerts in grouped.items() for alert in alerts
        }
        by_account: dict[str, list[Any]] = {}
        for record in executions(limit=5_000):
            account = owner.get(record.alert_id)
            if account is not None:
                by_account.setdefault(account, []).append(record)
        return by_account

    def soc_report(self, account: str) -> SocIncidentReport:
        """Write (or re-write) the handover report for one account."""
        alerts = self._alerts_for_account(account)
        if not alerts:
            raise KeyError(account)
        grouped = {account: alerts}
        bundle = build_soc_incident_bundle(
            account,
            alerts,
            self._executions_by_account(grouped).get(account, []),
            escalation=self._escalations_by_account().get(account),
            approval_window=getattr(self.responder, "approval_window", None),
        )
        provider = self.soc_report_provider
        report = provider.generate(bundle)
        self.last_soc_provenance = {
            "provider": str(getattr(provider, "name", type(provider).__name__)),
            "version": str(getattr(provider, "version", "?")),
            "fallback": bool(getattr(provider, "used_fallback", False)),
            "trace": "|".join(getattr(provider, "last_trace", []) or []) or "-",
        }
        logging.getLogger("graphsentinel.triage").info(
            "soc-report account=%s alerts=%d provider=%s fallback=%s facts=%d",
            account,
            len(alerts),
            self.last_soc_provenance["provider"],
            self.last_soc_provenance["fallback"],
            len(bundle.facts),
        )
        return report

    def triage(self, alert_id: str) -> AlertRecord:
        alert = self.store.get_alert(alert_id)
        if alert is None:
            raise KeyError(alert_id)
        report = self.triage_provider.generate(alert.evidence)
        # Record which engine actually authored this narrative. An analyst
        # acting on a report needs to know whether they are reading a
        # deterministic template or model-generated prose that fell back --
        # and an audit of a security decision needs it even more. Logged
        # rather than added to the response schema so the strict, frozen
        # TriageReport contract (and everything asserting against it) is
        # unaffected.
        provider = self.triage_provider
        # Also exposed to the caller (see the X-Triage-* headers on the triage
        # endpoints) so the console can label the report's origin rather than
        # presenting model prose and a deterministic template identically.
        self.last_triage_provenance = {
            "provider": str(getattr(provider, "name", type(provider).__name__)),
            "version": str(getattr(provider, "version", "?")),
            "fallback": bool(getattr(provider, "used_fallback", False)),
            "trace": "|".join(getattr(provider, "last_trace", []) or []) or "-",
        }
        logging.getLogger("graphsentinel.triage").info(
            "triage alert_id=%s provider=%s version=%s fallback=%s trace=%s",
            alert_id,
            getattr(provider, "name", type(provider).__name__),
            getattr(provider, "version", "?"),
            getattr(provider, "used_fallback", False),
            "|".join(getattr(provider, "last_trace", []) or []) or "-",
        )
        return self.store.attach_triage(alert_id, report)
