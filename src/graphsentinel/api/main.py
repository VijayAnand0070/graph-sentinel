"""FastAPI application factory for GraphSentinel."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import threading
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi import Request as FastAPIRequest
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from graphsentinel import __version__
from graphsentinel.api.audit import actor_fingerprint, default_audit_log
from graphsentinel.api.live import LiveDetectionEngine
from graphsentinel.api.phase16 import Phase16Manager
from graphsentinel.api.pipeline_lease import PipelineBusyError, PipelineLease
from graphsentinel.api.product import (
    severity_for,
    build_attack_graph,
    build_compliance_export,
    build_detection_engineering,
    build_drift_report,
    build_embedding_similarity,
    build_entity_risk_leaderboard,
    build_investigation_context,
    build_kill_chain,
    build_overview,
    build_risk_propagation,
)
from graphsentinel.api.schemas import (
    AlertRecord,
    EscalationDecisionRequest,
    ResponseApprovalRequest,
    ResponseUnblockRequest,
    ResponseModeRequest,
    AlertStatusUpdate,
    AttackGraph,
    CaseAlertLinkRequest,
    CaseNoteRequest,
    CaseRecord,
    CaseStatusUpdate,
    ComplianceExportRecord,
    CreateCaseRequest,
    DataReadiness,
    DetectionEngineeringOverview,
    DriftReportResponse,
    EmbeddingSimilarityResult,
    EntityRiskLeaderboard,
    HealthResponse,
    InvestigationContext,
    KillChainResult,
    LiveAuthBatch,
    LiveDetectionStatus,
    Phase16Overview,
    Phase16StartRequest,
    PlaybookCatalogEntry,
    PlaybookExecutionRecord,
    ProductOverview,
    RiskPropagationResult,
    RunPlaybookRequest,
    WebhookConfigRequest,
    WebhookConfigResponse,
    WebhookTestResult,
    ScoreBatchRequest,
    ScoreBatchResponse,
    ScoreEventRequest,
    ScoreEventResponse,
    SecurityPosture,
    TrainingStartRequest,
    TrainingStatus,
)
from graphsentinel.api.service import DetectionService
from graphsentinel.api.store import (
    CaseStore,
    PlaybookExecutionStore,
    SQLiteAlertStore,
    SQLiteCaseStore,
    SQLitePlaybookExecutionStore,
)
from graphsentinel.api.auto_reports import AutoReportService, report_webhook_payload
from graphsentinel.api.integrations import WebhookConfigStore, send_json, send_webhook
from graphsentinel.api.training import TrainingManager
from graphsentinel.training_status import DEFAULT_EXTERNAL_STATUS_PATH
from graphsentinel.detection.playbooks import PLAYBOOK_CATALOG, execute_playbook
from graphsentinel.detection.policy import (
    chain_rule_from_environment,
    policy_from_environment,
)
from graphsentinel.integrations.alert_summary import WebhookAlertSummary, severity_from_risk
from graphsentinel.integrations.siem_export import to_cef, to_ndjson_line
from graphsentinel.models.serving import load_inference_session
from graphsentinel.models.transfer_serving import is_transfer_checkpoint, load_transfer_session
from graphsentinel.response.coordinator import coordinator_from_environment
from graphsentinel.response.store import MemoryResponseStore, SQLiteResponseStore


# ---------------------------------------------------------------------------
# WebSocket connection manager — broadcasts live scored events to all clients
# ---------------------------------------------------------------------------


class ConnectionManager:
    """Thread-safe registry of connected WebSocket clients."""

    def __init__(self) -> None:
        self._active: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self._active:
            self._active.remove(websocket)

    async def broadcast(self, payload: dict) -> None:  # type: ignore[type-arg]
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        for ws in list(self._active):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


_ws_manager = ConnectionManager()
_server_loop: asyncio.AbstractEventLoop | None = None


def _broadcast_threadsafe(payload: dict) -> None:  # type: ignore[type-arg]
    """Schedule a broadcast from any thread.

    The live handler runs in the threadpool, where there is no running loop,
    so the coroutine is handed to the server's loop. With no loop recorded
    (a bare TestClient that never ran start-up) there are no WebSocket
    clients either, and the broadcast is simply skipped.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _server_loop
    if loop is None:
        return
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(_ws_manager.broadcast(payload), loop)


def default_service() -> DetectionService:
    database = os.getenv("GRAPHSENTINEL_DATABASE")
    store = SQLiteAlertStore(Path(database)) if database else None
    checkpoint = os.getenv("GRAPHSENTINEL_CHECKPOINT")
    promoted_checkpoint = Path(
        os.getenv("GRAPHSENTINEL_TRAINED_CHECKPOINT", "artifacts/models/tgn-production.pt")
    )
    if checkpoint is None and promoted_checkpoint.is_file():
        checkpoint = str(promoted_checkpoint)
    device = os.getenv("GRAPHSENTINEL_DEVICE", "cpu")
    model_session = None
    if checkpoint:
        try:
            if is_transfer_checkpoint(Path(checkpoint)):
                # The label-free model: an onboarded estate supplies its own
                # calibration profile; without one it is scored uncalibrated.
                profile = os.getenv("GRAPHSENTINEL_DEPLOYMENT_PROFILE", "").strip()
                model_session = load_transfer_session(
                    Path(checkpoint), profile_path=Path(profile) if profile else None, device=device
                )
            else:
                model_session = load_inference_session(Path(checkpoint), device=device)
            # Node memory is cumulative state: TGNState.initial() zeroes it, so
            # a restarted process asserts "nothing is known" about all 63,397
            # entities at once. Restore the backfill snapshot when one exists.
            # A failure here is logged and tolerated -- serving cold is worse
            # than serving warm, but far better than not serving at all.
            memory_path = os.getenv("GRAPHSENTINEL_TGN_MEMORY", "").strip()
            if memory_path and Path(memory_path).is_file():
                try:
                    restored = model_session.load_memory(Path(memory_path))
                    logging.getLogger("graphsentinel.api").info(
                        "Restored model memory from %s: %s", memory_path, restored
                    )
                except (OSError, ValueError, KeyError):
                    logging.getLogger("graphsentinel.api").exception(
                        "TGN memory snapshot %s could not be restored; "
                        "starting with cold memory.",
                        memory_path,
                    )
        except Exception:
            # A checkpoint that fails to load (missing file, architecture mismatch
            # after a model upgrade, corrupt weights, ...) must never take down the
            # whole API at import time — degrade to the explainable fallback path
            # instead so /health, /alerts, and the console still come up.
            logging.getLogger("graphsentinel.api").exception(
                "Failed to load model checkpoint %s; starting without a frozen model.",
                checkpoint,
            )
            model_session = None
    # Fusion operator and its calibrated threshold, selected together.
    #
    # Measured on the sealed test partition at an equal 25 FP/10k budget:
    # noisy-OR 0.8048 PR-AUC against linear 0.5773 (+39%). The linear operator
    # also gives the TGN an absolute veto -- its non-model channels sum to 0.45
    # against a 0.4543 threshold, so no amount of behavioural evidence can
    # raise an alert on its own. noisy_or is therefore the default; set
    # GRAPHSENTINEL_FUSION=linear to restore the previous behaviour.
    from graphsentinel.detection.fusion import select_fusion

    fusion_name = os.getenv("GRAPHSENTINEL_FUSION", "noisy_or")
    try:
        fusion_config, fusion_threshold = select_fusion(fusion_name)
    except ValueError:
        logging.getLogger("graphsentinel.api").exception(
            "Unknown GRAPHSENTINEL_FUSION=%r; falling back to noisy_or.", fusion_name
        )
        fusion_config, fusion_threshold = select_fusion("noisy_or")

    configured_threshold = os.getenv("GRAPHSENTINEL_THRESHOLD")
    # An explicit threshold always wins. Otherwise use the one calibrated for
    # THIS operator -- never the checkpoint's, which was fitted against linear
    # fusion and would change the alert rate if paired with noisy-OR.
    threshold = float(configured_threshold) if configured_threshold else fusion_threshold

    # Opt-in LLM triage. Imported lazily and defensively so the API still
    # starts when langgraph isn't installed or the agent module is broken --
    # triage then stays on the deterministic template, exactly as before.
    triage_provider = None
    soc_provider = None
    if os.getenv("GRAPHSENTINEL_TRIAGE_AGENT", "").strip().lower() in {"1", "true", "on"}:
        try:
            from graphsentinel.explain.agent import build_default_provider
            from graphsentinel.explain.soc_report import build_default_soc_provider

            triage_provider = build_default_provider()
            soc_provider = build_default_soc_provider()
            logging.getLogger("graphsentinel.api").info(
                "LangGraph triage agent enabled (alerts=%s, SOC reports=%s).",
                getattr(triage_provider, "name", "unknown"),
                getattr(soc_provider, "name", "unknown"),
            )
        except Exception:
            logging.getLogger("graphsentinel.api").exception(
                "Triage agent requested but unavailable; using the deterministic template."
            )
            triage_provider = None
            soc_provider = None

    return DetectionService(
        threshold=threshold,
        store=store,
        model_session=model_session,
        triage_provider=triage_provider,
        soc_report_provider=soc_provider,
        fusion=fusion_config,
    )


def scored_event_payload(
    raw_ev: Any,
    scored: Any,
    *,
    threshold: float,
    ground_truth_chain_id: str | None,
    score_components: dict[str, float] | None,
) -> dict[str, Any]:
    """The WebSocket payload for one scored event: what the console displays.

    The risk, alert flag and severity here are the detection service's own,
    untouched. An earlier version of this endpoint overrode them for any user
    named in the synthetic ground-truth manifest -- clamping the displayed risk
    to at least 0.92 and forcing the alert flag on -- "so the dashboard always
    shows the correct detection even when the model memory is cold". That made the live console
    display detections the model had not made, which is the one thing a
    detection console must never do: an observer watching a synthetic attack
    saw a critical alert whether or not anything had fired. The HTTP response
    and the alert store were never affected, so stored counts remained honest;
    only the display lied.

    Ground truth is still carried, as ground truth. ``ground_truth_chain_id``
    lets the console *label* an event as a known attack next to the model's
    real score, which is how a miss becomes visible instead of hidden.
    """
    return {
        "type": "scored_event",
        "alert_id": scored.alert_id,
        "timestamp": raw_ev.timestamp,
        "user": raw_ev.user,
        "source_host": raw_ev.source_host,
        "destination_host": raw_ev.destination_host,
        "risk": scored.risk,
        "alerted": scored.alerted,
        "severity": severity_for(scored.risk),
        "threshold": threshold,
        "dominant_signals": list(scored.dominant_signals),
        "auth_type": raw_ev.auth_type,
        "logon_type": raw_ev.logon_type,
        "success": raw_ev.success,
        "source": raw_ev.source,
        "is_ground_truth_attacker": ground_truth_chain_id is not None,
        "chain_id": ground_truth_chain_id,
        "scores": score_components,
    }


def create_app(service: DetectionService | None = None) -> FastAPI:
    detection = service or default_service()
    app = FastAPI(
        title="GraphSentinel API",
        version=__version__,
        description="Temporal lateral-movement detection and evidence-grounded triage",
    )
    logger = logging.getLogger("graphsentinel.api")
    id_map_dir = Path(os.getenv("GRAPHSENTINEL_ID_MAP_DIR", "artifacts/id_maps"))
    # What a rule-detected chain may do (GRAPHSENTINEL_CHAIN_RULE_POLICY) and
    # the rule's shape (GRAPHSENTINEL_CHAIN_RULE); see detection/policy.py.
    chain_policy = policy_from_environment()
    chain_rule = chain_rule_from_environment()
    live = LiveDetectionEngine(
        detection, id_map_dir=id_map_dir, policy=chain_policy, chain_rule=chain_rule
    )
    logger.info(
        "Chain rule %s under policy %s (floor %.4f, unattended=%s)",
        chain_rule.name, chain_policy.name, chain_policy.floor, chain_policy.unattended,
    )

    # Cases share the alert database file (a separate connection, disjoint
    # tables) when one is configured; otherwise an in-memory tracker, matching
    # how alerts themselves fall back to AlertStore without GRAPHSENTINEL_DATABASE.
    _case_db = os.getenv("GRAPHSENTINEL_DATABASE")
    case_store: CaseStore | SQLiteCaseStore = (
        SQLiteCaseStore(Path(_case_db)) if _case_db else CaseStore()
    )
    playbook_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore = (
        SQLitePlaybookExecutionStore(Path(_case_db)) if _case_db else PlaybookExecutionStore()
    )
    # Automatic response. Every alert the detection service persists is
    # dispatched through the coordinator; in dry_run (the default) that means
    # planned and recorded, performed by nothing. Arming requires an executing
    # backend and an audited mode change. Records share the alert database.
    responder = coordinator_from_environment(
        mode=os.getenv("GRAPHSENTINEL_AUTO_RESPONSE", "dry_run"),
        backend=os.getenv("GRAPHSENTINEL_RESPONSE_BACKEND", "dry_run"),
        store=SQLiteResponseStore(Path(_case_db)) if _case_db else MemoryResponseStore(),
    )
    detection.responder = responder
    logger.info(
        "Automatic response: mode=%s backend=%s can_arm=%s",
        responder.mode, responder.backend_name, responder.can_arm,
    )
    webhook_config = WebhookConfigStore()
    # Alerting: a webhook configured in the environment is live from start-up;
    # one set through the API replaces it at runtime.
    if os.getenv("GRAPHSENTINEL_WEBHOOK_URL", "").strip():
        webhook_config.update(
            url=os.environ["GRAPHSENTINEL_WEBHOOK_URL"].strip(),
            enabled=True,
            format="generic" if os.getenv("GRAPHSENTINEL_WEBHOOK_FORMAT", "slack") == "generic" else "slack",
            minimum_severity=os.getenv("GRAPHSENTINEL_WEBHOOK_MIN_SEVERITY", "high"),  # type: ignore[arg-type]
        )
    alert_deliveries = {"sent": 0, "failed": 0, "skipped": 0}

    def _notify_soc(alerts: Sequence[AlertRecord]) -> None:
        """Push each new alert to the SOC channel, naming what waits for approval."""
        config = webhook_config.get()
        waiting: dict[str, list[dict[str, object]]] = {}
        if config.enabled and config.url:
            for row in responder.pending_view():
                waiting.setdefault(str(row["alert_id"]), []).append(row)
        summaries = []
        for alert in alerts:
            severity = severity_from_risk(min(1.0, max(0.0, float(alert.risk))))
            if not webhook_config.should_dispatch(severity):
                alert_deliveries["skipped"] += 1
                continue
            event = alert.evidence.event
            rows = waiting.get(alert.alert_id, [])
            summaries.append(WebhookAlertSummary(
                alert_id=alert.alert_id,
                risk=min(1.0, max(0.0, float(alert.risk))),
                user=event.user,
                source_host=event.source_host,
                destination_host=event.destination_host,
                timestamp=int(alert.timestamp),
                severity=severity,
                pending_actions=tuple(str(r["action"]) for r in rows),
                decision_due=min((int(r["approval_deadline"]) for r in rows), default=None),  # type: ignore[call-overload]
            ))
        if not summaries:
            return

        def deliver() -> None:
            for summary in summaries:
                result = send_webhook(str(config.url), summary, format=config.format)
                alert_deliveries["sent" if result.success else "failed"] += 1
                if not result.success:
                    logger.warning("SOC webhook delivery failed for %s: %s", summary.alert_id, result.error)

        # Delivery is network I/O: it must never hold up scoring.
        threading.Thread(target=deliver, name="soc-webhook", daemon=True).start()

    detection.alert_listeners.append(_notify_soc)

    # Automatic SOC reports: every account the system locks gets an incident
    # report written in the background (local model when enabled, template
    # otherwise) and sent to the SOC endpoint.
    def _deliver_report(account: str, entry: dict[str, object]) -> None:
        config = webhook_config.get()
        if not (config.enabled and config.url):
            return
        result = send_json(str(config.url), report_webhook_payload(entry, format=config.format))
        if not result.success:
            logger.warning("SOC report delivery failed for %s: %s", account, result.error)

    auto_reports = AutoReportService(
        generate=detection.soc_report,
        provenance=lambda: dict(detection.last_soc_provenance),
        deliver=_deliver_report,
        report_dir=Path(os.getenv("GRAPHSENTINEL_SOC_REPORT_DIR", "artifacts/reports/soc")),
    )
    auto_reports_enabled = os.getenv("GRAPHSENTINEL_AUTO_REPORT", "on").strip().lower() not in {
        "off", "0", "false", "no",
    }

    def _report_locked_accounts(alerts: Sequence[AlertRecord]) -> None:
        if not auto_reports_enabled or responder.incidents is None:
            return
        for alert in alerts:
            account = alert.evidence.event.user
            if responder.incidents.escalation_for(account) is not None:
                auto_reports.request(account, alert_id=alert.alert_id)

    detection.alert_listeners.append(_report_locked_accounts)
    app.state.auto_reports = auto_reports

    # ── Ground-truth manifest ─────────────────────────────────────────────────
    # Load known attacker identities from the synthetic dataset manifest so the
    # WS broadcast can correctly flag them (and tag the originating chain) even
    # when the TGN memory is cold. Supports both the legacy single-chain
    # manifest (top-level attacker_user_name) and the v2 multi-chain manifest
    # (attack_chains: [{attacker_user_name, chain_id}, ...]).
    _gt_manifest_path = Path("artifacts/synthetic/ground_truth_manifest.json")
    _known_attacker_users: dict[str, str] = {}
    if _gt_manifest_path.exists():
        try:
            _gt = json.loads(_gt_manifest_path.read_text(encoding="utf-8"))
            for _chain in _gt.get("attack_chains", []):
                _name = _chain.get("attacker_user_name")
                if _name:
                    _known_attacker_users[_name] = _chain.get("chain_id", "ATK-000")
            _legacy_name = _gt.get("attacker_user_name")
            if _legacy_name and _legacy_name not in _known_attacker_users:
                _known_attacker_users[_legacy_name] = _gt.get("attack_chain_id", "ATK-001")
            logger.info("Ground-truth manifest loaded. Known attackers: %s", _known_attacker_users)
        except Exception as exc:
            logger.warning("Could not load ground-truth manifest: %s", exc)
    raw_dir = Path(os.getenv("GRAPHSENTINEL_RAW_DIR", "data/raw/lanl"))
    interim_dir = Path(os.getenv("GRAPHSENTINEL_INTERIM_DIR", "data/interim"))
    feature_dir = Path(os.getenv("GRAPHSENTINEL_FEATURE_DIR", "data/processed/features_v1"))
    feature_report_path = Path(
        os.getenv("GRAPHSENTINEL_FEATURE_REPORT", "artifacts/reports/features_v1.json")
    )
    checkpoint_path = Path(
        os.getenv("GRAPHSENTINEL_TRAINED_CHECKPOINT", "artifacts/models/tgn-production.pt")
    )
    training_report_path = Path(
        os.getenv("GRAPHSENTINEL_TRAINING_REPORT", "artifacts/metrics/tgn_training.json")
    )
    pipeline_lease = PipelineLease(
        Path(
            os.getenv(
                "GRAPHSENTINEL_PIPELINE_LEASE",
                "artifacts/runtime/model-pipeline.lease.json",
            )
        )
    )
    training = TrainingManager(
        detection,
        input_dir=feature_dir,
        feature_report_path=feature_report_path,
        checkpoint_path=checkpoint_path,
        report_path=training_report_path,
        raw_dir=raw_dir,
        interim_dir=interim_dir,
        id_map_dir=id_map_dir,
        validate_model=live.validate_model,
        promote_model=lambda session, threshold: live.promote_model(session, threshold=threshold),
        pipeline_lease=pipeline_lease,
        external_status_path=Path(
            os.getenv("GRAPHSENTINEL_TRAINING_STATUS_PATH", str(DEFAULT_EXTERNAL_STATUS_PATH))
        ),
    )
    phase16 = Phase16Manager(
        raw_dir=raw_dir,
        interim_dir=interim_dir,
        id_map_dir=id_map_dir,
        feature_dir=feature_dir,
        ingestion_report_path=Path(
            os.getenv("GRAPHSENTINEL_INGESTION_REPORT", "artifacts/reports/ingestion_auth.json")
        ),
        feature_report_path=feature_report_path,
        baseline_report_path=Path(
            os.getenv("GRAPHSENTINEL_BASELINE_REPORT", "artifacts/metrics/baselines_v1.json")
        ),
        training_report_path=training_report_path,
        checkpoint_path=checkpoint_path,
        candidate_path=Path(
            os.getenv("GRAPHSENTINEL_CANDIDATE_CHECKPOINT", "artifacts/models/tgn-candidate.pt")
        ),
        state_path=Path(
            os.getenv("GRAPHSENTINEL_PHASE16_STATE", "artifacts/runtime/phase16-state.json")
        ),
        lease=pipeline_lease,
        publish_candidate=lambda path, threshold, device: training.publish_candidate(
            path, threshold=threshold, device=device
        ),
    )
    # Every state-changing request is recorded. The response layer can
    # disable accounts and isolate hosts, so 'who asked for this' must be
    # answerable after the fact.
    audit_log = default_audit_log()
    web_root = Path(__file__).resolve().parents[1] / "web"
    configured_origins = os.getenv("GRAPHSENTINEL_ALLOWED_ORIGINS", "")
    origins = [origin.strip() for origin in configured_origins.split(",") if origin.strip()]
    authentication_scope = os.getenv("GRAPHSENTINEL_AUTH_SCOPE", "all").strip().lower()
    if authentication_scope not in {"all", "write"}:
        raise ValueError("GRAPHSENTINEL_AUTH_SCOPE must be 'all' or 'write'")
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH"],
            allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
        )
    app.add_middleware(GZipMiddleware, minimum_size=1_000)
    app.mount("/assets", StaticFiles(directory=web_root / "assets"), name="assets")

    @app.on_event("startup")
    async def _record_loop() -> None:
        global _server_loop
        _server_loop = asyncio.get_running_loop()

    @app.middleware("http")
    async def request_context(request: FastAPIRequest, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID", str(uuid4()))[:128]
        started = time.perf_counter()
        configured_key = os.getenv("GRAPHSENTINEL_API_KEY")
        mutation = request.method in {"POST", "PATCH", "PUT", "DELETE"}
        public_path = request.url.path in {"/", "/health", "/ready", "/docs", "/openapi.json"}
        public_path = public_path or request.url.path.startswith("/assets/")
        authentication_required = (
            bool(configured_key) and not public_path and (authentication_scope == "all" or mutation)
        )
        if authentication_required and configured_key is not None:
            supplied_key = request.headers.get("X-API-Key", "")
            if not secrets.compare_digest(configured_key, supplied_key):
                response = JSONResponse({"detail": "API key required"}, status_code=401)
            else:
                response = await call_next(request)
        else:
            response = await call_next(request)
        elapsed_ms = (time.perf_counter() - started) * 1_000
        if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
            # Reads are deliberately not audited: a polling console would bury
            # the entries that matter under thousands of GETs.
            audit_log.record(
                request_id=request_id,
                actor=actor_fingerprint(request.headers.get("X-API-Key")),
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                latency_ms=elapsed_ms,
                client=request.client.host if request.client else "",
            )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = (
            "public, max-age=3600" if request.url.path.startswith("/assets/") else "no-store"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "script-src 'self' 'unsafe-inline'; "
            "connect-src 'self' ws: wss:; frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        logger.info(
            "request_complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "elapsed_ms": round(elapsed_ms, 3),
            },
        )
        return response

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(web_root / "index.html")

    @app.get("/api/v1/synthetic-manifest", tags=["live-detection"])
    def synthetic_manifest() -> dict:  # type: ignore[type-arg]
        """Serve ground truth manifest for the synthetic live stream."""
        manifest_path = Path("artifacts/synthetic/ground_truth_manifest.json")
        if not manifest_path.is_file():
            raise HTTPException(status_code=404, detail="Synthetic manifest not found")
        try:
            return json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @app.get("/api/v1/synthetic-events", tags=["live-detection"])
    def synthetic_events(
        limit: int = Query(default=500, ge=1, le=30000),
    ) -> list[dict]:  # type: ignore[type-arg]
        """Serve synthetic stream rows to the browser-side live stream demo."""
        import importlib
        parquet_path = Path(
            os.getenv("GRAPHSENTINEL_SYNTHETIC_STREAM", "artifacts/synthetic/synthetic_live_stream.parquet")
        )
        if not parquet_path.is_file():
            raise HTTPException(
                status_code=404,
                detail=f"Synthetic stream not found at {parquet_path}. Run scripts/generate_synthetic_stream.py first.",
            )
        try:
            # polars, not pandas: pandas is neither installed nor declared in
            # pyproject.toml (the project's dataframe dependency is
            # "polars>=1.25,<2"), so importing it raised ModuleNotFoundError
            # that this handler swallowed into an opaque 500 -- leaving the
            # Live Stream Demo broken in any environment built from the
            # project's own declared dependencies.
            pl = importlib.import_module("polars")
            # Name the stream's ids with the dictionary it was *written* with,
            # not the one this server serves with: an id means a different
            # account in each (id 80 is U66@DOM1 in the generator's dictionary,
            # C791$@DOM1 in the serving one), and naming through the wrong one
            # renamed every identity in the demo and broke its ground truth.
            # The manifest's own attacker (id, name) pairs say which it is.
            from graphsentinel.api.stream_dictionary import (
                GENERATOR_DICTIONARY,
                stream_dictionary,
            )

            manifest_file = Path("artifacts/synthetic/ground_truth_manifest.json")
            manifest_doc = None
            if manifest_file.is_file():
                try:
                    manifest_doc = json.loads(manifest_file.read_text(encoding="utf-8"))
                except ValueError:
                    manifest_doc = None
            id_dir, _why = stream_dictionary(manifest_doc, [GENERATOR_DICTIONARY, id_map_dir])
            if id_dir is None:
                raise HTTPException(status_code=503, detail="no entity dictionary for the stream")
            user_map = json.loads((id_dir / "users.json").read_text(encoding="utf-8"))["values"]
            host_map = json.loads((id_dir / "hosts.json").read_text(encoding="utf-8"))["values"]
            auth_map = json.loads((id_dir / "auth_types.json").read_text(encoding="utf-8"))["values"]
            logon_map = json.loads((id_dir / "logon_types.json").read_text(encoding="utf-8"))["values"]
            orient_map = json.loads((id_dir / "orientations.json").read_text(encoding="utf-8"))["values"]

            frame = pl.read_parquet(parquet_path).head(limit)
            has_label = "label_redteam" in frame.columns
            results = []
            for row in frame.iter_rows(named=True):
                src_u = int(row["src_user_id"])
                dst_u = int(row["dst_user_id"])
                src_h = int(row["src_host_id"])
                dst_h = int(row["dst_host_id"])
                auth_id = int(row["auth_type_id"])
                logon_id = int(row["logon_type_id"])
                orient_id = int(row["orientation_id"])

                u_str = user_map[src_u] if src_u < len(user_map) else f"USER_{src_u}"
                dst_u_str = user_map[dst_u] if dst_u < len(user_map) else f"USER_{dst_u}"
                src_h_str = host_map[src_h] if src_h < len(host_map) else f"HOST_{src_h}"
                dst_h_str = host_map[dst_h] if dst_h < len(host_map) else f"HOST_{dst_h}"
                if src_h_str == dst_h_str:
                    dst_h_str = host_map[(dst_h + 1) % len(host_map)]

                results.append({
                    "timestamp": int(row["timestamp"]),
                    "user": u_str,
                    "source_host": src_h_str,
                    "destination_host": dst_h_str,
                    "destination_user": dst_u_str,
                    "auth_type": auth_map[auth_id] if auth_id < len(auth_map) else "unknown",
                    "logon_type": logon_map[logon_id] if logon_id < len(logon_map) else "unknown",
                    "orientation": orient_map[orient_id] if orient_id < len(orient_map) else "logon",
                    "success": bool(row["success"]),
                    # iter_rows(named=True) yields a plain dict, so a missing
                    # column would KeyError rather than defaulting -- gate on
                    # the schema instead.
                    "label_redteam": int(row["label_redteam"]) if has_label else 0,
                })
            return results
        except Exception as error:
            raise HTTPException(status_code=500, detail=f"Cannot load synthetic stream: {error}") from error


    @app.get("/health", response_model=HealthResponse, tags=["operations"])
    def health() -> HealthResponse:
        return HealthResponse(version=__version__, model_loaded=detection.model_loaded)

    @app.get("/ready", response_model=HealthResponse, tags=["operations"])
    def ready() -> HealthResponse:
        # Repository metrics exercise the persistence connection as a readiness check.
        detection.store.metrics()
        if not live.status().model_contract_ready:
            raise HTTPException(
                status_code=503,
                detail="loaded model is missing its verified frozen entity dictionary",
            )
        # Degradation is reported, not fatal. See HealthResponse.degraded.
        degraded: list[str] = []
        coverage = live.feature_coverage()
        if not coverage.get("restored_from_snapshot"):
            degraded.append(
                "feature-state-cold: cumulative features were not restored from a "
                "backfill snapshot; 12 of 27 features are wrong until one is built"
            )
        memory = detection.memory_coverage()
        if memory is not None and not memory.get("nodes_with_memory"):
            degraded.append(
                "model-memory-cold: every entity's memory vector is zero; the model "
                "is scoring as though nothing is known about any entity"
            )
        return HealthResponse(
            version=__version__,
            model_loaded=detection.model_loaded,
            degraded=tuple(degraded),
        )

    @app.get("/model", tags=["operations"])
    def model_provenance() -> dict[str, object]:
        provenance = detection.model_provenance()
        if provenance is None:
            raise HTTPException(status_code=503, detail="no frozen model checkpoint loaded")
        return provenance

    @app.post("/score-event", response_model=ScoreEventResponse, tags=["detection"])
    def score_event(request: ScoreEventRequest) -> ScoreEventResponse:
        try:
            return detection.score_event(request)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/score-batch", response_model=ScoreBatchResponse, tags=["detection"])
    def score_batch(request: ScoreBatchRequest) -> ScoreBatchResponse:
        try:
            return detection.score_batch(request)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/live/events", response_model=ScoreBatchResponse, tags=["live-detection"])
    def live_events(request: LiveAuthBatch) -> ScoreBatchResponse:  # type: ignore[override]
        # Deliberately synchronous: FastAPI runs it in the threadpool, so a
        # batch's feature computation and model inference never occupy the
        # event loop. As an ``async def`` it blocked every other request --
        # /health included -- for the duration of each batch.
        try:
            result = live.detect(request)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        # Broadcast each scored event to WebSocket subscribers as a side-effect
        threshold = detection.threshold
        for raw_ev, scored in zip(request.events, result.results):
            # A persisted AlertRecord (with the raw novelty/burst/pivot/corroboration/tgn
            # component breakdown) only exists for events the service alerted on.
            score_components: dict[str, float] | None = None
            if scored.alerted:
                persisted = detection.store.get_alert(scored.alert_id)
                if persisted is not None:
                    score_components = persisted.evidence.scores.model_dump()
            payload = scored_event_payload(
                raw_ev,
                scored,
                threshold=threshold,
                ground_truth_chain_id=_known_attacker_users.get(raw_ev.user),
                score_components=score_components,
            )
            if scored.alerted and scored.alert_id:
                # What automatic response did about this alert, so the console
                # shows the action next to the detection it answered.
                dispatched = responder.executions(alert_id=scored.alert_id)
                payload["response"] = {
                    "mode": responder.mode,
                    "auto": [r.action for r in dispatched if r.outcome in ("dry_run", "executed")],
                    "executed": [r.action for r in dispatched if r.outcome == "executed"],
                    "pending": [r.action for r in dispatched if r.outcome == "pending_approval"],
                }
            _broadcast_threadsafe(payload)
        return result

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket) -> None:
        """Push-stream of scored events to connected dashboard clients."""
        await _ws_manager.connect(websocket)
        try:
            # Send hello frame so client knows the connection is live
            await websocket.send_text(json.dumps({"type": "connected", "version": __version__}))
            while True:
                # Keep connection alive; client sends pings if needed
                await websocket.receive_text()
        except WebSocketDisconnect:
            _ws_manager.disconnect(websocket)

    @app.get("/api/v1/threshold-config", tags=["operations"])
    def threshold_config() -> dict:  # type: ignore[type-arg]
        """Single source of truth for risk severity banding used by the dashboard."""
        return {
            "decision_threshold": detection.threshold,
            "chain_rule": chain_rule.to_dict(),
            "chain_rule_policy": chain_policy.to_dict(),
            "bands": {
                "low":      {"min": 0.00, "max": 0.50, "color": "#3B82F6"},
                "medium":   {"min": 0.50, "max": 0.70, "color": "#F59E0B"},
                "high":     {"min": 0.70, "max": 0.85, "color": "#EF4444"},
                "critical": {"min": 0.85, "max": 1.00, "color": "#A855F7"},
            },
        }

    @app.get("/api/v1/live/status", response_model=LiveDetectionStatus, tags=["live-detection"])
    def live_status() -> LiveDetectionStatus:
        return live.status()

    @app.get("/api/v1/training/status", response_model=TrainingStatus, tags=["training"])
    def training_status() -> TrainingStatus:
        return training.status()

    @app.get("/api/v1/data/readiness", response_model=DataReadiness, tags=["training"])
    def data_readiness() -> DataReadiness:
        return training.data_readiness()

    @app.get("/api/v1/phase16", response_model=Phase16Overview, tags=["model-lifecycle"])
    def phase16_status() -> Phase16Overview:
        return phase16.status()

    @app.post(
        "/api/v1/phase16/start",
        response_model=Phase16Overview,
        status_code=202,
        tags=["model-lifecycle"],
    )
    def phase16_start(request: Phase16StartRequest) -> Phase16Overview:
        try:
            return phase16.start(request)
        except (FileNotFoundError, FileExistsError, PipelineBusyError, RuntimeError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/api/v1/security/posture", response_model=SecurityPosture, tags=["operations"])
    def security_posture() -> SecurityPosture:
        workers = int(os.getenv("GRAPHSENTINEL_WORKERS", "1"))
        api_key_required = bool(os.getenv("GRAPHSENTINEL_API_KEY"))
        reported_scope: Literal["all_requests", "write_requests", "not_configured"]
        if not api_key_required:
            reported_scope = "not_configured"
        elif authentication_scope == "all":
            reported_scope = "all_requests"
        else:
            reported_scope = "write_requests"
        return SecurityPosture(
            write_authentication="api_key" if api_key_required else "not_configured",
            authentication_scope=reported_scope,
            api_key_required=api_key_required,
            cors_restricted="*" not in origins,
            allowed_origins=tuple(origins) if origins else ("same-origin",),
            persistent_repository=isinstance(detection.store, SQLiteAlertStore),
            configured_workers=workers,
            ordered_stream_safe=workers == 1,
        )

    @app.post("/api/v1/training/start", response_model=TrainingStatus, tags=["training"])
    def training_start(request: TrainingStartRequest) -> TrainingStatus:
        try:
            return training.start(request)
        except FileNotFoundError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except RuntimeError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/alerts", response_model=tuple[AlertRecord, ...], tags=["investigation"])
    def alerts(
        minimum_risk: float = Query(default=0, ge=0, le=1),
        limit: int = Query(default=100, ge=1, le=1_000),
    ) -> tuple[AlertRecord, ...]:
        return detection.store.list_alerts(minimum_risk=minimum_risk, limit=limit)

    @app.get("/api/v1/alerts", response_model=tuple[AlertRecord, ...], tags=["product-console"])
    def product_alerts(
        minimum_risk: float = Query(default=0, ge=0, le=1),
        status: Literal["new", "reviewed", "closed"] | None = None,
        query: str | None = Query(default=None, max_length=128),
        limit: int = Query(default=250, ge=1, le=1_000),
    ) -> tuple[AlertRecord, ...]:
        alerts = detection.store.list_alerts(minimum_risk=minimum_risk, limit=1_000)
        if status is not None:
            alerts = tuple(alert for alert in alerts if alert.status == status)
        if query:
            needle = query.casefold()
            alerts = tuple(
                alert
                for alert in alerts
                if needle
                in " ".join(
                    (
                        alert.alert_id,
                        alert.evidence.event.user,
                        alert.evidence.event.source_host,
                        alert.evidence.event.destination_host,
                    )
                ).casefold()
            )
        return alerts[:limit]

    @app.get("/api/v1/overview", response_model=ProductOverview, tags=["product-console"])
    def product_overview() -> ProductOverview:
        return build_overview(
            detection.store,
            model_loaded=detection.model_loaded,
            threshold=detection.threshold,
        )

    @app.get("/api/v1/entity-risk", response_model=EntityRiskLeaderboard, tags=["product-console"])
    def product_entity_risk() -> EntityRiskLeaderboard:
        return build_entity_risk_leaderboard(detection.store)

    @app.get("/api/v1/risk-propagation", response_model=RiskPropagationResult, tags=["product-console"])
    def product_risk_propagation(
        seed_threshold: float = Query(default=0.85, ge=0, le=1),
    ) -> RiskPropagationResult:
        return build_risk_propagation(detection.store, seed_threshold=seed_threshold)

    @app.get(
        "/api/v1/embedding-similarity",
        response_model=EmbeddingSimilarityResult,
        tags=["product-console"],
    )
    def product_embedding_similarity(
        entity: str = Query(..., min_length=1),
        kind: Literal["user", "host"] = Query(...),
        top_k: int = Query(default=10, ge=1, le=100),
    ) -> EmbeddingSimilarityResult:
        try:
            return build_embedding_similarity(
                detection, live, query_entity=entity, query_kind=kind, top_k=top_k
            )
        except ValueError as error:
            message = str(error)
            status = 503 if "no frozen model" in message else 404
            raise HTTPException(status_code=status, detail=message) from error

    @app.get("/api/v1/kill-chain", response_model=KillChainResult, tags=["product-console"])
    def product_kill_chain(
        alert_ids: str = Query(..., description="Comma-separated alert IDs"),
    ) -> KillChainResult:
        ids = [raw.strip() for raw in alert_ids.split(",") if raw.strip()]
        if not ids:
            raise HTTPException(status_code=400, detail="alert_ids must contain at least one ID")
        return build_kill_chain(detection.store, ids)

    @app.get("/api/v1/drift", response_model=DriftReportResponse, tags=["product-console"])
    def product_drift() -> DriftReportResponse:
        return build_drift_report(detection)

    @app.post("/api/v1/cases", response_model=CaseRecord, tags=["cases"])
    def create_case(request: CreateCaseRequest) -> CaseRecord:
        return case_store.create_case(
            title=request.title, alert_ids=request.alert_ids, now=int(time.time())
        )

    @app.get("/api/v1/cases", response_model=tuple[CaseRecord, ...], tags=["cases"])
    def list_cases(
        status: Literal["open", "investigating", "closed"] | None = None,
        limit: int = Query(default=100, ge=1, le=500),
    ) -> tuple[CaseRecord, ...]:
        return case_store.list_cases(status=status, limit=limit)

    @app.get("/api/v1/cases/{case_id}", response_model=CaseRecord, tags=["cases"])
    def get_case(case_id: str) -> CaseRecord:
        case = case_store.get_case(case_id)
        if case is None:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id!r}")
        return case

    @app.post("/api/v1/cases/{case_id}/status", response_model=CaseRecord, tags=["cases"])
    def update_case_status(case_id: str, request: CaseStatusUpdate) -> CaseRecord:
        try:
            return case_store.update_status(
                case_id, request.status, closed_reason=request.closed_reason, now=int(time.time())
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id!r}") from error

    @app.post("/api/v1/cases/{case_id}/notes", response_model=CaseRecord, tags=["cases"])
    def add_case_note(case_id: str, request: CaseNoteRequest) -> CaseRecord:
        try:
            return case_store.add_note(
                case_id, author=request.author, text=request.text, now=int(time.time())
            )
        except KeyError as error:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id!r}") from error

    @app.post("/api/v1/cases/{case_id}/alerts", response_model=CaseRecord, tags=["cases"])
    def link_case_alerts(case_id: str, request: CaseAlertLinkRequest) -> CaseRecord:
        try:
            return case_store.link_alerts(case_id, request.alert_ids, now=int(time.time()))
        except KeyError as error:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id!r}") from error

    @app.get(
        "/api/v1/cases/{case_id}/compliance-export",
        response_model=ComplianceExportRecord,
        tags=["cases"],
    )
    def export_case_compliance_record(case_id: str) -> ComplianceExportRecord:
        try:
            return build_compliance_export(case_store, detection.store, case_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail=f"unknown case: {case_id!r}") from error

    @app.get("/api/v1/audit", tags=["operations"])
    def audit_trail(
        limit: int = Query(default=100, ge=1, le=1_000),
        high_impact_only: bool = Query(default=False),
        actor: str | None = Query(default=None),
    ) -> dict[str, object]:
        """Recent state-changing activity, newest first.

        ``high_impact_only`` narrows to requests whose effects reach outside
        the product -- playbook execution, integrations, case and alert
        mutations -- which is what an incident reviewer actually wants.

        Actors are key fingerprints, never keys.
        """
        return {
            "entries": [e.to_dict() for e in audit_log.recent(
                limit=limit, high_impact_only=high_impact_only, actor=actor)],
            "stats": audit_log.stats(),
        }

    @app.get("/api/v1/feature-state", tags=["operations"])
    def feature_state() -> dict[str, object]:
        """How much history this deployment is carrying, across both halves.

        Cumulative state lives in two places -- twelve of the 27 features, and
        every node's memory vector -- and neither is rebuilt by forward
        traffic. A cold deployment is quietly less accurate rather than
        obviously broken: measured on this corpus it runs at 46% of its
        achievable PR-AUC while ROC-AUC barely moves, so nothing in ordinary
        monitoring would show it.

        This endpoint makes the answer explicit, so "is this deployment warm?"
        is a question with an answer rather than something inferred from
        detection quality weeks later.
        """
        payload: dict[str, object] = {
            "features": live.feature_coverage(),
            "model_memory": detection.memory_coverage(),
        }
        features = payload["features"]
        warm_features = bool(features.get("restored_from_snapshot"))
        memory = payload["model_memory"]
        warm_memory = bool(memory and memory.get("nodes_with_memory"))
        payload["warm"] = warm_features and warm_memory
        if not payload["warm"]:
            payload["warning"] = (
                "This deployment is running on partial state. Build it with "
                "`graphsentinel backfill` and set GRAPHSENTINEL_FEATURE_STATE "
                "and GRAPHSENTINEL_TGN_MEMORY. See docs/ONBOARDING.md."
            )
        return payload

    @app.post("/api/v1/feature-state/save", tags=["operations"])
    def save_feature_state() -> dict[str, object]:
        """Persist the cumulative state so a restart resumes from it.

        Both halves, or the restart is inconsistent: the feature engine to
        ``GRAPHSENTINEL_FEATURE_STATE`` and, when a model is loaded and
        ``GRAPHSENTINEL_TGN_MEMORY`` is set, its node memory to that path.
        Saving only the features -- what this endpoint did before the
        end-to-end check caught it -- restarted with features advanced to
        now and memory frozen at onboarding day, a state no run ever
        produced (Finding 24).
        """
        memory_path = os.getenv("GRAPHSENTINEL_TGN_MEMORY", "").strip()
        try:
            return live.save_state(memory_path=Path(memory_path) if memory_path else None)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/api/v1/tactics", tags=["tactics"])
    def tactic_catalogue() -> dict[str, object]:
        """ATT&CK techniques this deployment can attribute, and their response plans.

        ``validation`` is included deliberately: only T1021 has real labels
        behind it in this corpus, and that caveat has to travel with the
        catalogue rather than living in a document nobody opens.
        """
        from graphsentinel.detection.response import catalogue
        from graphsentinel.detection.tactics import SIGNATURES, describe_validation

        # Measured against ATT&CK-described behaviour (Finding 22), when the
        # study has been run. A signature's badge should not outrank its
        # numbers, so they ride along with the catalogue.
        measured: dict[str, object] = {}
        try:
            study = json.loads(
                Path("artifacts/prevention/techniques/technique_validation.json").read_text(
                    encoding="utf-8"
                )
            )
            measured = {
                technique_id: {
                    "detection_recall": row["detection_recall"],
                    "attribution_recall": row["attribution_recall"],
                    "precision": row["precision"],
                    "false_attribution_rate_per_10k": row["false_attribution_rate_per_10k"],
                    "injected": row["injected"],
                }
                for technique_id, row in (study.get("techniques") or {}).items()
            }
        except (OSError, ValueError, KeyError):
            measured = {}

        return {
            "techniques": {
                technique_id: {
                    "name": signature.name,
                    "tactic": signature.tactic,
                    "description": signature.description,
                    "validated_against_labels": signature.ground_truth,
                    "measured_on_injected_behaviour": measured.get(technique_id),
                }
                for technique_id, signature in SIGNATURES.items()
            },
            "response": catalogue(),
            "validation": {
                **describe_validation(),
                "measured_note": (
                    "measured_on_injected_behaviour comes from scripts/validate_techniques.py: "
                    "recall on ATT&CK-described injections and precision against benign "
                    "traffic. Absent means the study has not been run in this checkout."
                ),
            },
        }

    @app.get("/api/v1/alerts/{alert_id}/response", tags=["tactics"])
    def alert_response_plan(alert_id: str) -> dict[str, object]:
        """The recommended response for one alert, selected by attributed technique.

        Risk decides how urgent; the technique decides what actually helps.
        Re-authentication stops lateral movement and does nothing against a
        brute-force attempt that has not succeeded yet, so the two cannot share
        a plan.
        """
        from graphsentinel.detection.response import plan_for

        alert = detection.store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail=f"unknown alert: {alert_id!r}")

        technique_id = alert.tactic.technique_id if alert.tactic else None
        confidence = alert.tactic.confidence if alert.tactic else "none"
        plan = plan_for(technique_id, confidence, risk=alert.risk)
        return {
            "alert_id": alert.alert_id,
            "risk": alert.risk,
            "tactic": alert.tactic.model_dump() if alert.tactic else None,
            "plan": plan.to_dict(),
            "mode": responder.mode,
            "executions": [r.to_dict() for r in responder.executions(alert_id=alert_id)],
            "pending": [r.action for r in responder.pending() if r.alert_id == alert_id],
        }

    # ── Research evidence ────────────────────────────────────────────────────
    @app.get("/api/v1/research/summary", tags=["research"])
    def research_summary() -> dict[str, object]:
        """The measured evidence behind the product, from committed artefacts.

        Every number here is read from a file a test re-derives or a script
        regenerates; nothing is computed on request, so the console cannot
        show a figure that does not exist somewhere reviewable. Absent
        artefacts are reported as absent rather than invented.
        """
        from graphsentinel.detection.gates import AUTO_EXECUTE_GATE

        def read_json(path: Path) -> dict[str, object] | None:
            try:
                return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]
            except (OSError, ValueError):
                return None

        evaluation = read_json(Path("docs/evaluation_report.json"))
        prevention = read_json(Path("artifacts/prevention/production/prevention_report.json"))
        policy = read_json(
            Path("artifacts/prevention/policy_rule_floor_at_gate/prevention_report.json")
        )
        techniques = read_json(Path("artifacts/prevention/techniques/technique_validation.json"))
        study = read_json(Path("artifacts/prevention/chain_rule_study/chain_rule_study.json"))
        findings: list[dict[str, str]] = []
        try:
            for line in Path("docs/DETECTION_RESEARCH_FINDINGS.md").read_text(
                encoding="utf-8"
            ).splitlines():
                if line.startswith("## Finding "):
                    number, _, title = line[len("## Finding "):].partition(" — ")
                    findings.append({"number": number.strip(), "title": title.strip()})
        except OSError:
            pass
        return {
            "evaluation": None if evaluation is None else {
                "detectors": evaluation.get("detectors"),
                "generalisation": evaluation.get("generalisation"),
                "entity_contamination": (evaluation.get("headline") or {}).get(
                    "entity_contamination"
                ),
                "generated_at": evaluation.get("generated_at"),
            },
            "gate": AUTO_EXECUTE_GATE.to_dict(),
            "prevention": None if prevention is None else {
                "operating_points": {
                    name: {
                        "overall": op.get("overall"),
                        "by_family": op.get("by_family"),
                        "by_interval": op.get("by_interval"),
                        "benign": op.get("benign"),
                        "chain_rule": op.get("chain_rule"),
                        "policy": op.get("policy"),
                        "loop": op.get("loop"),
                    }
                    for name, op in (prevention.get("operating_points") or {}).items()
                },
                "campaign_grid": prevention.get("campaign_grid"),
                "model_version": prevention.get("model_version"),
            },
            # What a rule-detected chain may do, and the rule's shape, as this
            # process runs them; and the study that chose the defaults.
            "chain_rule": {
                "shipped": chain_rule.to_dict(),
                "policy": chain_policy.to_dict(),
                "study": None if study is None else {
                    "corpus": study.get("corpus"),
                    "rows": [
                        {
                            "rule": row.get("rule"),
                            "policy": row.get("policy"),
                            "campaigns_detected": row.get("campaigns_detected"),
                            "chain_campaigns_detected": row.get("chain_campaigns_detected"),
                            "median_first_alert_hop": row.get("median_first_alert_hop"),
                            "prevented_campaign": row.get("prevented_campaign"),
                            "prevented_campaign_chain": row.get("prevented_campaign_chain"),
                            "benign_auto_per_10k": row.get("benign_auto_per_10k"),
                            "benign_users_hit": row.get("benign_users_hit"),
                        }
                        for row in (study.get("instrument") or {}).values()
                    ],
                },
            },
            "policy_rule_floor_at_gate": None if policy is None else {
                name: {"overall": op.get("overall"), "by_family": op.get("by_family"),
                       "benign": op.get("benign")}
                for name, op in (policy.get("operating_points") or {}).items()
            },
            "techniques": None if techniques is None else {
                "techniques": techniques.get("techniques"),
                "benign_events": techniques.get("benign_events"),
                "benign_alert_rate_per_10k": techniques.get("benign_alert_rate_per_10k"),
                "replicates_per_builder": techniques.get("replicates_per_builder"),
            },
            "findings": findings,
            "documents": {
                "findings": "docs/DETECTION_RESEARCH_FINDINGS.md",
                "evaluation": "docs/EVALUATION_REPORT.md",
                "instrument": "docs/PREVENTION_INSTRUMENT.md",
            },
        }

    # ── Automatic response ───────────────────────────────────────────────────
    @app.get("/api/v1/response/status", tags=["response"])
    def response_status() -> dict[str, object]:
        """Mode, backend, whether it can be armed, and dispatch counts."""
        return responder.status().to_dict()

    @app.get("/api/v1/response/executions", tags=["response"])
    def response_executions(
        limit: int = Query(default=100, ge=1, le=1000),
        alert_id: str | None = Query(default=None, max_length=64),
    ) -> dict[str, object]:
        """Every dispatch, newest first, with the literal command and its outcome."""
        return {
            "mode": responder.mode,
            "records": [r.to_dict() for r in responder.executions(limit=limit, alert_id=alert_id)],
        }

    @app.get("/api/v1/response/pending", tags=["response"])
    def response_pending() -> dict[str, object]:
        """Actions the catalogue reserves for a person, waiting for one, each
        with its approval deadline and what happens if nobody decides in time.
        Reading it also closes every window that has run out."""
        return {
            "mode": responder.mode,
            "approval_window": responder.approval_window.to_dict(),
            "pending": responder.pending_view(),
        }

    @app.post("/api/v1/response/reject", tags=["response"])
    def response_reject(request: ResponseApprovalRequest) -> dict[str, object]:
        """Decline one pending action inside its approval window; it never runs."""
        try:
            record = responder.reject(
                request.alert_id, request.action, approver=request.approver, note=request.note
            )
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return record.to_dict()

    @app.post("/api/v1/response/unblock", tags=["response"])
    def response_unblock(request: ResponseUnblockRequest) -> dict[str, object]:
        """Lift a block (account lock or network-path block) now; the revert
        command is recorded against the original alert."""
        try:
            record = responder.unblock(request.alert_id, request.action, actor=request.actor)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return record.to_dict()

    @app.post("/api/v1/response/approve", tags=["response"])
    def response_approve(request: ResponseApprovalRequest) -> dict[str, object]:
        """Release one reserved action on one alert. Dispatches it immediately
        (dry-run or armed, whichever the mode is)."""
        try:
            record = responder.approve(
                request.alert_id, request.action, approver=request.approver, note=request.note
            )
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return record.to_dict()

    @app.get("/api/v1/response/incidents", tags=["response"])
    def response_incidents() -> dict[str, object]:
        """The prevention loop's state: accounts under observation after a
        containment, active escalations with their auto-revert times, and the
        evidence each rests on. Reading it also performs any revert that has
        come due."""
        return responder.incident_view()

    @app.post("/api/v1/response/incidents/keep", tags=["response"])
    def response_incident_keep(request: EscalationDecisionRequest) -> dict[str, object]:
        """Keep an automatic lock: it will not be lifted by the system."""
        try:
            return responder.keep_escalation(request.account, actor=request.actor).to_dict()
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.post("/api/v1/response/incidents/revert", tags=["response"])
    def response_incident_revert(request: EscalationDecisionRequest) -> dict[str, object]:
        """Lift an automatic lock now; the revert command is recorded."""
        try:
            record = responder.revert_escalation(request.account, actor=request.actor)
        except LookupError as error:
            raise HTTPException(status_code=404, detail=str(error)) from error
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return {"reverted": record.to_dict() if record else None}

    @app.post("/api/v1/response/mode", tags=["response"])
    def response_mode(request: ResponseModeRequest) -> dict[str, object]:
        """Switch off / dry_run / armed. Arming a backend that performs nothing is
        refused rather than silently accepted."""
        try:
            return responder.set_mode(request.mode, actor=request.actor).to_dict()
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get(
        "/api/v1/playbooks", response_model=tuple[PlaybookCatalogEntry, ...], tags=["playbooks"]
    )
    def list_playbooks() -> tuple[PlaybookCatalogEntry, ...]:
        return tuple(
            PlaybookCatalogEntry(
                name=p.name, description=p.description, steps=tuple(s.action for s in p.steps)
            )
            for p in PLAYBOOK_CATALOG.values()
        )

    @app.post(
        "/api/v1/playbooks/{name}/run", response_model=PlaybookExecutionRecord, tags=["playbooks"]
    )
    def run_playbook(name: str, request: RunPlaybookRequest) -> PlaybookExecutionRecord:
        definition = PLAYBOOK_CATALOG.get(name)
        if definition is None:
            raise HTTPException(status_code=404, detail=f"unknown playbook: {name!r}")
        from graphsentinel.response.executor import Approval

        now = int(time.time())
        execution_id = f"playbook:{name}:{request.entity}:{now}"
        if request.approved_actions and not request.approver:
            raise HTTPException(status_code=422, detail="approved_actions requires an approver")
        approvals = [
            Approval(execution_id, action, request.approver) for action in request.approved_actions
        ]
        execution = execute_playbook(
            definition,
            entity=request.entity,
            entity_kind=request.entity_kind,
            risk=request.risk,
            now=now,
            approvals=approvals,
            execution_id=execution_id,
        )
        return playbook_store.record(execution)

    @app.get(
        "/api/v1/playbooks/executions",
        response_model=tuple[PlaybookExecutionRecord, ...],
        tags=["playbooks"],
    )
    def list_playbook_executions(
        limit: int = Query(default=100, ge=1, le=500),
    ) -> tuple[PlaybookExecutionRecord, ...]:
        return playbook_store.list_executions(limit=limit)

    @app.get(
        "/api/v1/integrations/webhook", response_model=WebhookConfigResponse, tags=["integrations"]
    )
    def get_webhook_config() -> WebhookConfigResponse:
        config = webhook_config.get()
        return WebhookConfigResponse(
            url=config.url, enabled=config.enabled, format=config.format,
            minimum_severity=config.minimum_severity,
        )

    @app.post(
        "/api/v1/integrations/webhook", response_model=WebhookConfigResponse, tags=["integrations"]
    )
    def set_webhook_config(request: WebhookConfigRequest) -> WebhookConfigResponse:
        config = webhook_config.update(
            url=request.url, enabled=request.enabled, format=request.format,
            minimum_severity=request.minimum_severity,
        )
        return WebhookConfigResponse(
            url=config.url, enabled=config.enabled, format=config.format,
            minimum_severity=config.minimum_severity,
        )

    @app.post(
        "/api/v1/integrations/webhook/test",
        response_model=WebhookTestResult,
        tags=["integrations"],
    )
    def test_webhook_config() -> WebhookTestResult:
        config = webhook_config.get()
        if not config.url:
            raise HTTPException(status_code=400, detail="no webhook URL configured")
        test_summary = WebhookAlertSummary(
            alert_id="GS-TEST-00000000",
            risk=0.91,
            user="test-user@DOM1",
            source_host="TEST-HOST-A",
            destination_host="TEST-HOST-B",
            timestamp=int(time.time()),
            severity="critical",
        )
        result = send_webhook(config.url, test_summary, format=config.format)
        return WebhookTestResult(
            success=result.success, status_code=result.status_code, error=result.error
        )

    @app.get("/api/v1/integrations/siem-export", tags=["integrations"])
    def siem_export(
        export_format: Literal["cef", "ndjson"] = Query(default="cef", alias="format"),
        limit: int = Query(default=500, ge=1, le=5_000),
    ) -> PlainTextResponse:
        alerts = detection.store.list_alerts(limit=limit)
        summaries = [
            WebhookAlertSummary(
                alert_id=alert.alert_id,
                risk=alert.risk,
                user=alert.evidence.event.user,
                source_host=alert.evidence.event.source_host,
                destination_host=alert.evidence.event.destination_host,
                timestamp=alert.timestamp,
                severity=severity_from_risk(alert.risk),
            )
            for alert in alerts
        ]
        if export_format == "cef":
            body = "\n".join(to_cef(s) for s in summaries)
            media_type = "text/plain"
        else:
            body = "\n".join(to_ndjson_line(s) for s in summaries)
            media_type = "application/x-ndjson"
        return PlainTextResponse(content=body, media_type=media_type)

    @app.get("/api/v1/graph", response_model=AttackGraph, tags=["product-console"])
    def product_graph(
        minimum_risk: float = Query(default=0, ge=0, le=1),
        limit: int = Query(default=250, ge=1, le=500),
    ) -> AttackGraph:
        return build_attack_graph(
            detection.store.list_alerts(minimum_risk=minimum_risk, limit=limit)
        )

    @app.get("/api/v1/paths", tags=["product-console"])
    def product_paths(
        limit: int = Query(default=100, ge=1, le=500),
    ) -> tuple[dict[str, object], ...]:
        return tuple(path.to_dict() for path in detection.store.list_paths(limit=limit))

    @app.get("/api/v1/entity-names", tags=["product-console"])
    def entity_names(
        user_ids: str = Query(default="", description="Comma-separated numeric user IDs"),
        host_ids: str = Query(default="", description="Comma-separated numeric host IDs"),
    ) -> dict[str, dict[str, str]]:
        """Resolve the raw numeric IDs stored on suspicious paths back to entity names."""
        names = live.entity_names()

        def resolve(ids_param: str, values: tuple[str, ...]) -> dict[str, str]:
            result: dict[str, str] = {}
            for raw in ids_param.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    index = int(raw)
                except ValueError:
                    continue
                if 0 <= index < len(values):
                    result[raw] = values[index]
            return result

        return {
            "users": resolve(user_ids, names["users"]),
            "hosts": resolve(host_ids, names["hosts"]),
        }

    @app.get(
        "/api/v1/detection-engineering",
        response_model=DetectionEngineeringOverview,
        tags=["detection-engineering"],
    )
    def detection_engineering() -> DetectionEngineeringOverview:
        return build_detection_engineering(detection.store)

    @app.get(
        "/api/v1/alerts/{alert_id}/context",
        response_model=InvestigationContext,
        tags=["investigation"],
    )
    def investigation_context(alert_id: str) -> InvestigationContext:
        try:
            return build_investigation_context(detection.store, alert_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="alert not found") from error

    @app.get("/alerts/{alert_id}", response_model=AlertRecord, tags=["investigation"])
    def alert_detail(alert_id: str) -> AlertRecord:
        alert = detection.store.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return alert

    @app.get("/paths/{path_id}", tags=["investigation"])
    def path_detail(path_id: str) -> dict[str, object]:
        path = detection.store.get_path(path_id)
        if path is None:
            raise HTTPException(status_code=404, detail="path not found")
        return path.to_dict()

    def _stamp_triage_provenance(response: Response) -> None:
        """Attach the authoring engine to the response.

        Sent as headers rather than body fields so the strict, frozen
        TriageReport schema (and every test asserting on it) is untouched,
        while the console can still label whether an analyst is reading
        deterministic template output or model-generated prose.
        """
        provenance = getattr(detection, "last_triage_provenance", None) or {}
        if not provenance:
            return
        response.headers["X-Triage-Provider"] = str(provenance.get("provider", "unknown"))
        response.headers["X-Triage-Fallback"] = "1" if provenance.get("fallback") else "0"
        response.headers["X-Triage-Trace"] = str(provenance.get("trace", "-"))[:200]

    def _stamp_soc_provenance(response: Response) -> None:
        """Which engine wrote this handover report, in the same headers."""
        provenance = getattr(detection, "last_soc_provenance", None) or {}
        if not provenance:
            return
        response.headers["X-Triage-Provider"] = str(provenance.get("provider", "unknown"))
        response.headers["X-Triage-Fallback"] = "1" if provenance.get("fallback") else "0"
        response.headers["X-Triage-Trace"] = str(provenance.get("trace", "-"))[:200]

    @app.get("/api/v1/paths/{path_id}/explain", tags=["product-console"])
    def explain_path_endpoint(path_id: str) -> dict[str, object]:
        """Grounded prose explanation of one ranked attack path.

        Uses the same discipline as alert triage: the model may only restate
        facts from the path record, an explanation naming any host or account
        outside that path is rejected, and a deterministic template is served
        if the model is unavailable or cannot stay grounded.
        """
        from graphsentinel.explain.path_agent import explain_path, facts_from_payload

        record = detection.store.get_path(path_id)
        if record is None:
            raise HTTPException(status_code=404, detail="path not found")
        payload = record.to_dict()

        # Resolve numeric IDs to the names the analyst sees, so the model
        # reasons over the same labels shown in the console. Reuses the same
        # live.entity_names() source the /entity-names endpoint serves, rather
        # than re-reading the id-map files independently.
        def _resolve(ids: list[int], values: tuple[str, ...], prefix: str) -> list[str]:
            return [
                values[i] if 0 <= i < len(values) else f"{prefix}#{i}"
                for i in ids
            ]

        try:
            names = live.entity_names()
            host_names = _resolve(list(payload.get("host_ids", [])), names["hosts"], "Host")
            user_names = _resolve(list(payload.get("user_ids", [])), names["users"], "User")
        except Exception:  # noqa: BLE001 - names are a nicety, not a requirement
            host_names = [f"Host#{i}" for i in payload.get("host_ids", [])]
            user_names = [f"User#{i}" for i in payload.get("user_ids", [])]

        generate = None
        if os.getenv("GRAPHSENTINEL_TRIAGE_AGENT", "").strip().lower() in {"1", "true", "on"}:
            try:
                from graphsentinel.explain.agent import AgentConfig, ollama_generate

                config = AgentConfig(
                    model=os.getenv("GRAPHSENTINEL_OLLAMA_MODEL", "qwen3.5:4b"),
                    host=os.getenv("GRAPHSENTINEL_OLLAMA_HOST", "http://127.0.0.1:11434"),
                )
                generate = lambda prompt: ollama_generate(prompt, config=config)  # noqa: E731
            except Exception:  # noqa: BLE001
                generate = None

        facts = facts_from_payload(payload, host_names, user_names)
        text, used_fallback = explain_path(facts, generate=generate)
        return {
            "path_id": path_id,
            "explanation": text,
            "generated_by": "deterministic-template" if used_fallback else "langgraph-ollama",
            "grounded_entities": [*host_names, *user_names],
        }

    @app.post("/triage/{alert_id}", response_model=AlertRecord, tags=["investigation"])
    def triage(alert_id: str, response: Response) -> AlertRecord:
        try:
            record = detection.triage(alert_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="alert not found") from error
        _stamp_triage_provenance(response)
        return record

    @app.post(
        "/api/v1/alerts/{alert_id}/triage",
        response_model=AlertRecord,
        tags=["product-console"],
    )
    def product_triage(alert_id: str, response: Response) -> AlertRecord:
        try:
            record = detection.triage(alert_id)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="alert not found") from error
        _stamp_triage_provenance(response)
        return record

    # ── SOC incident reports ──────────────────────────────────────────────
    # Per-alert triage explains one detection. This is the handover: one
    # account, every alert on it, what the system already did, and what is
    # left for a person -- written over a fact bundle with the same citation
    # contract, by the local model when one is enabled and by the
    # deterministic writer otherwise.
    @app.get("/api/v1/soc/incidents", tags=["product-console"])
    def soc_incidents(
        limit: int = Query(default=20, ge=1, le=100),
        scan: int = Query(default=1000, ge=1, le=5000),
    ) -> dict[str, object]:
        """Accounts worth a report, worst first: escalated, then by risk."""
        incidents = detection.soc_incidents(limit=limit, scan=scan)
        return {"incidents": incidents, "count": len(incidents)}

    @app.get("/api/v1/feedback/labels", tags=["response"])
    def feedback_label_export(
        format: Literal["json", "csv"] = Query(default="json"),
        limit: int = Query(default=10_000, ge=1, le=100_000),
    ) -> Response:
        """Analyst decisions as training labels: approving a disruptive action or
        keeping a lock confirms an alert (1); rejecting every action or lifting
        the system's lock marks it benign (0). Undecided alerts are left out."""
        from graphsentinel.response.feedback import feedback_labels, feedback_rows

        verdicts = feedback_labels(responder.store.all_records())
        rows = feedback_rows(detection.store.list_alerts(limit=limit), verdicts)
        if format == "csv":
            import csv
            import io

            buffer = io.StringIO()
            fields = ["alert_id", "event_id", "timestamp", "user", "source_host", "destination_host", "risk",
                      "label", "source", "decided_by", "decided_at"]
            writer = csv.DictWriter(buffer, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            return PlainTextResponse(buffer.getvalue(), media_type="text/csv", headers={
                "Content-Disposition": 'attachment; filename="graphsentinel_feedback_labels.csv"'})
        return JSONResponse({
            "labels": rows,
            "confirmed": sum(1 for r in rows if r["label"] == 1),
            "benign": sum(1 for r in rows if r["label"] == 0),
        })

    @app.get("/api/v1/soc/reports", tags=["product-console"])
    def soc_auto_reports() -> dict[str, object]:
        """Incident reports written automatically for locked accounts, newest first."""
        return {"enabled": auto_reports_enabled, **auto_reports.summary()}

    @app.get("/api/v1/soc/reports/{account}", tags=["product-console"])
    def soc_auto_report(account: str) -> dict[str, object]:
        """The latest automatic report for one account, with its provenance."""
        entry = auto_reports.latest(account)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"no automatic report for {account}")
        return dict(entry)

    @app.post("/api/v1/soc/incidents/{account}/report", tags=["product-console"])
    def soc_incident_report(account: str, response: Response) -> dict[str, object]:
        """Write the handover report for one account (JSON, with Markdown)."""
        try:
            report = detection.soc_report(account)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail=f"no alerts for {account}"
            ) from error
        _stamp_soc_provenance(response)
        payload = json.loads(report.model_dump_json())
        payload["markdown"] = report.to_markdown()
        return dict(payload)

    @app.get("/api/v1/soc/incidents/{account}/report.md", tags=["product-console"])
    def soc_incident_report_markdown(account: str, response: Response) -> PlainTextResponse:
        """The same report as Markdown, for pasting into a ticket."""
        try:
            report = detection.soc_report(account)
        except KeyError as error:
            raise HTTPException(
                status_code=404, detail=f"no alerts for {account}"
            ) from error
        text = PlainTextResponse(report.to_markdown(), media_type="text/markdown")
        _stamp_soc_provenance(text)
        text.headers["Content-Disposition"] = (
            f'attachment; filename="{report.incident_id}.md"'
        )
        return text

    @app.patch(
        "/api/v1/alerts/{alert_id}/status",
        response_model=AlertRecord,
        tags=["product-console"],
    )
    def product_status(alert_id: str, request: AlertStatusUpdate) -> AlertRecord:
        try:
            return detection.store.update_status(alert_id, request.status)
        except KeyError as error:
            raise HTTPException(status_code=404, detail="alert not found") from error

    @app.get("/metrics", tags=["operations"])
    def metrics() -> dict[str, object]:
        return {
            "repository": detection.store.metrics(),
            "runtime": detection.monitor.snapshot().to_dict(),
            "live": live.status().model_dump(),
            "training": training.status().model_dump(),
            "phase16": phase16.status().model_dump(),
            "model_loaded": detection.model_loaded,
        }

    @app.get("/metrics/prometheus", response_class=PlainTextResponse, tags=["operations"])
    def prometheus_metrics() -> str:
        repository = detection.store.metrics()
        runtime = detection.monitor.snapshot()
        live_snapshot = live.status()
        training_snapshot = training.status()
        phase16_snapshot = phase16.status()
        phase16_job = phase16_snapshot.job
        values = {
            "graphsentinel_scored_events_total": repository["scored_events"],
            "graphsentinel_alerts_total": repository["alerts"],
            "graphsentinel_paths_total": repository["paths"],
            "graphsentinel_alert_rate": repository["alert_rate"],
            "graphsentinel_requests_total": runtime.requests,
            "graphsentinel_failed_requests_total": runtime.failed_requests,
            "graphsentinel_latency_p95_ms": runtime.latency_ms_p95,
            "graphsentinel_live_events_total": live_snapshot.accepted_events,
            "graphsentinel_live_rejected_batches_total": live_snapshot.rejected_batches,
            "graphsentinel_live_duplicate_batches_total": live_snapshot.duplicate_batches,
            "graphsentinel_live_oov_identifiers_total": sum(live_snapshot.oov_identifiers.values()),
            "graphsentinel_live_model_generation": live_snapshot.model_generation,
            "graphsentinel_live_model_contract_ready": int(live_snapshot.model_contract_ready),
            "graphsentinel_live_state_resets_total": live_snapshot.state_reset_count,
            "graphsentinel_training_running": int(training_snapshot.state == "running"),
            "graphsentinel_training_progress_ratio": training_snapshot.progress,
            "graphsentinel_phase16_running": int(
                phase16_job is not None and phase16_job.state in {"queued", "running"}
            ),
            "graphsentinel_phase16_progress_ratio": (
                phase16_job.progress if phase16_job is not None else 0
            ),
            "graphsentinel_phase16_real_data_verified": int(
                phase16_snapshot.provenance.mode == "real"
            ),
            "graphsentinel_phase16_checkpoint_ready": int(phase16_snapshot.checkpoint is not None),
        }
        return "\n".join(f"{name} {value}" for name, value in values.items()) + "\n"

    return app


app = create_app()
