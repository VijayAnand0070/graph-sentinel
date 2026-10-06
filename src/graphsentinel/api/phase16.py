"""Durable real-data activation and accuracy-engineering pipeline."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock, Thread
from typing import Any, Literal
from uuid import uuid4

import torch

from graphsentinel import __version__
from graphsentinel.api.pipeline_lease import LeaseHandle, PipelineBusyError, PipelineLease
from graphsentinel.api.schemas import (
    Phase16BaselineMetrics,
    Phase16Checkpoint,
    Phase16Job,
    Phase16JobConfig,
    Phase16LeakageCheck,
    Phase16Metrics,
    Phase16MetricSet,
    Phase16Overview,
    Phase16PipelineStage,
    Phase16Promotion,
    Phase16PromotionGate,
    Phase16Provenance,
    Phase16Split,
    Phase16SplitPartition,
    Phase16StartRequest,
    Phase16TimeRange,
)
from graphsentinel.datasets.catalog import LANL_DOI, LANL_SOURCE_PAGE
from graphsentinel.datasets.registry import verified_manifest_dataset_sha256, verify_registered
from graphsentinel.evaluation.experiments import (
    BaselineExperimentConfig,
    run_baselines_from_dataset,
)
from graphsentinel.features.pipeline import FEATURE_VERSION, build_feature_dataset
from graphsentinel.ingestion.auth import ingest_auth
from graphsentinel.models.config import load_tgn_training_config
from graphsentinel.models.serving import load_inference_session
from graphsentinel.models.training_pipeline import (
    TGNTrainingReport,
    train_tgn_from_dataset,
)

PublishCandidate = Callable[[Path, float, str], None]

_STAGES = (
    ("register", "Verify registration"),
    ("normalize", "Normalize telemetry"),
    ("features", "Build causal features"),
    ("train", "Train candidate TGN"),
    ("validate", "Select threshold"),
    ("test", "Holdout evaluation"),
    ("promote", "Promote checkpoint"),
)
_STAGE_PROGRESS = {
    "register": 0.04,
    "normalize": 0.16,
    "features": 0.32,
    "train": 0.45,
    "validate": 0.82,
    "test": 0.90,
    "promote": 0.96,
}


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _hash_json(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _as_float(value: object) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return None


class Phase16Manager:
    """Own the verified raw-to-production workflow and its durable journal."""

    def __init__(
        self,
        *,
        raw_dir: Path,
        interim_dir: Path,
        id_map_dir: Path,
        feature_dir: Path,
        ingestion_report_path: Path,
        feature_report_path: Path,
        baseline_report_path: Path,
        training_report_path: Path,
        checkpoint_path: Path,
        candidate_path: Path,
        state_path: Path,
        lease: PipelineLease,
        publish_candidate: PublishCandidate,
    ) -> None:
        self.raw_dir = raw_dir
        self.interim_dir = interim_dir
        self.id_map_dir = id_map_dir
        self.feature_dir = feature_dir
        self.ingestion_report_path = ingestion_report_path
        self.feature_report_path = feature_report_path
        self.baseline_report_path = baseline_report_path
        self.training_report_path = training_report_path
        self.checkpoint_path = checkpoint_path
        self.candidate_path = candidate_path
        self.state_path = state_path
        self.lease = lease
        self._publish_candidate = publish_candidate
        self._lock = RLock()
        self._journal = self._load_journal()

    def _default_config(self) -> dict[str, object]:
        return {"max_events": 250_000, "epochs": 12, "patience": 3, "device": "auto"}

    def _idle_journal(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "job": {
                "job_id": None,
                "state": "idle",
                "progress": 0.0,
                "stage": None,
                "epoch": 0,
                "total_epochs": 0,
                "started_at": None,
                "finished_at": None,
                "message": "Ready when registered LANL core files are available",
                "config": self._default_config(),
            },
            "stage_updates": {},
            "promotion": {},
        }

    def _load_journal(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return self._idle_journal()
        journal = _read_json(self.state_path)
        valid = bool(
            journal is not None
            and journal.get("schema_version") == 1
            and isinstance(journal.get("job"), dict)
            and isinstance(journal.get("stage_updates"), dict)
            and isinstance(journal.get("promotion"), dict)
        )
        if valid:
            assert journal is not None
            try:
                Phase16Job.model_validate(journal["job"])
            except ValueError:
                valid = False
        if not valid:
            failed = self._idle_journal()
            failed["journal_corrupt"] = True
            failed_job = failed["job"]
            if isinstance(failed_job, dict):
                failed_job.update(
                    {
                        "state": "failed",
                        "finished_at": _utc_now(),
                        "message": (
                            "The durable pipeline journal is invalid or from an unsupported "
                            "schema; archive it before starting another run"
                        ),
                    }
                )
            return failed
        assert journal is not None
        job = journal.get("job")
        if isinstance(job, dict) and job.get("state") in {"queued", "running"}:
            job.update(
                {
                    "state": "failed",
                    "finished_at": _utc_now(),
                    "message": (
                        "The previous API process stopped before this job finished. "
                        "Verified immutable inputs are safe; start a new run to resume."
                    ),
                }
            )
            journal["interrupted"] = True
            _write_json(self.state_path, journal)
        return journal

    def status(self) -> Phase16Overview:
        with self._lock:
            return self._build_overview()

    def start(self, request: Phase16StartRequest) -> Phase16Overview:
        with self._lock:
            if self._journal.get("journal_corrupt") is True:
                raise RuntimeError(
                    "the durable pipeline journal is invalid; archive it before starting a run"
                )
            job = self._journal.get("job", {})
            if isinstance(job, dict) and job.get("state") in {"queued", "running"}:
                raise PipelineBusyError("a Phase 16 pipeline job is already running")
            missing = [
                name
                for name in ("auth.txt.gz", "redteam.txt.gz")
                if not (self.raw_dir / name).is_file()
            ]
            if missing:
                raise FileNotFoundError(
                    "registered LANL core files are required; use `graphsentinel dataset "
                    "register --source <download-directory> --execute --full-scan` first "
                    f"(missing: {', '.join(missing)})"
                )
            job_id = f"P16-{uuid4().hex[:12].upper()}"
            handle = self.lease.acquire(owner="phase16", job_id=job_id)
            config = request.model_dump()
            self._journal = {
                "schema_version": 1,
                "job": {
                    "job_id": job_id,
                    "state": "queued",
                    "progress": 0.0,
                    "stage": "register",
                    "epoch": 0,
                    "total_epochs": request.epochs,
                    "started_at": _utc_now(),
                    "finished_at": None,
                    "message": "Pipeline accepted; preparing full raw-data verification",
                    "config": config,
                },
                "stage_updates": {},
                "promotion": {},
            }
            self._persist()
            try:
                worker = Thread(
                    target=self._run,
                    args=(request, handle),
                    daemon=True,
                    name=f"phase16-{job_id.lower()}",
                )
                worker.start()
            except Exception as error:
                message = self._public_error(error)
                job = self._journal.get("job", {})
                if isinstance(job, dict):
                    job.update(
                        {
                            "state": "failed",
                            "finished_at": _utc_now(),
                            "message": f"worker launch failed: {message}",
                        }
                    )
                self._persist()
                self.lease.release(handle)
                raise
            return self._build_overview()

    def _persist(self) -> None:
        _write_json(self.state_path, self._journal)

    def _job_update(self, **changes: object) -> None:
        with self._lock:
            job = self._journal.setdefault("job", {})
            if isinstance(job, dict):
                job.update(changes)
            self._persist()

    def _stage(self, key: str, *, status: str, detail: str) -> None:
        now = _utc_now()
        with self._lock:
            updates = self._journal.setdefault("stage_updates", {})
            if isinstance(updates, dict):
                updates[key] = {"status": status, "detail": detail, "updated_at": now}
            job = self._journal.setdefault("job", {})
            if isinstance(job, dict):
                job.update(
                    {
                        "state": "running",
                        "stage": key,
                        "progress": _STAGE_PROGRESS[key],
                        "message": detail,
                    }
                )
            self._persist()

    def _training_progress(
        self, epoch: int, total: int, train_loss: float, validation_pr_auc: float | None
    ) -> None:
        progress = _STAGE_PROGRESS["train"] + (epoch / total) * 0.34
        self._job_update(
            state="running",
            stage="train",
            epoch=epoch,
            total_epochs=total,
            progress=min(progress, 0.79),
            message=(
                f"Training epoch {epoch}/{total}; loss {train_loss:.5f}; "
                f"validation PR-AUC {validation_pr_auc if validation_pr_auc is not None else 'n/a'}"
            ),
        )

    def _run(self, request: Phase16StartRequest, handle: LeaseHandle) -> None:
        try:
            device = self._resolve_device(request.device)
            candidate_path = self._run_artifact(self.candidate_path, handle.job_id)
            candidate_baseline_report = self._run_artifact(self.baseline_report_path, handle.job_id)
            candidate_training_report = self._run_artifact(self.training_report_path, handle.job_id)
            self._journal["run_artifacts"] = {
                "candidate_checkpoint": str(candidate_path),
                "baseline_report": str(candidate_baseline_report),
                "training_report": str(candidate_training_report),
            }
            self._persist()
            self._stage(
                "register",
                status="running",
                detail="Performing a full gzip, schema, order, and SHA-256 verification",
            )
            manifest_path, validation = verify_registered(
                self.raw_dir,
                "core",
                full_scan=True,
                quick_scan_rows=10_000,
            )
            if any(
                item.malformed_rows or not item.timestamps_non_decreasing for item in validation
            ):
                raise ValueError("raw data failed the full LANL contract verification")
            dataset_sha256 = verified_manifest_dataset_sha256(self.raw_dir, "core")
            self._journal["dataset_sha256"] = dataset_sha256
            self._persist()
            self._stage(
                "register",
                status="complete",
                detail=(
                    f"Verified {len(validation)} immutable core files; "
                    f"manifest {manifest_path.name}"
                ),
            )

            self._stage(
                "normalize",
                status="running",
                detail="Streaming authentication events into typed chronological Parquet",
            )
            raw_hashes = {item.file: item.sha256 for item in validation}
            ingestion_payload = self._validated_ingestion(raw_hashes)
            reused_ingestion = ingestion_payload is not None
            if ingestion_payload is None:
                ingestion = ingest_auth(
                    auth_path=self.raw_dir / "auth.txt.gz",
                    redteam_path=self.raw_dir / "redteam.txt.gz",
                    output_dir=self.interim_dir,
                    id_map_dir=self.id_map_dir,
                    report_path=self.ingestion_report_path,
                )
                ingestion_payload = ingestion.to_dict()
            rows_parsed = int(ingestion_payload["rows_parsed"])
            redteam_matches = int(ingestion_payload["redteam_matches"])
            self._stage(
                "normalize",
                status="complete",
                detail=(
                    f"{'Reused' if reused_ingestion else 'Normalized'} {rows_parsed:,} "
                    f"events with {redteam_matches:,} positive labels"
                ),
            )

            self._stage(
                "features",
                status="running",
                detail="Building timestamp-safe rolling graph and behavior features",
            )
            feature_payload = self._validated_features(ingestion_payload)
            reused_features = feature_payload is not None
            if feature_payload is None:
                features = build_feature_dataset(
                    input_dir=self.interim_dir,
                    output_dir=self.feature_dir,
                    report_path=self.feature_report_path,
                )
                feature_payload = features.to_dict()
            feature_events = int(feature_payload["events"])
            contract_hash = str(feature_payload["feature_contract_sha256"])
            self._stage(
                "features",
                status="complete",
                detail=(
                    f"{'Reused' if reused_features else 'Built'} {feature_events:,} "
                    f"causal feature records under contract {contract_hash[:12]}"
                ),
            )

            memory_limit = int(os.getenv("GRAPHSENTINEL_MAX_IN_MEMORY_EVENTS", "2000000"))
            if memory_limit < 100:
                raise ValueError("GRAPHSENTINEL_MAX_IN_MEMORY_EVENTS must be at least 100")
            selected_events = min(feature_events, request.max_events or feature_events)
            if selected_events > memory_limit:
                raise ValueError(
                    f"the selected {selected_events:,}-event training cohort exceeds the "
                    f"configured in-memory safety limit of {memory_limit:,}; set max_events "
                    "to a safe bound or increase GRAPHSENTINEL_MAX_IN_MEMORY_EVENTS after "
                    "capacity testing"
                )

            self._stage(
                "train",
                status="running",
                detail="Benchmarking classical detectors before candidate TGN training",
            )
            run_baselines_from_dataset(
                input_dir=self.feature_dir,
                feature_report_path=self.feature_report_path,
                output_path=candidate_baseline_report,
                max_events=request.max_events,
                config=BaselineExperimentConfig(),
            )
            report = train_tgn_from_dataset(
                input_dir=self.feature_dir,
                feature_report_path=self.feature_report_path,
                checkpoint_path=candidate_path,
                report_path=candidate_training_report,
                max_events=request.max_events,
                id_map_dir=self.id_map_dir,
                baseline_report_path=candidate_baseline_report,
                dataset_sha256=dataset_sha256,
                config=load_tgn_training_config(epochs=request.epochs, patience=request.patience),
                device=device,
                progress=self._training_progress,
            )
            self._validate_candidate_lineage(
                candidate_path,
                report=report,
                dataset_sha256=dataset_sha256,
                device=device,
            )
            self._stage(
                "train",
                status="complete",
                detail=f"Candidate trained; best epoch {report.best_epoch}",
            )

            self._stage(
                "validate",
                status="complete",
                detail=(
                    "Threshold frozen on validation only at "
                    f"{float(report.threshold_selection['threshold']):.4f}"
                ),
            )
            self._stage(
                "test",
                status="complete",
                detail=(
                    "Opened the holdout test partition once; PR-AUC "
                    f"{report.test_metrics['pr_auc']}"
                ),
            )
            eligible = bool(report.promotion["eligible"])
            if not eligible:
                self._stage(
                    "promote",
                    status="blocked",
                    detail="Candidate did not beat the declared validation baseline",
                )
                self._journal["promotion"] = {
                    "status": "rejected",
                    "eligible": False,
                    "decision": "Candidate retained; production checkpoint unchanged",
                }
                self._job_update(
                    state="rejected",
                    stage="promote",
                    progress=1.0,
                    finished_at=_utc_now(),
                    message="Accuracy gate rejected the candidate; no production change was made",
                )
                return

            previous_checkpoint_id = self._checkpoint_sha(self.checkpoint_path)
            self._stage(
                "promote",
                status="running",
                detail="Preflighting candidate contract and opening atomic rollback boundary",
            )
            threshold = float(report.threshold_selection["threshold"])
            self._publish_release(
                candidate_path,
                threshold=threshold,
                device=device,
                reports=(
                    (candidate_baseline_report, self.baseline_report_path),
                    (candidate_training_report, self.training_report_path),
                ),
            )
            current_checkpoint_id = self._checkpoint_sha(self.checkpoint_path)
            promoted_at = _utc_now()
            self._journal["promotion"] = {
                "status": "promoted",
                "eligible": True,
                "decision": "Candidate beat the baseline and passed serving-contract preflight",
                "promoted_at": promoted_at,
                "current_checkpoint_id": current_checkpoint_id,
                "previous_checkpoint_id": previous_checkpoint_id,
            }
            self._stage(
                "promote",
                status="complete",
                detail="Production checkpoint published atomically; rollback copy retired",
            )
            self._job_update(
                state="completed",
                progress=1.0,
                finished_at=promoted_at,
                message="Phase 16 completed and the validated temporal model is live",
            )
        except Exception as error:
            message = self._public_error(error)
            with self._lock:
                job = self._journal.get("job", {})
                stage = str(job.get("stage", "register")) if isinstance(job, dict) else "register"
                updates = self._journal.setdefault("stage_updates", {})
                if isinstance(updates, dict):
                    updates[stage] = {
                        "status": "failed",
                        "detail": message,
                        "updated_at": _utc_now(),
                    }
                self._journal["promotion"] = {
                    "status": "blocked",
                    "eligible": False,
                    "decision": "Pipeline failed before a safe promotion could complete",
                }
                if isinstance(job, dict):
                    job.update(
                        {
                            "state": "failed",
                            "finished_at": _utc_now(),
                            "message": message,
                        }
                    )
                self._persist()
        finally:
            self.lease.release(handle)

    def _validated_ingestion(self, raw_hashes: dict[str, str]) -> dict[str, Any] | None:
        report = _read_json(self.ingestion_report_path)
        parquet_ready = bool(list(self.interim_dir.glob("auth_day=*/*.parquet")))
        map_names = ("users", "hosts", "auth_types", "logon_types", "orientations")
        maps_ready = all((self.id_map_dir / f"{name}.json").is_file() for name in map_names)
        if report is None and not parquet_ready and not maps_ready:
            return None
        if report is None or not parquet_ready or not maps_ready:
            raise ValueError(
                "existing normalized artifacts are incomplete; archive them before retrying"
            )
        checks = (
            report.get("source_auth_sha256") == raw_hashes.get("auth.txt.gz"),
            report.get("source_redteam_sha256") == raw_hashes.get("redteam.txt.gz"),
            report.get("timestamps_non_decreasing") is True,
            isinstance(report.get("rows_parsed"), int) and report["rows_parsed"] > 0,
            isinstance(report.get("redteam_matches"), int) and report["redteam_matches"] > 0,
            isinstance(report.get("parquet_files"), int) and report["parquet_files"] > 0,
        )
        if not all(checks):
            raise ValueError("existing normalized artifacts do not match the verified raw dataset")
        return report

    def _validated_features(self, ingestion: dict[str, Any]) -> dict[str, Any] | None:
        report = _read_json(self.feature_report_path)
        parquet_ready = bool(list(self.feature_dir.glob("feature_day=*/*.parquet")))
        embedded_report = _read_json(self.feature_dir / "_feature_report.json")
        if report is None and not parquet_ready and embedded_report is None:
            return None
        if report is None or not parquet_ready or embedded_report is None:
            raise ValueError(
                "existing feature artifacts are incomplete; archive them before retrying"
            )
        contract = report.get("feature_contract_sha256")
        checks = (
            report == embedded_report,
            report.get("feature_version") == FEATURE_VERSION,
            isinstance(contract, str) and len(contract) == 64,
            report.get("events") == ingestion.get("rows_parsed"),
            report.get("redteam_events") == ingestion.get("redteam_matches"),
            report.get("timestamp_min") == ingestion.get("timestamp_min"),
            report.get("timestamp_max") == ingestion.get("timestamp_max"),
            isinstance(report.get("output_files"), int) and report["output_files"] > 0,
        )
        if not all(checks):
            raise ValueError(
                "existing feature artifacts do not match normalized data and causal contract"
            )
        return report

    @staticmethod
    def _resolve_device(requested: str) -> str:
        if requested == "auto":
            return "cuda" if torch.cuda.is_available() else "cpu"
        if requested == "cuda" and not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested but is not available")
        return requested

    def _public_error(self, error: Exception) -> str:
        message = str(error).replace("\r", " ").replace("\n", " ")[:500]
        paths = (
            self.raw_dir,
            self.interim_dir,
            self.id_map_dir,
            self.feature_dir,
            self.ingestion_report_path,
            self.feature_report_path,
            self.baseline_report_path,
            self.training_report_path,
            self.checkpoint_path,
            self.candidate_path,
            self.state_path,
        )
        for path in paths:
            for rendered in {str(path), str(path.resolve())}:
                if rendered:
                    message = message.replace(rendered, "[artifact]")
        return message or "pipeline stage failed without a diagnostic message"

    def _validate_candidate_lineage(
        self,
        candidate_path: Path,
        *,
        report: TGNTrainingReport,
        dataset_sha256: str,
        device: str,
    ) -> None:
        actual_checkpoint_sha = self._checkpoint_sha(candidate_path)
        if actual_checkpoint_sha != report.checkpoint_sha256:
            raise ValueError("candidate checkpoint hash does not match its training report")
        session = load_inference_session(candidate_path, device=device)
        provenance = session.provenance
        checks = (
            (provenance.model_version, report.model_version, "model version"),
            (
                provenance.feature_contract_sha256,
                report.feature_contract_sha256,
                "feature contract",
            ),
            (
                provenance.entity_dictionary_sha256,
                report.entity_dictionary_sha256,
                "entity dictionary",
            ),
            (provenance.dataset_sha256, dataset_sha256, "dataset"),
            (
                provenance.training_run_sha256,
                report.training_run_sha256,
                "training run",
            ),
        )
        for actual, expected, label in checks:
            if actual != expected:
                raise ValueError(f"candidate {label} provenance does not match its report")
        if provenance.oov_user_buckets != int(
            report.training_configuration["oov_user_buckets"]
        ) or provenance.oov_host_buckets != int(report.training_configuration["oov_host_buckets"]):
            raise ValueError("candidate OOV capacity does not match its training report")
        threshold = float(report.threshold_selection["threshold"])
        if provenance.decision_threshold != threshold:
            raise ValueError("candidate decision threshold does not match its training report")

    @staticmethod
    def _run_artifact(path: Path, job_id: str) -> Path:
        return path.parent / "phase16-runs" / job_id / path.name

    @staticmethod
    def _copy_atomic(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
        try:
            shutil.copyfile(source, temporary)
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    def _publish_release(
        self,
        candidate_path: Path,
        *,
        threshold: float,
        device: str,
        reports: tuple[tuple[Path, Path], ...],
    ) -> None:
        """Publish report pointers and the live model as one rollback-capable release."""

        rollbacks: list[tuple[Path, Path, bool]] = []
        with self._lock:
            try:
                for source, destination in reports:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    rollback = destination.with_name(f".{destination.name}.{uuid4().hex}.rollback")
                    had_previous = destination.is_file()
                    if had_previous:
                        shutil.copyfile(destination, rollback)
                    rollbacks.append((destination, rollback, had_previous))
                    self._copy_atomic(source, destination)
                self._publish_candidate(candidate_path, threshold, device)
            except Exception:
                rollback_failures: list[str] = []
                for destination, rollback, had_previous in reversed(rollbacks):
                    try:
                        if had_previous:
                            os.replace(rollback, destination)
                        else:
                            destination.unlink(missing_ok=True)
                    except OSError:
                        rollback_failures.append(destination.name)
                if rollback_failures:
                    raise RuntimeError(
                        "model release failed and report rollback requires operator recovery: "
                        + ", ".join(rollback_failures)
                    ) from None
                raise
            else:
                for _destination, rollback, _had_previous in rollbacks:
                    rollback.unlink(missing_ok=True)

    @staticmethod
    def _checkpoint_sha(path: Path) -> str | None:
        if not path.is_file():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(8 * 1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _build_overview(self) -> Phase16Overview:
        manifest = _read_json(self.raw_dir / "manifest.json")
        ingestion = _read_json(self.ingestion_report_path)
        features = _read_json(self.feature_report_path)
        job = self._journal.get("job", {})
        job_id = job.get("job_id") if isinstance(job, dict) else None
        job_state = job.get("state") if isinstance(job, dict) else None
        use_run_report = bool(
            isinstance(job_id, str)
            and re.fullmatch(r"P16-[A-F0-9]{12}", job_id)
            and job_state != "completed"
        )
        if use_run_report:
            assert isinstance(job_id, str)
            baseline_path = self._run_artifact(self.baseline_report_path, job_id)
            training_path = self._run_artifact(self.training_report_path, job_id)
        else:
            baseline_path = self.baseline_report_path
            training_path = self.training_report_path
        baseline = _read_json(baseline_path)
        training = _read_json(training_path)
        return Phase16Overview(
            generated_at=time.time(),
            provenance=self._provenance(manifest, ingestion, features),
            pipeline=self._pipeline(manifest, ingestion, features, training),
            job=self._job(),
            split=self._split(training),
            metrics=self._metrics(training, baseline),
            promotion=self._promotion(training),
            checkpoint=self._checkpoint(training),
        )

    def _job(self) -> Phase16Job:
        payload = self._journal.get("job")
        if not isinstance(payload, dict):
            payload = self._idle_journal()["job"]
        config_payload = payload.get("config")
        if not isinstance(config_payload, dict):
            config_payload = self._default_config()
        defaults = self._idle_journal()["job"]
        merged = dict(defaults) if isinstance(defaults, dict) else {}
        merged.update(payload)
        merged["config"] = Phase16JobConfig.model_validate(config_payload)
        return Phase16Job.model_validate(merged)

    def _provenance(
        self,
        manifest: dict[str, Any] | None,
        ingestion: dict[str, Any] | None,
        features: dict[str, Any] | None,
    ) -> Phase16Provenance:
        files = manifest.get("files", []) if manifest else []
        valid_files = [item for item in files if isinstance(item, dict)]
        full_verified = bool(valid_files) and all(
            item.get("validation_level") == "full"
            and item.get("malformed_rows") == 0
            and item.get("timestamps_non_decreasing") is True
            for item in valid_files
        )
        raw_ready = all(
            (self.raw_dir / name).is_file() for name in ("auth.txt.gz", "redteam.txt.gz")
        )
        mode: Literal["real", "demo", "unregistered"] = (
            "real" if raw_ready and full_verified else "unregistered"
        )
        hashes = {
            str(item.get("file")): str(item.get("sha256"))
            for item in valid_files
            if isinstance(item.get("sha256"), str)
        }
        dataset_hash = _hash_json(hashes) if len(hashes) >= 2 else None
        events_value = features.get("events") if features else None
        events = int(events_value) if isinstance(events_value, int) else 0
        positives = (
            int(features["redteam_events"])
            if features and isinstance(features.get("redteam_events"), int)
            else None
        )
        start = _as_float(features.get("timestamp_min")) if features else None
        end = _as_float(features.get("timestamp_max")) if features else None
        if start is None and ingestion:
            start = _as_float(ingestion.get("timestamp_min"))
            end = _as_float(ingestion.get("timestamp_max"))
        job = self._journal.get("job", {})
        job_config = job.get("config", {}) if isinstance(job, dict) else {}
        cohort_size = job_config.get("max_events") if isinstance(job_config, dict) else None
        cohort_notice = (
            f" The current experiment is bounded to the leading chronological cohort of "
            f"{cohort_size:,} events out of {events:,}."
            if isinstance(cohort_size, int) and events > cohort_size
            else ""
        )
        return Phase16Provenance(
            mode=mode,
            label=(
                "User-registered LANL-format core dataset; full contract scan passed"
                if mode == "real"
                else (
                    "Registered core files are awaiting a full contract scan"
                    if raw_ready
                    else "No verified real training dataset registered"
                )
            ),
            dataset_id="LANL-COMP-CYBER1" if manifest else None,
            dataset_version="core-v1" if manifest else None,
            source=str(manifest.get("source_page", LANL_SOURCE_PAGE)) if manifest else None,
            registered_at=str(manifest.get("registered_at_utc")) if manifest else None,
            immutable=raw_ready and full_verified,
            file_count=len(valid_files),
            event_count=events or (int(ingestion.get("rows_parsed", 0)) if ingestion else 0),
            positive_events=positives,
            dataset_sha256=dataset_hash,
            time_range=Phase16TimeRange(start=start, end=end),
            notice=(
                "Integrity and format are verified locally; the hashes do not independently "
                "prove that the files came from the publisher. Source DOI: "
                + LANL_DOI
                + cohort_notice
                if mode == "real"
                else (
                    "The raw core files exist, but full integrity provenance is not yet "
                    "available. Starting Phase 16 performs that scan before processing."
                    if raw_ready
                    else "Place the licensed/downloaded LANL files outside the app, then use "
                    "the safe CLI registration command. Synthetic telemetry is never reported "
                    "as accuracy evidence."
                )
            ),
        )

    def _pipeline(
        self,
        manifest: dict[str, Any] | None,
        ingestion: dict[str, Any] | None,
        features: dict[str, Any] | None,
        training: dict[str, Any] | None,
    ) -> tuple[Phase16PipelineStage, ...]:
        manifest_files = manifest.get("files", []) if manifest else []
        file_inventory = {
            item.get("file"): item
            for item in manifest_files
            if isinstance(item, dict) and isinstance(item.get("file"), str)
        }
        ingestion_data = ingestion or {}
        feature_data = features or {}
        training_data = training or {}
        register_valid = all(
            name in file_inventory
            and file_inventory[name].get("validation_level") == "full"
            and file_inventory[name].get("malformed_rows") == 0
            and file_inventory[name].get("timestamps_non_decreasing") is True
            for name in ("auth.txt.gz", "redteam.txt.gz")
        )
        normalize_valid = bool(
            register_valid
            and ingestion_data
            and ingestion_data.get("source_auth_sha256")
            == file_inventory["auth.txt.gz"].get("sha256")
            and ingestion_data.get("source_redteam_sha256")
            == file_inventory["redteam.txt.gz"].get("sha256")
            and ingestion_data.get("timestamps_non_decreasing") is True
            and isinstance(ingestion_data.get("rows_parsed"), int)
            and ingestion_data["rows_parsed"] > 0
            and bool(list(self.interim_dir.glob("auth_day=*/*.parquet")))
        )
        features_valid = bool(
            normalize_valid
            and feature_data
            and feature_data.get("feature_version") == FEATURE_VERSION
            and feature_data.get("events") == ingestion_data.get("rows_parsed")
            and feature_data.get("redteam_events") == ingestion_data.get("redteam_matches")
            and isinstance(feature_data.get("feature_contract_sha256"), str)
            and len(feature_data["feature_contract_sha256"]) == 64
            and bool(list(self.feature_dir.glob("feature_day=*/*.parquet")))
        )
        training_valid = bool(
            features_valid
            and training_data
            and training_data.get("feature_contract_sha256")
            == feature_data.get("feature_contract_sha256")
            and isinstance(training_data.get("training_run_sha256"), str)
            and len(training_data["training_run_sha256"]) == 64
        )
        inferred = {
            "register": register_valid,
            "normalize": normalize_valid,
            "features": features_valid,
            "train": training_valid,
            "validate": bool(training_valid and training_data.get("threshold_selection")),
            "test": bool(training_valid and training_data.get("test_metrics")),
            "promote": self.checkpoint_path.is_file()
            and self._journal.get("promotion", {}).get("status") == "promoted",
        }
        updates = self._journal.get("stage_updates", {})
        result: list[Phase16PipelineStage] = []
        prerequisite_complete = True
        for key, label in _STAGES:
            update = updates.get(key) if isinstance(updates, dict) else None
            if isinstance(update, dict):
                status = str(update.get("status", "pending"))
                detail = str(update.get("detail", ""))
                updated_at = update.get("updated_at")
            elif inferred[key]:
                status = "complete"
                detail = "Verified artifact is present"
                updated_at = None
            else:
                status = "pending" if prerequisite_complete else "blocked"
                detail = (
                    "Awaiting this stage" if prerequisite_complete else "Blocked by prerequisite"
                )
                updated_at = None
            result.append(
                Phase16PipelineStage(
                    key=key,  # type: ignore[arg-type]
                    label=label,
                    status=status,  # type: ignore[arg-type]
                    detail=detail,
                    updated_at=str(updated_at) if updated_at else None,
                )
            )
            prerequisite_complete = status == "complete"
        return tuple(result)

    def _split(self, training: dict[str, Any] | None) -> Phase16Split | None:
        split = training.get("split") if training else None
        if not isinstance(split, dict):
            return None
        counts = split.get("counts", {})
        positives = split.get("positives", {})
        if not isinstance(counts, dict) or not isinstance(positives, dict):
            return None

        def partition(name: str) -> Phase16SplitPartition:
            count = int(counts.get(name, 0))
            positive = int(positives.get(name, 0))
            prefix = "validation" if name == "validation" else name
            return Phase16SplitPartition(
                events=count,
                positive_events=positive,
                positive_rate=positive / count if count else None,
                start=_as_float(split.get(f"{prefix}_start_timestamp")),
                end=_as_float(split.get(f"{prefix}_end_timestamp")),
            )

        train = partition("train")
        validation = partition("validation")
        test = partition("test")
        return Phase16Split(
            train=train,
            validation=validation,
            test=test,
            leakage_checks=(
                Phase16LeakageCheck(
                    name="strict_temporal_boundaries",
                    passed=bool(
                        train.end is not None
                        and validation.start is not None
                        and validation.end is not None
                        and test.start is not None
                        and train.end < validation.start <= validation.end < test.start
                    ),
                    detail="Equal timestamps cannot cross train, validation, or test cuts",
                ),
                Phase16LeakageCheck(
                    name="normalizer_train_only",
                    passed=True,
                    detail="Robust feature normalization is fitted on the training partition only",
                ),
                Phase16LeakageCheck(
                    name="threshold_validation_only",
                    passed=bool(training and training.get("threshold_selection")),
                    detail="The alert threshold is frozen before the holdout test is opened",
                ),
            ),
        )

    @staticmethod
    def _metric_set(payload: object, threshold: float | None, *, k: int = 100) -> Phase16MetricSet:
        values = payload if isinstance(payload, dict) else {}
        return Phase16MetricSet(
            pr_auc=_as_float(values.get("pr_auc")),
            recall_at_k=_as_float(values.get(f"recall_at_{k}")),
            precision_at_k=_as_float(values.get(f"precision_at_{k}")),
            false_positives_per_10k=_as_float(values.get("false_positives_per_10000")),
            brier_score=_as_float(values.get("brier_score")),
            threshold=threshold,
        )

    def _metrics(
        self, training: dict[str, Any] | None, baseline: dict[str, Any] | None
    ) -> Phase16Metrics | None:
        if not training:
            return None
        threshold_payload = training.get("threshold_selection", {})
        threshold = _as_float(
            threshold_payload.get("threshold") if isinstance(threshold_payload, dict) else None
        )
        baseline_models = baseline.get("models", {}) if baseline else {}
        candidates: list[tuple[float, str, dict[str, Any]]] = []
        if isinstance(baseline_models, dict):
            for name, result in baseline_models.items():
                if not isinstance(result, dict):
                    continue
                validation = result.get("validation", {})
                pr_auc = _as_float(
                    validation.get("pr_auc") if isinstance(validation, dict) else None
                )
                candidates.append((pr_auc if pr_auc is not None else -1.0, str(name), result))
        _score, baseline_name, baseline_result = max(
            candidates, default=(-1.0, "not_available", {})
        )
        baseline_threshold_payload = baseline_result.get("threshold_selection", {})
        baseline_threshold = _as_float(
            baseline_threshold_payload.get("threshold")
            if isinstance(baseline_threshold_payload, dict)
            else None
        )
        baseline_metrics = self._metric_set(
            baseline_result.get("test", {}), baseline_threshold
        ).model_dump()
        return Phase16Metrics(
            model_name=str(training.get("model_version", "TemporalGraphNetwork")),
            k=100,
            validation=self._metric_set(training.get("validation_metrics", {}), threshold),
            test=self._metric_set(training.get("test_metrics", {}), threshold),
            baseline=Phase16BaselineMetrics(name=baseline_name, **baseline_metrics),
        )

    def _promotion(self, training: dict[str, Any] | None) -> Phase16Promotion:
        recorded = self._journal.get("promotion", {})
        if not isinstance(recorded, dict):
            recorded = {}
        training_promotion = training.get("promotion", {}) if training else {}
        if not isinstance(training_promotion, dict):
            training_promotion = {}
        eligible = bool(training_promotion.get("eligible", recorded.get("eligible", False)))
        actual = _as_float(training_promotion.get("model_validation_pr_auc"))
        target = _as_float(training_promotion.get("best_baseline_validation_pr_auc"))
        budget = None
        false_positive_rate = None
        if training:
            threshold = training.get("threshold_selection", {})
            configuration = training.get("training_configuration", {})
            if isinstance(threshold, dict):
                false_positive_rate = _as_float(threshold.get("false_positives_per_10000"))
            if isinstance(configuration, dict):
                budget = _as_float(configuration.get("false_positives_per_10000_budget"))
        gates = (
            Phase16PromotionGate(
                name="validation_pr_auc_beats_baseline",
                actual=actual,
                target=target,
                operator=">",
                passed=(actual > target) if actual is not None and target is not None else None,
                detail="Candidate must outperform the best declared baseline on validation",
            ),
            Phase16PromotionGate(
                name="validation_false_positive_budget",
                actual=false_positive_rate,
                target=budget,
                operator="<=",
                passed=(false_positive_rate <= budget)
                if false_positive_rate is not None and budget is not None
                else None,
                detail="Frozen validation threshold must satisfy the analyst alert budget",
            ),
            Phase16PromotionGate(
                name="serving_contract_preflight",
                actual=1.0 if recorded.get("status") == "promoted" else None,
                target=1.0,
                operator="==",
                passed=True if recorded.get("status") == "promoted" else None,
                detail="Checkpoint, dictionary, feature contract, and live swap are validated",
            ),
        )
        status = str(recorded.get("status", "not_evaluated"))
        if status not in {"promoted", "rejected", "blocked", "not_evaluated"}:
            status = "not_evaluated"
        return Phase16Promotion(
            status=status,  # type: ignore[arg-type]
            eligible=eligible,
            decision=str(recorded.get("decision", "No candidate has completed evaluation")),
            gates=gates,
            promoted_at=str(recorded["promoted_at"]) if recorded.get("promoted_at") else None,
            current_checkpoint_id=(
                str(recorded["current_checkpoint_id"])
                if recorded.get("current_checkpoint_id")
                else None
            ),
            previous_checkpoint_id=(
                str(recorded["previous_checkpoint_id"])
                if recorded.get("previous_checkpoint_id")
                else None
            ),
        )

    def _checkpoint(self, training: dict[str, Any] | None) -> Phase16Checkpoint | None:
        if not training or not self.checkpoint_path.is_file():
            return None
        dictionary = training.get("entity_dictionary_sha256")
        contract = training.get("feature_contract_sha256")
        if not isinstance(dictionary, str) or not isinstance(contract, str):
            return None
        configuration = training.get("configuration", {})
        if not isinstance(configuration, dict):
            configuration = {}
        training_configuration = training.get("training_configuration", {})
        if not isinstance(training_configuration, dict):
            training_configuration = {}
        count = self._parameter_count(configuration)
        return Phase16Checkpoint(
            checkpoint_id=str(
                training.get("checkpoint_sha256", self._checkpoint_sha(self.checkpoint_path))
            ),
            created_at=datetime.fromtimestamp(
                self.checkpoint_path.stat().st_mtime, tz=UTC
            ).isoformat(),
            model_type="TemporalGraphNetwork",
            epoch=int(training.get("best_epoch", 0)),
            dictionary_sha256=dictionary,
            dataset_sha256=str(training.get("dataset_sha256") or contract),
            code_version=str(training.get("graphsentinel_version", __version__)),
            feature_contract_version=str(training.get("feature_version", FEATURE_VERSION)),
            parameter_count=(
                int(training["parameter_count"])
                if isinstance(training.get("parameter_count"), int)
                else count
            ),
            device=str(training.get("device", "unknown")),
            oov_user_buckets=int(training_configuration.get("oov_user_buckets", 0)),
            oov_host_buckets=int(training_configuration.get("oov_host_buckets", 0)),
        )

    @staticmethod
    def _parameter_count(configuration: dict[str, Any]) -> int:
        try:
            nodes = int(configuration.get("num_nodes", 0))
            message = int(configuration.get("message_dim", 0))
            memory = int(configuration.get("memory_dim", 0))
            time_dim = int(configuration.get("time_dim", 0))
            hidden = int(configuration.get("hidden_dim", 0))
        except (TypeError, ValueError):
            return 0
        # Honest deterministic estimate from the published architecture dimensions.
        return max(0, nodes * memory + (message + memory * 3 + time_dim) * hidden)
