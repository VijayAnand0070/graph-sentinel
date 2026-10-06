"""Bounded background training orchestration for the product API."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from threading import RLock, Thread
from uuid import uuid4

from graphsentinel.api.pipeline_lease import LeaseHandle, PipelineLease
from graphsentinel.api.schemas import DataReadiness, TrainingStartRequest, TrainingStatus
from graphsentinel.api.service import DetectionService
from graphsentinel.datasets.registry import verified_manifest_dataset_sha256
from graphsentinel.models.config import load_tgn_training_config
from graphsentinel.models.serving import TGNInferenceSession, load_inference_session
from graphsentinel.models.training_pipeline import train_tgn_from_dataset
from graphsentinel.training_status import (
    DEFAULT_EXTERNAL_STATUS_PATH,
    read_external_training_status,
)


class TrainingManager:
    def __init__(
        self,
        detection: DetectionService,
        *,
        input_dir: Path,
        feature_report_path: Path,
        checkpoint_path: Path,
        report_path: Path,
        raw_dir: Path = Path("data/raw/lanl"),
        interim_dir: Path = Path("data/interim"),
        id_map_dir: Path = Path("artifacts/id_maps"),
        validate_model: Callable[[TGNInferenceSession], None] | None = None,
        promote_model: Callable[[TGNInferenceSession, float], None] | None = None,
        pipeline_lease: PipelineLease | None = None,
        external_status_path: Path = DEFAULT_EXTERNAL_STATUS_PATH,
    ) -> None:
        self.detection = detection
        self.input_dir = input_dir
        self.feature_report_path = feature_report_path
        self.checkpoint_path = checkpoint_path
        self.report_path = report_path
        self.raw_dir = raw_dir
        self.interim_dir = interim_dir
        self.id_map_dir = id_map_dir
        self._validate_model = validate_model
        self._promote_model = promote_model
        self._pipeline_lease = pipeline_lease
        # Injectable (rather than always reading the hardcoded default) so
        # tests can point it at an isolated tmp_path instead of picking up
        # whatever a real, concurrently-running CLI training job has written
        # to the real default path.
        self._external_status_path = external_status_path
        self._lease_handle: LeaseHandle | None = None
        self._lock = RLock()
        completed_report = self._verified_completed_report()
        if completed_report is not None:
            self._status = TrainingStatus(
                state="completed",
                epoch=0,
                total_epochs=0,
                progress=1,
                message="Verified promoted checkpoint and matching training report available",
                checkpoint_path=str(self.checkpoint_path),
                report_path=str(self.report_path) if self.report_path.is_file() else None,
                completed_at=int(self.checkpoint_path.stat().st_mtime),
            )
        else:
            self._status = TrainingStatus(
                state="idle",
                epoch=0,
                total_epochs=0,
                progress=0,
                message=(
                    "Checkpoint exists without a verified matching training report; ready to train"
                    if self.checkpoint_path.is_file()
                    else "Ready to train"
                ),
            )

    def _verified_completed_report(self) -> dict[str, object] | None:
        if not self.checkpoint_path.is_file() or not self.report_path.is_file():
            return None
        try:
            report = json.loads(self.report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not isinstance(report, dict):
            return None
        expected_hash = report.get("checkpoint_sha256")
        promotion = report.get("promotion")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            return None
        if not isinstance(promotion, dict) or promotion.get("eligible") is not True:
            return None
        digest = hashlib.sha256()
        with self.checkpoint_path.open("rb") as stream:
            while chunk := stream.read(8 * 1024 * 1024):
                digest.update(chunk)
        return report if digest.hexdigest() == expected_hash else None

    def status(self) -> TrainingStatus:
        with self._lock:
            if self._status.state != "running":
                # No API-triggered job is active — surface a CLI-driven run's
                # progress instead, so `graphsentinel train tgn` run from a
                # terminal shows up live in the dashboard too, not just runs
                # started through /api/v1/training/start.
                external = read_external_training_status(path=self._external_status_path)
                if external is not None:
                    return TrainingStatus(
                        state=external["state"],
                        epoch=external["epoch"],
                        total_epochs=external["total_epochs"],
                        progress=external["progress"],
                        train_loss=external.get("train_loss"),
                        validation_pr_auc=external.get("validation_pr_auc"),
                        message=f"[CLI] {external.get('message') or ''}",
                        checkpoint_path=external.get("checkpoint_path"),
                        report_path=external.get("report_path"),
                        started_at=external.get("started_at"),
                        completed_at=external.get("completed_at"),
                    )
            return self._status

    def data_readiness(self) -> DataReadiness:
        feature_dataset = bool(list(self.input_dir.glob("feature_day=*/*.parquet")))
        feature_report = self.feature_report_path.is_file()
        entity_dictionary = all(
            (self.id_map_dir / f"{name}.json").is_file()
            for name in ("users", "hosts", "auth_types", "logon_types", "orientations")
        )
        return DataReadiness(
            raw_auth_registered=(self.raw_dir / "auth.txt.gz").is_file(),
            raw_labels_registered=(self.raw_dir / "redteam.txt.gz").is_file(),
            normalized_dataset_ready=bool(list(self.interim_dir.glob("auth_day=*/*.parquet"))),
            feature_dataset_ready=feature_dataset,
            feature_report_ready=feature_report,
            entity_dictionary_ready=entity_dictionary,
            checkpoint_ready=self.checkpoint_path.is_file(),
            training_ready=feature_dataset and feature_report and entity_dictionary,
        )

    def start(self, request: TrainingStartRequest) -> TrainingStatus:
        if not self.data_readiness().training_ready:
            raise FileNotFoundError(
                "no processed training dataset; register, ingest, and build features first"
            )
        with self._lock:
            if self._status.state == "running":
                raise RuntimeError("a training job is already running")
            if self._pipeline_lease is not None:
                self._lease_handle = self._pipeline_lease.acquire(
                    owner="legacy-training", job_id=f"legacy-{uuid4().hex[:12]}"
                )
            self._status = TrainingStatus(
                state="running",
                epoch=0,
                total_epochs=request.epochs,
                progress=0,
                message="Loading chronological feature dataset",
                checkpoint_path=str(self.checkpoint_path),
                report_path=str(self.report_path),
                started_at=int(time.time()),
            )
            try:
                worker = Thread(target=self._run, args=(request,), daemon=True, name="tgn-training")
                worker.start()
            except Exception:
                if self._pipeline_lease is not None and self._lease_handle is not None:
                    self._pipeline_lease.release(self._lease_handle)
                    self._lease_handle = None
                raise
            return self._status

    def _progress(
        self, epoch: int, total: int, train_loss: float, validation_pr_auc: float | None
    ) -> None:
        with self._lock:
            self._status = self._status.model_copy(
                update={
                    "epoch": epoch,
                    "total_epochs": total,
                    "progress": epoch / total,
                    "train_loss": train_loss,
                    "validation_pr_auc": validation_pr_auc,
                    "message": f"Training epoch {epoch} of {total}",
                }
            )

    def _run(self, request: TrainingStartRequest) -> None:
        try:
            run_id = f"legacy-{uuid4().hex[:12]}"
            candidate_path = (
                self.checkpoint_path.parent / "training-runs" / run_id / self.checkpoint_path.name
            )
            candidate_report = (
                self.report_path.parent / "training-runs" / run_id / self.report_path.name
            )
            report = train_tgn_from_dataset(
                input_dir=self.input_dir,
                feature_report_path=self.feature_report_path,
                checkpoint_path=candidate_path,
                report_path=candidate_report,
                max_events=request.max_events,
                id_map_dir=self.id_map_dir,
                dataset_sha256=verified_manifest_dataset_sha256(self.raw_dir, "core"),
                config=load_tgn_training_config(epochs=request.epochs, patience=request.patience),
                device=request.device,
                progress=self._progress,
            )
            if not bool(report.promotion["eligible"]):
                with self._lock:
                    self._status = self._status.model_copy(
                        update={
                            "state": "rejected",
                            "epoch": report.epochs_completed,
                            "progress": 1.0,
                            "message": (
                                "Candidate retained but not promoted: validation PR-AUC did "
                                "not beat the declared baselines"
                            ),
                            "checkpoint_path": str(candidate_path),
                            "report_path": str(candidate_report),
                            "completed_at": int(time.time()),
                        }
                    )
                return
            threshold = float(report.threshold_selection["threshold"])
            self._publish_candidate_and_report(
                candidate_path,
                candidate_report,
                threshold=threshold,
                device=request.device,
            )
            with self._lock:
                self._status = self._status.model_copy(
                    update={
                        "state": "completed",
                        "epoch": report.epochs_completed,
                        "progress": 1.0,
                        "message": (f"Model promoted; test PR-AUC {report.test_metrics['pr_auc']}"),
                        "report_path": str(self.report_path),
                        "completed_at": int(time.time()),
                    }
                )
        except Exception as error:
            with self._lock:
                self._status = self._status.model_copy(
                    update={
                        "state": "failed",
                        "message": str(error)[:500],
                        "completed_at": int(time.time()),
                    }
                )
        finally:
            with self._lock:
                if self._pipeline_lease is not None and self._lease_handle is not None:
                    self._pipeline_lease.release(self._lease_handle)
                    self._lease_handle = None

    def publish_candidate(self, candidate_path: Path, *, threshold: float, device: str) -> None:
        """Publish a pre-evaluated candidate through the serving rollback boundary."""

        self._publish_candidate(candidate_path, threshold=threshold, device=device)

    def _publish_candidate_and_report(
        self,
        candidate_path: Path,
        candidate_report: Path,
        *,
        threshold: float,
        device: str,
    ) -> None:
        """Publish a report and checkpoint with rollback of both production pointers."""

        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        report_temporary = self.report_path.with_name(f".{self.report_path.name}.tmp")
        report_rollback = self.report_path.with_name(f".{self.report_path.name}.rollback")
        had_report = self.report_path.is_file()
        with self._lock:
            if had_report:
                shutil.copyfile(self.report_path, report_rollback)
            try:
                shutil.copyfile(candidate_report, report_temporary)
                os.replace(report_temporary, self.report_path)
                self._publish_candidate(candidate_path, threshold=threshold, device=device)
            except Exception:
                if had_report:
                    os.replace(report_rollback, self.report_path)
                else:
                    self.report_path.unlink(missing_ok=True)
                raise
            else:
                report_rollback.unlink(missing_ok=True)
            finally:
                report_temporary.unlink(missing_ok=True)

    def _publish_candidate(self, candidate_path: Path, *, threshold: float, device: str) -> None:
        """Validate, atomically publish, and install a candidate with disk rollback."""

        candidate_session = load_inference_session(candidate_path, device=device)
        if self._validate_model is not None:
            self._validate_model(candidate_session)
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.checkpoint_path.with_name(f".{self.checkpoint_path.name}.tmp")
        rollback = self.checkpoint_path.with_name(f".{self.checkpoint_path.name}.rollback")
        had_previous = self.checkpoint_path.is_file()
        if had_previous:
            shutil.copyfile(self.checkpoint_path, rollback)
        try:
            shutil.copyfile(candidate_path, temporary)
            os.replace(temporary, self.checkpoint_path)
            production_session = load_inference_session(self.checkpoint_path, device=device)
            if self._promote_model is None:
                self.detection.install_model(production_session, threshold=threshold)
            else:
                self._promote_model(production_session, threshold)
        except Exception as promotion_error:
            if had_previous:
                try:
                    os.replace(rollback, self.checkpoint_path)
                except OSError as rollback_error:
                    raise RuntimeError(
                        "model promotion and checkpoint rollback failed; "
                        f"recovery copy retained at {rollback}"
                    ) from rollback_error
            elif self.checkpoint_path.exists():
                self.checkpoint_path.unlink()
            raise promotion_error
        else:
            rollback.unlink(missing_ok=True)
        finally:
            temporary.unlink(missing_ok=True)
