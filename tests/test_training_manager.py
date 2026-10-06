import os
from collections.abc import Callable
from pathlib import Path

import pytest

from graphsentinel.api.service import DetectionService
from graphsentinel.api.training import TrainingManager
from graphsentinel.features.causal import MODEL_FEATURE_NAMES
from graphsentinel.models.serving import TGNInferenceSession
from graphsentinel.models.tgn import TemporalGraphNetwork


def _checkpoint(path: Path, version: str) -> None:
    TemporalGraphNetwork(
        num_nodes=2,
        message_dim=len(MODEL_FEATURE_NAMES),
        memory_dim=4,
        time_dim=2,
        hidden_dim=6,
        dropout=0,
    ).save_checkpoint(
        path,
        metadata={
            "feature_version": "auth-causal-v1",
            "model_version": version,
            "user_capacity": 1,
            "host_capacity": 1,
        },
    )


def _manager(
    tmp_path: Path,
    *,
    promote_model: Callable[[TGNInferenceSession, float], None] | None = None,
    validate_model: Callable[[TGNInferenceSession], None] | None = None,
) -> TrainingManager:
    return TrainingManager(
        DetectionService(),
        input_dir=tmp_path / "features",
        feature_report_path=tmp_path / "features.json",
        checkpoint_path=tmp_path / "production.pt",
        report_path=tmp_path / "training.json",
        promote_model=promote_model,
        validate_model=validate_model,
        # Isolated so a real, concurrently-running CLI training job (which
        # writes to the real default path) can never leak its "running"
        # status into these tests.
        external_status_path=tmp_path / "external-training-status.json",
    )


def test_failed_runtime_promotion_restores_previous_checkpoint(tmp_path: Path) -> None:
    production = tmp_path / "production.pt"
    candidate = tmp_path / "candidate.pt"
    _checkpoint(production, "stable")
    _checkpoint(candidate, "candidate")
    previous = production.read_bytes()

    def reject(_session: TGNInferenceSession, _threshold: float) -> None:
        raise RuntimeError("simulated live promotion failure")

    manager = _manager(tmp_path, promote_model=reject)

    with pytest.raises(RuntimeError, match="simulated live promotion failure"):
        manager._publish_candidate(candidate, threshold=0.6, device="cpu")

    assert production.read_bytes() == previous
    assert not (tmp_path / ".production.pt.tmp").exists()
    assert not (tmp_path / ".production.pt.rollback").exists()


def test_checkpoint_presence_alone_does_not_infer_completed_job(tmp_path: Path) -> None:
    _checkpoint(tmp_path / "production.pt", "untracked")

    status = _manager(tmp_path).status()

    assert status.state == "idle"
    assert "without a verified matching training report" in status.message


def test_candidate_preflight_runs_before_checkpoint_publication(tmp_path: Path) -> None:
    production = tmp_path / "production.pt"
    candidate = tmp_path / "candidate.pt"
    _checkpoint(production, "stable")
    _checkpoint(candidate, "candidate")
    previous = production.read_bytes()
    promoted = False

    def reject_validation(_session: TGNInferenceSession) -> None:
        raise ValueError("dictionary contract rejected")

    def promote(_session: TGNInferenceSession, _threshold: float) -> None:
        nonlocal promoted
        promoted = True

    manager = _manager(tmp_path, promote_model=promote, validate_model=reject_validation)

    with pytest.raises(ValueError, match="dictionary contract rejected"):
        manager._publish_candidate(candidate, threshold=0.6, device="cpu")

    assert production.read_bytes() == previous
    assert promoted is False


def test_failed_checkpoint_restore_retains_recovery_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production = tmp_path / "production.pt"
    candidate = tmp_path / "candidate.pt"
    _checkpoint(production, "stable")
    _checkpoint(candidate, "candidate")
    previous = production.read_bytes()
    original_replace = os.replace

    def guarded_replace(source: str | Path, destination: str | Path) -> None:
        if Path(source).name == ".production.pt.rollback":
            raise OSError("simulated restore failure")
        original_replace(source, destination)

    def reject(_session: TGNInferenceSession, _threshold: float) -> None:
        raise RuntimeError("simulated live promotion failure")

    monkeypatch.setattr(os, "replace", guarded_replace)
    manager = _manager(tmp_path, promote_model=reject)

    with pytest.raises(RuntimeError, match="recovery copy retained"):
        manager._publish_candidate(candidate, threshold=0.6, device="cpu")

    recovery = tmp_path / ".production.pt.rollback"
    assert recovery.read_bytes() == previous
