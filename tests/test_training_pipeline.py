import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.models.serving import load_inference_session
from graphsentinel.models.training_pipeline import TGNTrainingConfig, train_tgn_from_dataset


def _normalized(event_id: int, *, label: int) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=event_id + 1,
        src_user_id=1,
        dst_user_id=1,
        src_host_id=1 + event_id % 2,
        dst_host_id=3 + event_id % 3,
        auth_type_id=1,
        logon_type_id=1,
        orientation_id=1,
        success=1,
        label_redteam=label,
        day=0,
        hour=0,
    )


def test_training_pipeline_publishes_loadable_normalized_checkpoint(tmp_path: Path) -> None:
    labels = [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
    records = list(
        CausalFeatureEngine().transform(
            _normalized(index, label=label) for index, label in enumerate(labels)
        )
    )
    feature_dir = tmp_path / "features" / "feature_day=00"
    feature_dir.mkdir(parents=True)
    pq.write_table(
        pa.Table.from_pylist([record.to_dict() for record in records]),
        feature_dir / "part.parquet",
    )
    feature_report = tmp_path / "feature-report.json"
    feature_report.write_text(json.dumps({"feature_contract_sha256": "a" * 64}), encoding="utf-8")
    checkpoint = tmp_path / "model.pt"
    report_path = tmp_path / "training.json"

    report = train_tgn_from_dataset(
        input_dir=tmp_path / "features",
        feature_report_path=feature_report,
        checkpoint_path=checkpoint,
        report_path=report_path,
        config=TGNTrainingConfig(
            epochs=1,
            patience=1,
            memory_dim=6,
            time_dim=4,
            hidden_dim=8,
            dropout=0,
            truncate_after_events=4,
            false_positives_per_10000_budget=10_000,
            require_baseline_improvement=False,
            oov_user_buckets=4,
            oov_host_buckets=8,
        ),
    )
    session = load_inference_session(checkpoint)

    assert report.epochs_completed == 1
    assert report.best_epoch == 1
    assert report.test_metrics["events"] == 2
    assert checkpoint.is_file() and report_path.is_file()
    assert len(session.provenance.feature_center) == 27
    assert len(session.provenance.feature_scale) == 27
    assert session.provenance.decision_threshold == report.threshold_selection["threshold"]
    assert session.provenance.feature_contract_sha256 == "a" * 64
    assert session.provenance.training_run_sha256 == report.training_run_sha256
    assert report.parameter_count == sum(
        parameter.numel() for parameter in session.model.parameters()
    )
    assert report.device == "cpu"


def test_a_fault_after_the_first_epoch_finishes_from_the_best_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient CUDA fault at epoch 13 of 16 once discarded a two-hour
    run. The best state is written to disk as it is reached, and a RuntimeError
    in a later epoch ends training from that state instead of losing it; the
    report says so."""
    from graphsentinel.models import training_pipeline

    labels = [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
    records = list(
        CausalFeatureEngine().transform(
            _normalized(index, label=label) for index, label in enumerate(labels)
        )
    )
    feature_dir = tmp_path / "features" / "feature_day=00"
    feature_dir.mkdir(parents=True)
    pq.write_table(
        pa.Table.from_pylist([record.to_dict() for record in records]),
        feature_dir / "part.parquet",
    )
    feature_report = tmp_path / "feature-report.json"
    feature_report.write_text(json.dumps({"feature_contract_sha256": "a" * 64}), encoding="utf-8")
    checkpoint = tmp_path / "model.pt"
    real_train_epoch = training_pipeline.train_epoch
    calls = {"n": 0}

    def faulting_train_epoch(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 3:
            raise RuntimeError("CUDA error: CUBLAS_STATUS_EXECUTION_FAILED")
        return real_train_epoch(*args, **kwargs)

    monkeypatch.setattr(training_pipeline, "train_epoch", faulting_train_epoch)
    config = TGNTrainingConfig(
        epochs=5,
        patience=5,
        memory_dim=6,
        time_dim=4,
        hidden_dim=8,
        dropout=0,
        truncate_after_events=4,
        false_positives_per_10000_budget=10_000,
        require_baseline_improvement=False,
        oov_user_buckets=4,
        oov_host_buckets=8,
    )
    report = train_tgn_from_dataset(
        input_dir=tmp_path / "features",
        feature_report_path=feature_report,
        checkpoint_path=checkpoint,
        report_path=tmp_path / "training.json",
        config=config,
    )
    assert report.epochs_completed == 2
    assert report.interrupted is not None and "epoch 3" in report.interrupted
    assert "CUBLAS" in report.interrupted
    assert checkpoint.is_file()
    assert not (tmp_path / "model.pt.best-so-far").exists()  # removed once published
    assert load_inference_session(checkpoint).provenance.training_run_sha256 == (
        report.training_run_sha256
    )

    # A fault before any epoch completed is still fatal: there is nothing to
    # finish from.
    calls["n"] = 2
    with pytest.raises(RuntimeError, match="CUBLAS"):
        train_tgn_from_dataset(
            input_dir=tmp_path / "features",
            feature_report_path=feature_report,
            checkpoint_path=tmp_path / "second.pt",
            report_path=tmp_path / "second.json",
            config=config,
        )


def test_config_rejects_non_positive_positive_weight_cap() -> None:
    with pytest.raises(ValueError, match="positive_weight_cap must be positive"):
        TGNTrainingConfig(positive_weight_cap=0)
    with pytest.raises(ValueError, match="positive_weight_cap must be positive"):
        TGNTrainingConfig(positive_weight_cap=-5.0)


def test_config_allows_none_positive_weight_cap_by_default() -> None:
    assert TGNTrainingConfig().positive_weight_cap is None


def test_training_with_capped_positive_weight_completes_and_records_cap(
    tmp_path: Path,
) -> None:
    labels = [0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0]
    records = list(
        CausalFeatureEngine().transform(
            _normalized(index, label=label) for index, label in enumerate(labels)
        )
    )
    feature_dir = tmp_path / "features" / "feature_day=00"
    feature_dir.mkdir(parents=True)
    pq.write_table(
        pa.Table.from_pylist([record.to_dict() for record in records]),
        feature_dir / "part.parquet",
    )
    feature_report = tmp_path / "feature-report.json"
    feature_report.write_text(json.dumps({"feature_contract_sha256": "a" * 64}), encoding="utf-8")
    checkpoint = tmp_path / "model.pt"
    report_path = tmp_path / "training.json"

    report = train_tgn_from_dataset(
        input_dir=tmp_path / "features",
        feature_report_path=feature_report,
        checkpoint_path=checkpoint,
        report_path=report_path,
        config=TGNTrainingConfig(
            epochs=1,
            patience=1,
            memory_dim=6,
            time_dim=4,
            hidden_dim=8,
            dropout=0,
            truncate_after_events=4,
            false_positives_per_10000_budget=10_000,
            require_baseline_improvement=False,
            oov_user_buckets=4,
            oov_host_buckets=8,
            positive_weight_cap=2.0,
        ),
    )

    assert report.epochs_completed == 1
    assert report.training_configuration["positive_weight_cap"] == 2.0
    assert report.promotion["eligible"] is True
