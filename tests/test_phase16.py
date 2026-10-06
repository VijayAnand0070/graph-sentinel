from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

import graphsentinel.api.phase16 as phase16_module
from graphsentinel.api.main import create_app
from graphsentinel.api.phase16 import Phase16Manager
from graphsentinel.api.pipeline_lease import PipelineBusyError, PipelineLease
from graphsentinel.api.schemas import Phase16StartRequest
from graphsentinel.api.service import DetectionService


def _manager(tmp_path: Path, *, publish: Any = None) -> Phase16Manager:
    return Phase16Manager(
        raw_dir=tmp_path / "raw",
        interim_dir=tmp_path / "interim",
        id_map_dir=tmp_path / "id-maps",
        feature_dir=tmp_path / "features",
        ingestion_report_path=tmp_path / "reports" / "ingestion.json",
        feature_report_path=tmp_path / "reports" / "features.json",
        baseline_report_path=tmp_path / "metrics" / "baselines.json",
        training_report_path=tmp_path / "metrics" / "training.json",
        checkpoint_path=tmp_path / "models" / "production.pt",
        candidate_path=tmp_path / "models" / "candidate.pt",
        state_path=tmp_path / "runtime" / "phase16.json",
        lease=PipelineLease(tmp_path / "runtime" / "pipeline.lease"),
        publish_candidate=publish or (lambda _path, _threshold, _device: None),
    )


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_phase16_status_is_honest_without_registered_data(tmp_path: Path) -> None:
    overview = _manager(tmp_path).status()

    assert overview.provenance.mode == "unregistered"
    assert overview.provenance.event_count == 0
    assert overview.job is not None and overview.job.state == "idle"
    assert [stage.key for stage in overview.pipeline] == [
        "register",
        "normalize",
        "features",
        "train",
        "validate",
        "test",
        "promote",
    ]
    assert overview.pipeline[0].status == "pending"
    assert all(stage.status == "blocked" for stage in overview.pipeline[1:])
    assert overview.metrics is None
    assert overview.checkpoint is None


def test_phase16_start_requires_registered_core_files(tmp_path: Path) -> None:
    manager = _manager(tmp_path)

    with pytest.raises(FileNotFoundError, match=r"auth\.txt\.gz, redteam\.txt\.gz"):
        manager.start(Phase16StartRequest(epochs=1, patience=1))

    assert manager.status().job is not None
    assert manager.status().job.state == "idle"


def test_pipeline_lease_excludes_other_manager_instances(tmp_path: Path) -> None:
    first = PipelineLease(tmp_path / "pipeline.lease")
    second = PipelineLease(tmp_path / "pipeline.lease")
    handle = first.acquire(owner="phase16", job_id="P16-FIRST")

    with pytest.raises(PipelineBusyError, match="P16-FIRST"):
        second.acquire(owner="legacy-training", job_id="LEGACY-SECOND")

    first.release(handle)
    next_handle = second.acquire(owner="legacy-training", job_id="LEGACY-SECOND")
    second.release(next_handle)


def test_stale_pipeline_lease_is_recovered(tmp_path: Path) -> None:
    lease_path = tmp_path / "pipeline.lease"
    _write_json(
        lease_path,
        {
            "schema_version": 1,
            "token": "stale",
            "owner": "phase16",
            "job_id": "P16-STALE",
            "pid": 2_147_483_647,
        },
    )
    lease = PipelineLease(lease_path)

    handle = lease.acquire(owner="phase16", job_id="P16-RECOVERED")

    assert lease.read()["job_id"] == "P16-RECOVERED"  # type: ignore[index]
    lease.release(handle)


def test_running_journal_recovers_as_interrupted_failure(tmp_path: Path) -> None:
    state_path = tmp_path / "runtime" / "phase16.json"
    _write_json(
        state_path,
        {
            "schema_version": 1,
            "job": {
                "job_id": "P16-INTERRUPTED",
                "state": "running",
                "progress": 0.5,
                "stage": "train",
                "epoch": 2,
                "total_epochs": 10,
                "started_at": "2026-08-12T10:00:00+00:00",
                "finished_at": None,
                "message": "training",
                "config": {
                    "max_events": 1000,
                    "epochs": 10,
                    "patience": 3,
                    "device": "cpu",
                },
            },
            "stage_updates": {},
            "promotion": {},
        },
    )

    recovered = _manager(tmp_path).status().job

    assert recovered is not None
    assert recovered.job_id == "P16-INTERRUPTED"
    assert recovered.state == "failed"
    assert "previous API process stopped" in recovered.message
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["interrupted"] is True


def test_corrupt_journal_fails_closed_without_overwrite(tmp_path: Path) -> None:
    state_path = tmp_path / "runtime" / "phase16.json"
    state_path.parent.mkdir(parents=True)
    original = b"{not-json"
    state_path.write_bytes(original)
    manager = _manager(tmp_path)

    status = manager.status().job

    assert status is not None and status.state == "failed"
    assert "journal is invalid" in status.message
    assert state_path.read_bytes() == original
    with pytest.raises(RuntimeError, match="journal is invalid"):
        manager.start(Phase16StartRequest())


def test_phase16_runs_full_pipeline_and_promotes_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    captured: dict[str, Any] = {}
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "auth.txt.gz").write_bytes(b"registered-auth")
    (raw / "redteam.txt.gz").write_bytes(b"registered-labels")
    auth_hash = "a" * 64
    label_hash = "b" * 64
    feature_hash = "c" * 64

    def verify(raw_dir: Path, scope: str, **options: Any) -> tuple[Path, list[Any]]:
        calls.append("verify")
        captured["verify"] = (raw_dir, scope, options)
        files = [
            {
                "file": "auth.txt.gz",
                "sha256": auth_hash,
                "validation_level": "full",
                "malformed_rows": 0,
                "timestamps_non_decreasing": True,
            },
            {
                "file": "redteam.txt.gz",
                "sha256": label_hash,
                "validation_level": "full",
                "malformed_rows": 0,
                "timestamps_non_decreasing": True,
            },
        ]
        manifest = raw_dir / "manifest.json"
        _write_json(
            manifest,
            {
                "dataset": "LANL",
                "source_page": "https://example.test/lanl",
                "registered_at_utc": "2026-08-12T10:00:00+00:00",
                "files": files,
            },
        )
        results = [
            SimpleNamespace(
                file=item["file"],
                sha256=item["sha256"],
                malformed_rows=0,
                timestamps_non_decreasing=True,
            )
            for item in files
        ]
        return manifest, results

    ingestion_payload = {
        "source_auth_sha256": auth_hash,
        "source_redteam_sha256": label_hash,
        "rows_parsed": 120,
        "redteam_matches": 6,
        "timestamp_min": 1,
        "timestamp_max": 120,
        "timestamps_non_decreasing": True,
        "parquet_files": 1,
    }

    def ingest(**options: Any) -> Any:
        calls.append("normalize")
        captured["ingest"] = options
        partition = options["output_dir"] / "auth_day=00"
        partition.mkdir(parents=True)
        (partition / "part.parquet").write_bytes(b"normalized")
        for name in ("users", "hosts", "auth_types", "logon_types", "orientations"):
            _write_json(options["id_map_dir"] / f"{name}.json", {"unknown": 0})
        _write_json(options["report_path"], ingestion_payload)
        return SimpleNamespace(**ingestion_payload, to_dict=lambda: ingestion_payload)

    feature_payload = {
        "feature_version": "auth-causal-v1",
        "feature_contract_sha256": feature_hash,
        "events": 120,
        "redteam_events": 6,
        "timestamp_min": 1,
        "timestamp_max": 120,
        "output_files": 1,
    }

    def features(**options: Any) -> Any:
        calls.append("features")
        captured["features"] = options
        partition = options["output_dir"] / "feature_day=00"
        partition.mkdir(parents=True)
        (partition / "part.parquet").write_bytes(b"features")
        _write_json(options["output_dir"] / "_feature_report.json", feature_payload)
        _write_json(options["report_path"], feature_payload)
        return SimpleNamespace(**feature_payload, to_dict=lambda: feature_payload)

    def baselines(**options: Any) -> Any:
        calls.append("baselines")
        captured["baselines"] = options
        _write_json(
            options["output_path"],
            {"feature_contract_sha256": feature_hash, "models": {}},
        )
        return SimpleNamespace()

    training_payload = {
        "feature_contract_sha256": feature_hash,
        "training_run_sha256": "d" * 64,
        "dataset_sha256": "e" * 64,
        "best_epoch": 2,
        "threshold_selection": {"threshold": 0.72},
        "validation_metrics": {"pr_auc": 0.8},
        "test_metrics": {"pr_auc": 0.75},
        "promotion": {
            "eligible": True,
            "model_validation_pr_auc": 0.8,
            "best_baseline_validation_pr_auc": 0.6,
        },
    }

    def train(**options: Any) -> Any:
        calls.append("train")
        captured["train"] = options
        options["checkpoint_path"].parent.mkdir(parents=True, exist_ok=True)
        options["checkpoint_path"].write_bytes(b"candidate")
        _write_json(options["report_path"], training_payload)
        return SimpleNamespace(**training_payload)

    def publish(candidate: Path, threshold: float, device: str) -> None:
        calls.append("promote")
        captured["publish"] = (candidate, threshold, device)
        production = tmp_path / "models" / "production.pt"
        production.write_bytes(candidate.read_bytes())

    monkeypatch.setattr(phase16_module, "verify_registered", verify)
    monkeypatch.setattr(phase16_module, "ingest_auth", ingest)
    monkeypatch.setattr(phase16_module, "build_feature_dataset", features)
    monkeypatch.setattr(phase16_module, "run_baselines_from_dataset", baselines)
    monkeypatch.setattr(phase16_module, "train_tgn_from_dataset", train)
    manager = _manager(tmp_path, publish=publish)
    monkeypatch.setattr(manager, "_validate_candidate_lineage", lambda *args, **kwargs: None)

    accepted = manager.start(
        Phase16StartRequest(max_events=10_000, epochs=4, patience=2, device="cpu")
    )
    assert accepted.job is not None and accepted.job.job_id
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        current = manager.status()
        if current.job is not None and current.job.state in {"completed", "failed", "rejected"}:
            break
        time.sleep(0.01)

    assert current.job is not None
    assert current.job.state == "completed", current.job.message
    assert calls == ["verify", "normalize", "features", "baselines", "train", "promote"]
    assert captured["verify"][2]["full_scan"] is True
    assert captured["baselines"]["max_events"] == 10_000
    assert captured["train"]["max_events"] == 10_000
    assert captured["train"]["config"].epochs == 4
    assert captured["publish"][1:] == (0.72, "cpu")
    assert all(stage.status == "complete" for stage in current.pipeline)
    assert current.promotion.status == "promoted"


def test_phase16_api_fails_closed_and_rejects_source_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_RAW_DIR", str(tmp_path / "raw"))
    monkeypatch.setenv("GRAPHSENTINEL_INTERIM_DIR", str(tmp_path / "interim"))
    monkeypatch.setenv("GRAPHSENTINEL_ID_MAP_DIR", str(tmp_path / "maps"))
    monkeypatch.setenv("GRAPHSENTINEL_FEATURE_DIR", str(tmp_path / "features"))
    monkeypatch.setenv("GRAPHSENTINEL_PHASE16_STATE", str(tmp_path / "phase16.json"))
    monkeypatch.setenv("GRAPHSENTINEL_PIPELINE_LEASE", str(tmp_path / "pipeline.lease"))
    client = TestClient(create_app(DetectionService()))

    status = client.get("/api/v1/phase16")
    missing = client.post("/api/v1/phase16/start", json={"epochs": 1, "patience": 1})
    arbitrary_path = client.post(
        "/api/v1/phase16/start",
        json={"epochs": 1, "patience": 1, "source_dir": "C:/unsafe"},
    )

    assert status.status_code == 200
    assert status.json()["provenance"]["mode"] == "unregistered"
    assert missing.status_code == 409
    assert "dataset register" in missing.json()["detail"]
    assert arbitrary_path.status_code == 422


def test_release_failure_restores_previous_production_reports(tmp_path: Path) -> None:
    def reject(_path: Path, _threshold: float, _device: str) -> None:
        raise RuntimeError("live installation rejected")

    manager = _manager(tmp_path, publish=reject)
    old_baseline = tmp_path / "metrics" / "baselines.json"
    old_training = tmp_path / "metrics" / "training.json"
    candidate_baseline = tmp_path / "run" / "baselines.json"
    candidate_training = tmp_path / "run" / "training.json"
    for path, content in (
        (old_baseline, b"old-baseline"),
        (old_training, b"old-training"),
        (candidate_baseline, b"new-baseline"),
        (candidate_training, b"new-training"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    with pytest.raises(RuntimeError, match="live installation rejected"):
        manager._publish_release(
            tmp_path / "candidate.pt",
            threshold=0.7,
            device="cpu",
            reports=(
                (candidate_baseline, old_baseline),
                (candidate_training, old_training),
            ),
        )

    assert old_baseline.read_bytes() == b"old-baseline"
    assert old_training.read_bytes() == b"old-training"
    assert not list((tmp_path / "metrics").glob("*.rollback"))
