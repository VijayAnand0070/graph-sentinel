from __future__ import annotations

import json
from pathlib import Path

from graphsentinel.evaluation.experiments import (
    BaselineExperimentConfig,
    run_baseline_experiments,
)
from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent


def _records():
    events = []
    positive_indices = {2, 5, 9, 13, 17, 21, 25, 29, 33, 37}
    for index in range(40):
        events.append(
            NormalizedAuthEvent(
                event_id=index,
                timestamp=index + 1,
                src_user_id=(index % 4) + 1,
                dst_user_id=(index % 4) + 1,
                src_host_id=(index % 5) + 1,
                dst_host_id=(index % 7) + 2,
                auth_type_id=(index % 2) + 1,
                logon_type_id=(index % 3) + 1,
                orientation_id=1,
                success=int(index % 6 != 0),
                label_redteam=int(index in positive_indices),
                day=0,
                hour=0,
            )
        )
    return list(CausalFeatureEngine().transform(events))


def test_baseline_experiment_freezes_split_thresholds_and_artifact(tmp_path: Path) -> None:
    output = tmp_path / "baseline.json"

    report = run_baseline_experiments(
        _records(),
        feature_contract_sha256="a" * 64,
        output_path=output,
        config=BaselineExperimentConfig(
            train_fraction=0.6,
            validation_fraction=0.2,
            false_positives_per_10000_budget=10_000,
            isolation_forest_estimators=10,
        ),
    )

    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert report.experiment_id.startswith("GS-E1E2-")
    assert set(report.models) == {"rule", "rarity", "isolation_forest", "logistic"}
    assert report.split["counts"] == {"train": 24, "validation": 8, "test": 8}
    assert persisted["config_sha256"] == report.config_sha256
    assert all("test" in result for result in persisted["models"].values())
