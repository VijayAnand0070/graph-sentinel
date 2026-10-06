"""Reproducible chronological baseline experiment runner."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import MISSING, asdict, dataclass
from pathlib import Path
from typing import Any

from graphsentinel import __version__
from graphsentinel.evaluation.metrics import ranking_metrics, select_threshold_under_budget
from graphsentinel.evaluation.splits import fit_chronological_split
from graphsentinel.features.causal import FeatureRecord
from graphsentinel.models.baselines import (
    Baseline,
    IsolationForestBaseline,
    LogisticBaseline,
    RarityBaseline,
    RuleBaseline,
)


@dataclass(frozen=True, slots=True)
class BaselineExperimentConfig:
    train_fraction: float = 0.70
    validation_fraction: float = 0.15
    false_positives_per_10000_budget: float = 25
    seed: int = 1729
    isolation_forest_estimators: int = 200

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BaselineExperimentReport:
    schema_version: int
    graphsentinel_version: str
    experiment_id: str
    config: dict[str, int | float]
    config_sha256: str
    feature_contract_sha256: str
    events: int
    timestamp_min: int
    timestamp_max: int
    split: dict[str, object]
    models: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_feature_parquet(input_dir: Path) -> list[Path]:
    paths = sorted(input_dir.glob("feature_day=*/*.parquet"))
    if not paths:
        raise FileNotFoundError(f"No feature Parquet files found under {input_dir}")
    return paths


def read_feature_records(input_dir: Path, *, max_events: int | None = None) -> list[FeatureRecord]:
    if max_events is not None and max_events <= 0:
        raise ValueError("max_events must be positive")
    try:
        import pyarrow.parquet as pq  # type: ignore[import-untyped]
    except ImportError as error:
        raise RuntimeError('Experiments require: pip install -e ".[data,ml]"') from error
    all_fields = FeatureRecord.__dataclass_fields__
    # fields with a default were added in later feature versions; files written
    # before them are still read, and the record keeps the default
    required = {name for name, f in all_fields.items() if f.default is MISSING}
    records: list[FeatureRecord] = []
    for path in discover_feature_parquet(input_dir):
        parquet = pq.ParquetFile(path)
        present = set(parquet.schema_arrow.names)
        missing = required - present
        if missing:
            raise ValueError(f"{path} is missing feature columns: {sorted(missing)}")
        field_names = tuple(name for name in all_fields if name in present)
        for batch in parquet.iter_batches(batch_size=65_536, columns=list(field_names)):
            columns = batch.to_pydict()
            for row_index in range(batch.num_rows):
                records.append(
                    FeatureRecord(**{name: columns[name][row_index] for name in field_names})
                )
                if max_events is not None and len(records) >= max_events:
                    return records
    return records


def _hash_json(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


DEFAULT_EXPERIMENT_CONFIG = BaselineExperimentConfig()


def run_baseline_experiments(
    records: list[FeatureRecord],
    *,
    feature_contract_sha256: str,
    output_path: Path,
    config: BaselineExperimentConfig = DEFAULT_EXPERIMENT_CONFIG,
) -> BaselineExperimentReport:
    """Fit E1/E2 baselines and freeze thresholds using validation data only."""

    if not records:
        raise ValueError("baseline experiments require feature records")
    timestamps = [record.timestamp for record in records]
    labels = [record.label_redteam for record in records]
    split = fit_chronological_split(
        timestamps,
        labels,
        train_fraction=config.train_fraction,
        validation_fraction=config.validation_fraction,
    )
    train = records[: split.train_end_index]
    validation = records[split.train_end_index : split.validation_end_index]
    test = records[split.validation_end_index :]
    detectors: dict[str, Baseline] = {
        "rule": RuleBaseline(),
        "rarity": RarityBaseline(),
        "isolation_forest": IsolationForestBaseline(
            random_state=config.seed, estimators=config.isolation_forest_estimators
        ).fit(train),
        "logistic": LogisticBaseline(random_state=config.seed).fit(train),
    }
    validation_labels = [record.label_redteam for record in validation]
    test_labels = [record.label_redteam for record in test]
    model_results: dict[str, dict[str, Any]] = {}
    for name, detector in detectors.items():
        validation_scores = detector.predict_scores(validation)
        threshold = select_threshold_under_budget(
            validation_labels,
            validation_scores,
            false_positives_per_10000_budget=(config.false_positives_per_10000_budget),
        )
        test_scores = detector.predict_scores(test)
        model_results[name] = {
            "threshold_selection": threshold.to_dict(),
            "validation": ranking_metrics(
                validation_labels,
                validation_scores,
                threshold=threshold.threshold,
            ),
            "test": ranking_metrics(
                test_labels,
                test_scores,
                threshold=threshold.threshold,
            ),
        }
    config_payload = config.to_dict()
    experiment_basis = {
        "config": config_payload,
        "feature_contract_sha256": feature_contract_sha256,
        "timestamp_min": timestamps[0],
        "timestamp_max": timestamps[-1],
        "events": len(records),
    }
    report = BaselineExperimentReport(
        schema_version=1,
        graphsentinel_version=__version__,
        experiment_id="GS-E1E2-" + _hash_json(experiment_basis)[:12].upper(),
        config=config_payload,
        config_sha256=_hash_json(config_payload),
        feature_contract_sha256=feature_contract_sha256,
        events=len(records),
        timestamp_min=timestamps[0],
        timestamp_max=timestamps[-1],
        split=split.to_dict(),
        models=model_results,
    )
    _write_json(output_path, report.to_dict())
    return report


def run_baselines_from_dataset(
    *,
    input_dir: Path,
    feature_report_path: Path,
    output_path: Path,
    max_events: int | None = None,
    config: BaselineExperimentConfig = DEFAULT_EXPERIMENT_CONFIG,
) -> BaselineExperimentReport:
    feature_report = json.loads(feature_report_path.read_text(encoding="utf-8"))
    contract_hash = feature_report.get("feature_contract_sha256")
    if not isinstance(contract_hash, str) or len(contract_hash) != 64:
        raise ValueError("feature report has no valid contract hash")
    return run_baseline_experiments(
        read_feature_records(input_dir, max_events=max_events),
        feature_contract_sha256=contract_hash,
        output_path=output_path,
        config=config,
    )
