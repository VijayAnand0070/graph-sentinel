"""Strict loader for the canonical TGN training configuration."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from graphsentinel.features.causal import MODEL_FEATURE_NAMES
from graphsentinel.models.training_pipeline import TGNTrainingConfig

DEFAULT_TGN_CONFIG_PATH = Path("configs/model_tgn.yaml")


def _mapping(payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or not all(isinstance(key, str) for key in payload):
        raise ValueError(f"{name} must be a string-keyed mapping")
    return payload


def _exact_keys(payload: dict[str, Any], expected: set[str], name: str) -> None:
    if set(payload) != expected:
        missing = sorted(expected - set(payload))
        extra = sorted(set(payload) - expected)
        raise ValueError(f"{name} fields do not match contract; missing={missing}, extra={extra}")


def load_tgn_training_config(
    path: Path | None = None,
    *,
    epochs: int | None = None,
    patience: int | None = None,
) -> TGNTrainingConfig:
    """Load one fail-closed configuration and apply bounded run-control overrides."""

    configured_path = path or Path(
        os.getenv("GRAPHSENTINEL_MODEL_CONFIG", str(DEFAULT_TGN_CONFIG_PATH))
    )
    try:
        root = _mapping(yaml.safe_load(configured_path.read_text(encoding="utf-8")), "root")
    except OSError as error:
        raise FileNotFoundError(f"TGN configuration is unavailable: {configured_path}") from error
    _exact_keys(root, {"schema_version", "model", "training", "selection"}, "root")
    if root["schema_version"] != 1:
        raise ValueError("unsupported TGN configuration schema")
    model = _mapping(root["model"], "model")
    training = _mapping(root["training"], "training")
    selection = _mapping(root["selection"], "selection")
    _exact_keys(
        model,
        {
            "message_dim",
            "memory_dim",
            "time_dim",
            "hidden_dim",
            "dropout",
            "score_before_memory_update",
        },
        "model",
    )
    _exact_keys(
        training,
        {
            "epochs",
            "patience",
            "seed",
            "optimizer",
            "learning_rate",
            "weight_decay",
            "loss",
            "truncate_after_events",
            "oov_user_buckets",
            "oov_host_buckets",
            "positive_weight_cap",
            "time_bucket_seconds",
        },
        "training",
    )
    _exact_keys(
        selection,
        {
            "train_fraction",
            "validation_fraction",
            "false_positives_per_10000_budget",
            "require_baseline_improvement",
            "minimum_pr_auc_improvement",
        },
        "selection",
    )
    if model["message_dim"] != len(MODEL_FEATURE_NAMES):
        raise ValueError("model.message_dim does not match the causal feature contract")
    if model["score_before_memory_update"] is not True:
        raise ValueError("score-before-memory-update must remain enabled")
    if training["optimizer"] != "adamw" or training["loss"] != "weighted_bce":
        raise ValueError("optimizer and loss do not match the implemented training contract")
    config = TGNTrainingConfig(
        epochs=int(training["epochs"]),
        patience=int(training["patience"]),
        learning_rate=float(training["learning_rate"]),
        weight_decay=float(training["weight_decay"]),
        memory_dim=int(model["memory_dim"]),
        time_dim=int(model["time_dim"]),
        hidden_dim=int(model["hidden_dim"]),
        dropout=float(model["dropout"]),
        truncate_after_events=int(training["truncate_after_events"]),
        train_fraction=float(selection["train_fraction"]),
        validation_fraction=float(selection["validation_fraction"]),
        false_positives_per_10000_budget=float(selection["false_positives_per_10000_budget"]),
        seed=int(training["seed"]),
        require_baseline_improvement=bool(selection["require_baseline_improvement"]),
        minimum_pr_auc_improvement=float(selection["minimum_pr_auc_improvement"]),
        oov_user_buckets=int(training["oov_user_buckets"]),
        oov_host_buckets=int(training["oov_host_buckets"]),
        positive_weight_cap=(
            float(training["positive_weight_cap"])
            if training["positive_weight_cap"] is not None
            else None
        ),
        time_bucket_seconds=int(training["time_bucket_seconds"]),
    )
    return replace(
        config,
        epochs=epochs if epochs is not None else config.epochs,
        patience=patience if patience is not None else config.patience,
    )
