"""End-to-end, leakage-safe TGN training and checkpoint promotion."""

from __future__ import annotations

import hashlib
import json
import os
import random
import statistics
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from itertools import groupby
from pathlib import Path
from typing import Any

import torch

from graphsentinel import __version__
from graphsentinel.detection.fusion import RiskComponents, fuse_risk
from graphsentinel.detection.signals import SignalTracker
from graphsentinel.evaluation.experiments import read_feature_records
from graphsentinel.evaluation.metrics import (
    average_precision,
    ranking_metrics,
    select_threshold_under_budget,
)
from graphsentinel.evaluation.splits import fit_chronological_split
from graphsentinel.features.causal import MODEL_FEATURE_NAMES, FeatureRecord
from graphsentinel.features.pipeline import FEATURE_VERSION
from graphsentinel.graph.temporal import NodeIdSpace, TemporalGraphEvent
from graphsentinel.ingestion.id_map import AuthIdMaps, auth_id_map_sha256
from graphsentinel.models.baselines import RarityBaseline, RuleBaseline
from graphsentinel.models.tgn import TemporalBatch, TemporalGraphNetwork
from graphsentinel.models.training import time_window_groups, timestamp_groups, train_epoch

ProgressCallback = Callable[[int, int, float, float | None], None]


@dataclass(frozen=True, slots=True)
class TGNTrainingConfig:
    epochs: int = 12
    patience: int = 3
    learning_rate: float = 0.001
    weight_decay: float = 0.0001
    memory_dim: int = 64
    time_dim: int = 16
    hidden_dim: int = 96
    dropout: float = 0.1
    truncate_after_events: int = 2_048
    train_fraction: float = 0.70
    validation_fraction: float = 0.15
    false_positives_per_10000_budget: float = 25
    seed: int = 1729
    require_baseline_improvement: bool = True
    minimum_pr_auc_improvement: float = 0.0
    oov_user_buckets: int = 4_096
    oov_host_buckets: int = 16_384
    positive_weight_cap: float | None = None
    time_bucket_seconds: int = 0
    #: Ablation: score without reading node memory (see TemporalGraphNetwork).
    use_memory: bool = True
    #: Ablation: source hosts whose *training-partition* events contribute no
    #: gradient. They stay in the stream, so the split, the replay, validation
    #: and test are identical to an ordinary run -- only what the model is
    #: allowed to learn from changes. This is how an attacker entity is held out
    #: without changing the partition it is later tested on.
    exclude_train_src_hosts: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        if self.epochs <= 0 or self.patience <= 0:
            raise ValueError("epochs and patience must be positive")
        if self.learning_rate <= 0 or self.weight_decay < 0:
            raise ValueError("learning rate must be positive and weight decay non-negative")
        if min(self.memory_dim, self.time_dim, self.hidden_dim, self.truncate_after_events) <= 0:
            raise ValueError("model dimensions and truncation interval must be positive")
        if self.time_bucket_seconds < 0:
            raise ValueError("time_bucket_seconds must not be negative")
        if not 0 <= self.dropout < 1:
            raise ValueError("dropout must be in [0, 1)")
        if not 0 < self.train_fraction < 1:
            raise ValueError("train_fraction must be between zero and one")
        if not 0 < self.validation_fraction < 1 - self.train_fraction:
            raise ValueError("validation_fraction leaves no test partition")
        if self.false_positives_per_10000_budget < 0:
            raise ValueError("false-positive budget cannot be negative")
        if self.seed < 0:
            raise ValueError("training seed cannot be negative")
        if self.minimum_pr_auc_improvement < 0:
            raise ValueError("minimum PR-AUC improvement cannot be negative")
        if self.oov_user_buckets <= 0 or self.oov_host_buckets <= 0:
            raise ValueError("OOV user and host bucket counts must be positive")
        if self.positive_weight_cap is not None and self.positive_weight_cap <= 0:
            raise ValueError("positive_weight_cap must be positive when set")


@dataclass(frozen=True, slots=True)
class FeatureNormalizer:
    center: tuple[float, ...]
    scale: tuple[float, ...]

    @classmethod
    def fit(cls, records: Sequence[FeatureRecord]) -> FeatureNormalizer:
        if not records:
            raise ValueError("normalizer requires training records")
        # Fit one feature at a time so a 250k-event cohort does not materialize
        # 27 dense Python columns before training tensors are even created.
        center: list[float] = []
        scale: list[float] = []
        for name in MODEL_FEATURE_NAMES:
            column = [float(getattr(record, name)) for record in records]
            center.append(statistics.median(column))
            scale.append(max(1e-6, _percentile(column, 0.75) - _percentile(column, 0.25)))
            del column
        return cls(center=tuple(center), scale=tuple(scale))

    def transform(self, record: FeatureRecord) -> tuple[float, ...]:
        values = tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES)
        return tuple(
            max(-10.0, min(10.0, (value - center) / scale))
            for value, center, scale in zip(values, self.center, self.scale, strict=True)
        )


@dataclass(frozen=True, slots=True)
class TGNTrainingReport:
    schema_version: int
    graphsentinel_version: str
    model_version: str
    feature_version: str
    feature_contract_sha256: str
    dataset_sha256: str | None
    training_run_sha256: str
    entity_dictionary_sha256: str | None
    checkpoint_path: str
    checkpoint_sha256: str
    events: int
    split: dict[str, object]
    configuration: dict[str, int | float]
    training_configuration: dict[str, int | float | bool]
    parameter_count: int
    device: str
    epochs_completed: int
    best_epoch: int
    epoch_history: tuple[dict[str, int | float | None], ...]
    threshold_selection: dict[str, float | int]
    validation_metrics: dict[str, float | int | None]
    test_metrics: dict[str, float | int | None]
    baseline_validation_pr_auc: dict[str, float | None]
    promotion: dict[str, bool | float | str]
    #: Positives the loss was actually computed over. Equals the split's train
    #: positive count unless ``exclude_train_src_hosts`` masked some -- in
    #: which case the gap between the two is the size of the held-out entity,
    #: and a reader comparing this run to a normal one needs to see it.
    training_positives_in_loss: int | None = None
    #: Set when an epoch raised (a CUDA fault, typically) after at least one
    #: epoch had completed: the run finished from the best state it had
    #: already reached, scored on the CPU, and this says which epoch died and
    #: why. A report without it ran every epoch it reports.
    interrupted: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _percentile(values: Sequence[float], proportion: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * proportion
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _events(
    records: Sequence[FeatureRecord],
    id_space: NodeIdSpace,
    normalizer: FeatureNormalizer,
    loss_weights: Sequence[float] | None = None,
) -> list[TemporalGraphEvent]:
    if loss_weights is not None and len(loss_weights) != len(records):
        raise ValueError("loss_weights must align with records")
    return [
        TemporalGraphEvent(
            event_id=record.event_id,
            timestamp=record.timestamp,
            source_node=id_space.user(record.src_user_id),
            destination_node=id_space.host(record.dst_host_id),
            origin_host_node=id_space.host(record.src_host_id),
            message=normalizer.transform(record),
            label_redteam=record.label_redteam,
            loss_weight=1.0 if loss_weights is None else float(loss_weights[index]),
        )
        for index, record in enumerate(records)
    ]


def _score_stream(
    model: TemporalGraphNetwork,
    events: Sequence[TemporalGraphEvent],
    *,
    start: int,
    end: int,
    device: torch.device | str,
    window_seconds: int = 0,
) -> tuple[list[int], list[float]]:
    """Replay the stream chronologically to rebuild memory, scoring [start, end).

    This is a full replay from the beginning of the stream on every call (the
    model's memory has no meaning without it), so it dominates per-epoch
    wall-clock time even more than training itself once ``window_seconds``
    speeds up the training pass. ``window_seconds`` here uses the exact same
    non-overlapping, strictly-increasing batching as ``train_epoch`` -- safe
    for the same reason: scoring always happens against pre-batch memory, so
    coarser batching never lets a later event's information leak into an
    earlier one's score, it only coarsens the "elapsed time since last event"
    feature.
    """

    model.eval()
    state = model.initial_state(device=device)
    labels: list[int] = []
    scores: list[float] = []
    offset = 0
    groups = (
        timestamp_groups(events[:end])
        if window_seconds == 0
        else time_window_groups(events[:end], window_seconds=window_seconds)
    )
    with torch.inference_mode():
        for group in groups:
            batch = TemporalBatch.from_events(
                group, device=device, allow_time_window=window_seconds > 0
            )
            logits, state = model.step(batch, state)
            probabilities = torch.sigmoid(logits).cpu().tolist()
            for event, probability in zip(group, probabilities, strict=True):
                if offset >= start:
                    labels.append(event.label_redteam)
                    scores.append(float(probability))
                offset += 1
    return labels, scores


def _fused_scores(
    records: Sequence[FeatureRecord], tgn_scores: Sequence[float], *, start: int
) -> list[float]:
    if len(tgn_scores) != len(records) - start:
        raise ValueError("TGN score range does not match feature records")
    # The same signal state the live gateway keeps, advanced the same way, so
    # the threshold fitted here is fitted on the channels the product computes.
    tracker = SignalTracker()
    result: list[float] = []
    score_index = 0
    indexed = enumerate(records)
    for _timestamp, grouped in groupby(indexed, key=lambda item: item[1].timestamp):
        group = tuple(grouped)
        for index, record in group:
            if index >= start:
                signals, _chain = tracker.signals(record)
                result.append(
                    fuse_risk(
                        RiskComponents(
                            tgn=tgn_scores[score_index],
                            novelty=signals.novelty,
                            burst=signals.burst,
                            pivot=signals.pivot,
                            corroboration=0,
                        )
                    ).score
                )
                score_index += 1
        tracker.observe_group(record for _index, record in group)
    return result


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_json(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def train_tgn_from_dataset(
    *,
    input_dir: Path,
    feature_report_path: Path,
    checkpoint_path: Path,
    report_path: Path,
    max_events: int | None = None,
    id_map_dir: Path | None = None,
    baseline_report_path: Path | None = None,
    dataset_sha256: str | None = None,
    config: TGNTrainingConfig | None = None,
    device: torch.device | str = "cpu",
    progress: ProgressCallback | None = None,
) -> TGNTrainingReport:
    """Train, validate, select a threshold, test once, and atomically publish a checkpoint."""

    config = config or TGNTrainingConfig()
    feature_report = json.loads(feature_report_path.read_text(encoding="utf-8"))
    contract_hash = feature_report.get("feature_contract_sha256")
    if not isinstance(contract_hash, str) or len(contract_hash) != 64:
        raise ValueError("feature report has no valid contract hash")
    if dataset_sha256 is not None and (
        len(dataset_sha256) != 64
        or any(character not in "0123456789abcdef" for character in dataset_sha256)
    ):
        raise ValueError("dataset_sha256 must be a lowercase SHA-256 digest")
    records = read_feature_records(input_dir, max_events=max_events)
    if not records:
        raise ValueError("TGN training requires feature records")
    split = fit_chronological_split(
        [record.timestamp for record in records],
        [record.label_redteam for record in records],
        train_fraction=config.train_fraction,
        validation_fraction=config.validation_fraction,
    )
    random.seed(config.seed)
    torch.manual_seed(config.seed)
    observed_user_capacity = max(record.src_user_id for record in records) + 1
    observed_host_capacity = (
        max(max(record.src_host_id, record.dst_host_id) for record in records) + 1
    )
    dictionary_hash: str | None = None
    if id_map_dir is not None:
        maps = AuthIdMaps.load(id_map_dir)
        user_dictionary_capacity = len(maps.users)
        host_dictionary_capacity = len(maps.hosts)
        dictionary_hash = auth_id_map_sha256(id_map_dir)
        if (
            user_dictionary_capacity < observed_user_capacity
            or host_dictionary_capacity < observed_host_capacity
        ):
            raise ValueError("entity dictionary does not cover all feature dataset IDs")
    else:
        user_dictionary_capacity = observed_user_capacity
        host_dictionary_capacity = observed_host_capacity
    user_capacity = user_dictionary_capacity + config.oov_user_buckets
    host_capacity = host_dictionary_capacity + config.oov_host_buckets
    id_space = NodeIdSpace(user_capacity=user_capacity, host_capacity=host_capacity)
    normalizer = FeatureNormalizer.fit(records[: split.train_end_index])
    excluded = set(config.exclude_train_src_hosts)
    loss_weights: list[float] | None = None
    if excluded:
        # Only training-partition events are masked; validation and test keep
        # every label so the held-out entity is still *measured*.
        loss_weights = [
            0.0 if index < split.train_end_index and record.src_host_id in excluded else 1.0
            for index, record in enumerate(records)
        ]
    events = _events(records, id_space, normalizer, loss_weights)
    model = TemporalGraphNetwork(
        num_nodes=id_space.node_count,
        message_dim=len(MODEL_FEATURE_NAMES),
        memory_dim=config.memory_dim,
        time_dim=config.time_dim,
        hidden_dim=config.hidden_dim,
        dropout=config.dropout,
        use_memory=config.use_memory,
    ).to(device)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=config.learning_rate, weight_decay=config.weight_decay
    )
    train_records = records[: split.train_end_index]
    positives = sum(
        record.label_redteam
        for index, record in enumerate(train_records)
        if loss_weights is None or loss_weights[index] > 0
    )
    if positives == 0:
        raise ValueError("training partition contains no positive events")
    positive_weight = (len(train_records) - positives) / positives
    # An uncapped weight on a handful of positive examples invites the model to
    # memorize their idiosyncrasies rather than learn a generalizable pattern —
    # capping trades some recall sensitivity for materially better generalization.
    if config.positive_weight_cap is not None:
        positive_weight = min(positive_weight, config.positive_weight_cap)
    history: list[dict[str, int | float | None]] = []
    best_state: dict[str, torch.Tensor] | None = None
    best_epoch = 0
    best_pr_auc = -1.0
    stale_epochs = 0
    epochs_completed = 0
    interrupted: str | None = None
    # The best state so far is written to disk the moment it is reached, on
    # the CPU: a GPU fault in a later epoch (a transient CUBLAS failure cost
    # this project twelve epochs of a two-hour run) then loses the epochs
    # after it, not the run. The file is removed once the checkpoint is
    # published.
    best_state_path = checkpoint_path.with_name(checkpoint_path.name + ".best-so-far")
    for epoch in range(1, config.epochs + 1):
        try:
            result = train_epoch(
                model,
                events[: split.train_end_index],
                optimizer,
                positive_weight=max(1.0, positive_weight),
                truncate_after_events=config.truncate_after_events,
                device=device,
                window_seconds=config.time_bucket_seconds,
            )
            validation_labels, validation_scores = _score_stream(
                model,
                events,
                start=split.train_end_index,
                end=split.validation_end_index,
                device=device,
                window_seconds=config.time_bucket_seconds,
            )
        except RuntimeError as error:
            if best_state is None:
                raise
            interrupted = f"epoch {epoch} raised {type(error).__name__}: {error}"
            break
        validation_scores = _fused_scores(
            records[: split.validation_end_index],
            validation_scores,
            start=split.train_end_index,
        )
        pr_auc = average_precision(validation_labels, validation_scores)
        history.append({"epoch": epoch, "train_loss": result.loss, "validation_pr_auc": pr_auc})
        epochs_completed = epoch
        if progress:
            progress(epoch, config.epochs, result.loss, pr_auc)
        comparable = pr_auc if pr_auc is not None else -1.0
        if comparable > best_pr_auc:
            best_pr_auc = comparable
            best_epoch = epoch
            best_state = {
                name: tensor.detach().to("cpu", copy=True)
                for name, tensor in model.state_dict().items()
            }
            torch.save(best_state, best_state_path)
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= config.patience:
                break
    if best_state is None:
        raise RuntimeError("training did not produce a valid model state")
    if interrupted is not None and torch.device(device).type != "cpu":
        # After a device fault the context cannot be trusted; the best state
        # is already on the CPU, so finish there with a fresh model.
        device = torch.device("cpu")
        model = TemporalGraphNetwork(
            num_nodes=id_space.node_count,
            message_dim=len(MODEL_FEATURE_NAMES),
            memory_dim=config.memory_dim,
            time_dim=config.time_dim,
            hidden_dim=config.hidden_dim,
            dropout=config.dropout,
            use_memory=config.use_memory,
        )
    model.load_state_dict(best_state)
    validation_labels, validation_scores = _score_stream(
        model,
        events,
        start=split.train_end_index,
        end=split.validation_end_index,
        device=device,
        window_seconds=config.time_bucket_seconds,
    )
    # Keep the model's own scores before fusion. The promotion gate compares
    # against baselines that are scored RAW (fuse_risk appears nowhere in
    # evaluation/experiments.py), so gating on the fused score compares a
    # pipeline against detectors and handicaps the candidate by whatever the
    # fusion costs. Measured on this run that handicap was 0.0666 validation
    # PR-AUC, and the candidate was rejected by 0.0030.
    validation_model_scores = list(validation_scores)
    validation_scores = _fused_scores(
        records[: split.validation_end_index],
        validation_scores,
        start=split.train_end_index,
    )
    threshold = select_threshold_under_budget(
        validation_labels,
        validation_scores,
        false_positives_per_10000_budget=config.false_positives_per_10000_budget,
    )
    test_labels, test_scores = _score_stream(
        model,
        events,
        start=split.validation_end_index,
        end=len(events),
        device=device,
        window_seconds=config.time_bucket_seconds,
    )
    test_scores = _fused_scores(records, test_scores, start=split.validation_end_index)
    validation_records = records[split.train_end_index : split.validation_end_index]
    baseline_pr_auc = {
        "rule": average_precision(
            validation_labels, RuleBaseline().predict_scores(validation_records)
        ),
        "rarity": average_precision(
            validation_labels, RarityBaseline().predict_scores(validation_records)
        ),
    }
    if baseline_report_path is not None:
        baseline_report = json.loads(baseline_report_path.read_text(encoding="utf-8"))
        if baseline_report.get("feature_contract_sha256") != contract_hash:
            raise ValueError("baseline report feature contract does not match training data")
        models = baseline_report.get("models")
        if not isinstance(models, dict):
            raise ValueError("baseline report has no model results")
        for name, result in models.items():
            validation_result = result.get("validation") if isinstance(result, dict) else None
            value = validation_result.get("pr_auc") if isinstance(validation_result, dict) else None
            if value is not None and not isinstance(value, int | float):
                raise ValueError("baseline validation PR-AUC must be numeric or null")
            baseline_pr_auc[str(name)] = float(value) if value is not None else None
    best_baseline = max(value or 0.0 for value in baseline_pr_auc.values())
    # Gate on the model against the baselines, like for like. The fused score
    # is still recorded below, because it is what the deployed pipeline
    # actually produces and an operator needs both numbers.
    model_validation_pr_auc = average_precision(validation_labels, validation_model_scores) or 0.0
    fused_validation_pr_auc = average_precision(validation_labels, validation_scores) or 0.0
    improvement = model_validation_pr_auc - best_baseline
    promotion_eligible = (
        not config.require_baseline_improvement or improvement > config.minimum_pr_auc_improvement
    )
    training_run_hash = _hash_json(
        {
            "configuration": asdict(config),
            "dataset_sha256": dataset_sha256,
            "entity_dictionary_sha256": dictionary_hash,
            "events": len(records),
            "feature_contract_sha256": contract_hash,
            "split": split.to_dict(),
        }
    )
    model_version = f"tgn-{FEATURE_VERSION}-{training_run_hash[:12]}"
    model.save_checkpoint(
        checkpoint_path,
        metadata={
            "feature_version": FEATURE_VERSION,
            "feature_contract_sha256": contract_hash,
            "dataset_sha256": dataset_sha256,
            "training_run_sha256": training_run_hash,
            "entity_dictionary_sha256": dictionary_hash,
            "feature_names": list(MODEL_FEATURE_NAMES),
            "feature_center": list(normalizer.center),
            "feature_scale": list(normalizer.scale),
            "model_version": model_version,
            "user_capacity": user_capacity,
            "host_capacity": host_capacity,
            "user_dictionary_capacity": user_dictionary_capacity,
            "host_dictionary_capacity": host_dictionary_capacity,
            "oov_user_buckets": config.oov_user_buckets,
            "oov_host_buckets": config.oov_host_buckets,
            "decision_threshold": threshold.threshold,
            "training_seed": config.seed,
        },
    )
    report = TGNTrainingReport(
        schema_version=1,
        graphsentinel_version=__version__,
        model_version=model_version,
        feature_version=FEATURE_VERSION,
        feature_contract_sha256=contract_hash,
        dataset_sha256=dataset_sha256,
        training_run_sha256=training_run_hash,
        entity_dictionary_sha256=dictionary_hash,
        checkpoint_path=str(checkpoint_path.resolve()),
        checkpoint_sha256=_sha256(checkpoint_path),
        events=len(records),
        split=split.to_dict(),
        training_positives_in_loss=positives,
        configuration=model.configuration(),
        training_configuration=asdict(config),
        parameter_count=sum(parameter.numel() for parameter in model.parameters()),
        device=str(torch.device(device)),
        epochs_completed=epochs_completed,
        best_epoch=best_epoch,
        epoch_history=tuple(history),
        interrupted=interrupted,
        threshold_selection=threshold.to_dict(),
        validation_metrics=ranking_metrics(
            validation_labels, validation_scores, threshold=threshold.threshold
        ),
        test_metrics=ranking_metrics(test_labels, test_scores, threshold=threshold.threshold),
        baseline_validation_pr_auc=baseline_pr_auc,
        promotion={
            "eligible": promotion_eligible,
            "model_validation_pr_auc": model_validation_pr_auc,
            "fused_validation_pr_auc": fused_validation_pr_auc,
            "comparison_basis": (
                "raw model scores against raw baseline scores; the fused score "
                "is reported separately because it measures the pipeline, not "
                "the model"
            ),
            "best_baseline_validation_pr_auc": best_baseline,
            "improvement": improvement,
            "gate": (
                "candidate beats the best declared baseline"
                if config.require_baseline_improvement
                else "baseline improvement gate explicitly disabled"
            ),
        },
    )
    _write_json(report_path, report.to_dict())
    best_state_path.unlink(missing_ok=True)
    return report
