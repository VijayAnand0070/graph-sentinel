from __future__ import annotations

from pathlib import Path

import pytest
import torch

from graphsentinel.graph.temporal import TemporalGraphEvent
from graphsentinel.models.tgn import (
    TemporalBatch,
    TemporalGraphNetwork,
    to_pyg_temporal_data,
)
from graphsentinel.models.training import time_window_groups, train_epoch


def _event(
    event_id: int,
    timestamp: int,
    source: int,
    destination: int,
    label: int = 0,
) -> TemporalGraphEvent:
    return TemporalGraphEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_node=source,
        destination_node=destination,
        origin_host_node=4,
        message=(1.0, 0.5, 0.0),
        label_redteam=label,
    )


def _model() -> TemporalGraphNetwork:
    torch.manual_seed(7)
    return TemporalGraphNetwork(
        num_nodes=8,
        message_dim=3,
        memory_dim=6,
        time_dim=4,
        hidden_dim=8,
        dropout=0.0,
    )


def test_scoring_does_not_mutate_temporal_state() -> None:
    model = _model().eval()
    state = model.initial_state()
    batch = TemporalBatch.from_events([_event(0, 1, 1, 5)])
    memory_before = state.memory.clone()
    time_before = state.last_update.clone()

    logits = model.score(batch, state)

    assert logits.shape == (1,)
    assert torch.equal(state.memory, memory_before)
    assert torch.equal(state.last_update, time_before)
    assert state.stream_timestamp is None


def test_update_aggregates_equal_timestamp_messages_once_per_node() -> None:
    model = _model().eval()
    state = model.initial_state()
    batch = TemporalBatch.from_events([_event(0, 1, 1, 5), _event(1, 1, 1, 6)])

    updated = model.update(batch, state)

    assert updated.stream_timestamp == 1
    assert not torch.equal(updated.memory[1], state.memory[1])
    assert updated.last_update[1].item() == 1
    assert torch.equal(updated.memory[0], state.memory[0])


def test_memory_updater_receives_gradient_from_future_event() -> None:
    model = _model().train()
    initial = model.initial_state()
    first = TemporalBatch.from_events([_event(0, 1, 1, 5)])
    second = TemporalBatch.from_events([_event(1, 2, 1, 6, label=1)])

    _, state = model.step(first, initial)
    logits = model.score(second, state)
    torch.nn.functional.binary_cross_entropy_with_logits(logits, second.labels).backward()

    assert model.memory_updater.weight_hh.grad is not None
    assert model.message_function[0].weight.grad is not None


def test_training_epoch_uses_chronology_and_truncation() -> None:
    model = _model()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    events = [
        _event(0, 1, 1, 5),
        _event(1, 2, 1, 6, 1),
        _event(2, 3, 2, 7),
    ]

    result = train_epoch(
        model,
        events,
        optimizer,
        positive_weight=2.0,
        truncate_after_events=2,
    )

    assert result.events == 3
    assert result.positives == 1
    assert result.optimizer_steps == 2
    assert result.final_state.stream_timestamp == 3


def test_pyg_adapter_preserves_temporal_fields() -> None:
    events = [_event(0, 1, 1, 5), _event(1, 2, 2, 6, 1)]

    data = to_pyg_temporal_data(events)

    assert data.src.tolist() == [1, 2]
    assert data.dst.tolist() == [5, 6]
    assert data.t.tolist() == [1, 2]
    assert data.origin_host.tolist() == [4, 4]
    assert data.msg.shape == (2, 3)


def test_checkpoint_contains_configuration_and_metadata(tmp_path: Path) -> None:
    path = tmp_path / "tgn.pt"
    model = _model()

    model.save_checkpoint(path, metadata={"feature_version": "auth-causal-v1"})
    payload = torch.load(path, weights_only=False)

    assert payload["schema_version"] == 1
    assert payload["configuration"]["memory_dim"] == 6
    assert payload["metadata"]["feature_version"] == "auth-causal-v1"


def test_temporal_batch_rejects_mixed_timestamps() -> None:
    with pytest.raises(ValueError, match="shared timestamp"):
        TemporalBatch.from_events([_event(0, 1, 1, 5), _event(1, 2, 1, 6)])


def test_temporal_batch_time_window_uses_last_timestamp() -> None:
    batch = TemporalBatch.from_events(
        [_event(0, 1, 1, 5), _event(1, 2, 1, 6)], allow_time_window=True
    )

    assert batch.timestamp == 2


def test_temporal_batch_time_window_rejects_decreasing_timestamps() -> None:
    with pytest.raises(ValueError, match="non-decreasing"):
        TemporalBatch.from_events(
            [_event(0, 2, 1, 5), _event(1, 1, 1, 6)], allow_time_window=True
        )


def test_time_window_groups_buckets_by_fixed_width_window() -> None:
    events = [
        _event(0, 0, 1, 5),
        _event(1, 4, 1, 6),
        _event(2, 5, 1, 6),
        _event(3, 11, 2, 7),
    ]

    groups = list(time_window_groups(events, window_seconds=5))

    assert [[event.event_id for event in group] for group in groups] == [[0, 1], [2], [3]]


def test_time_window_groups_rejects_nonpositive_window() -> None:
    with pytest.raises(ValueError, match="positive"):
        list(time_window_groups([_event(0, 1, 1, 5)], window_seconds=0))


def test_time_window_groups_rejects_decreasing_timestamps() -> None:
    with pytest.raises(ValueError, match="non-decreasing"):
        list(time_window_groups([_event(0, 2, 1, 5), _event(1, 1, 1, 6)], window_seconds=5))


def test_training_epoch_with_time_window_batches_across_timestamps() -> None:
    model = _model()
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    events = [
        _event(0, 1, 1, 5),
        _event(1, 2, 1, 6, 1),
        _event(2, 3, 2, 7),
        _event(3, 20, 2, 5),
    ]

    result = train_epoch(
        model,
        events,
        optimizer,
        positive_weight=2.0,
        truncate_after_events=2,
        window_seconds=5,
    )

    assert result.events == 4
    assert result.positives == 1
    assert result.final_state.stream_timestamp == 20
