from pathlib import Path

import pytest
import torch

from graphsentinel.models.serving import (
    CheckpointError,
    InferenceEvent,
    load_inference_session,
)
from graphsentinel.models.tgn import TemporalGraphNetwork


def _checkpoint(path: Path, *, feature_version: str = "auth-causal-v1") -> None:
    model = TemporalGraphNetwork(
        num_nodes=8,
        message_dim=3,
        memory_dim=6,
        time_dim=4,
        hidden_dim=8,
        dropout=0,
    )
    model.save_checkpoint(
        path,
        metadata={
            "feature_version": feature_version,
            "model_version": "test-1",
            "user_capacity": 3,
            "host_capacity": 5,
        },
    )


def _event(event_id: int, timestamp: int) -> InferenceEvent:
    return InferenceEvent(
        event_id=event_id,
        timestamp=timestamp,
        user_id=1,
        source_host_id=1,
        destination_host_id=2,
        message=(1.0, 0.5, 0.0),
    )


def test_preview_is_transactional_until_committed(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    _checkpoint(path)
    session = load_inference_session(path)

    preview = session.preview([_event(1, 10)])

    assert session.stream_timestamp is None
    assert session.state_version == 0
    assert len(preview.probabilities) == 1
    session.commit(preview)
    assert session.stream_timestamp == 10
    assert session.state_version == 1


def test_stale_preview_cannot_overwrite_newer_state(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    _checkpoint(path)
    session = load_inference_session(path)
    first = session.preview([_event(1, 10)])
    stale = session.preview([_event(2, 20)])
    session.commit(first)

    with pytest.raises(RuntimeError, match="stale"):
        session.commit(stale)


def test_checkpoint_loader_validates_feature_version_and_hash(tmp_path: Path) -> None:
    path = tmp_path / "model.pt"
    _checkpoint(path)

    session = load_inference_session(path)

    assert len(session.provenance.sha256) == 64
    assert session.provenance.user_capacity == 3
    assert session.provenance.host_capacity == 5
    with pytest.raises(CheckpointError, match="feature version mismatch"):
        load_inference_session(path, expected_feature_version="wrong-version")


def test_checkpoint_loader_rejects_unsafe_or_invalid_payload(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pt"
    torch.save({"schema_version": 99}, path)

    with pytest.raises(CheckpointError, match="unsupported checkpoint"):
        load_inference_session(path)
