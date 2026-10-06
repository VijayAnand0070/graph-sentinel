from pathlib import Path

import torch

from graphsentinel.api.live import LiveDetectionEngine
from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
from graphsentinel.api.service import DetectionService
from graphsentinel.features.causal import MODEL_FEATURE_NAMES
from graphsentinel.ingestion.id_map import AuthIdMaps, auth_id_map_sha256
from graphsentinel.models.serving import load_inference_session
from graphsentinel.models.tgn import TemporalGraphNetwork


def test_live_model_promotion_reloads_dictionary_and_resets_generation(tmp_path: Path) -> None:
    id_map_dir = tmp_path / "id-maps"
    service = DetectionService(threshold=0.99)
    live = LiveDetectionEngine(service, id_map_dir=id_map_dir)
    live.detect(
        LiveAuthBatch(
            events=(
                LiveAuthEvent(
                    timestamp=10,
                    user="dynamic-user",
                    source_host="dynamic-a",
                    destination_host="dynamic-b",
                    success=True,
                ),
            )
        )
    )

    maps = AuthIdMaps()
    maps.users.encode("known-user")
    maps.hosts.encode("known-source")
    maps.hosts.encode("known-destination")
    maps.auth_types.encode("Kerberos")
    maps.logon_types.encode("Network")
    maps.orientations.encode("LogOn")
    maps.save(id_map_dir)
    dictionary_hash = auth_id_map_sha256(id_map_dir)
    user_buckets = 4
    host_buckets = 64
    model = TemporalGraphNetwork(
        num_nodes=len(maps.users) + user_buckets + len(maps.hosts) + host_buckets,
        message_dim=len(MODEL_FEATURE_NAMES),
        memory_dim=6,
        time_dim=4,
        hidden_dim=8,
        dropout=0,
    )
    checkpoint = tmp_path / "model.pt"
    model.save_checkpoint(
        checkpoint,
        metadata={
            "feature_version": "auth-causal-v1",
            "feature_contract_sha256": "a" * 64,
            "dataset_sha256": "b" * 64,
            "training_run_sha256": "c" * 64,
            "model_version": "promotion-test",
            "user_capacity": len(maps.users) + user_buckets,
            "host_capacity": len(maps.hosts) + host_buckets,
            "user_dictionary_capacity": len(maps.users),
            "host_dictionary_capacity": len(maps.hosts),
            "oov_user_buckets": user_buckets,
            "oov_host_buckets": host_buckets,
            "entity_dictionary_sha256": dictionary_hash,
            "feature_names": list(MODEL_FEATURE_NAMES),
            "feature_center": [0.0] * len(MODEL_FEATURE_NAMES),
            "feature_scale": [1.0] * len(MODEL_FEATURE_NAMES),
            "decision_threshold": 0.7,
        },
    )
    session = load_inference_session(checkpoint)

    live.promote_model(session, threshold=0.7)
    result = live.detect(
        LiveAuthBatch(
            events=(
                LiveAuthEvent(
                    timestamp=20,
                    user="known-user",
                    source_host="known-source",
                    destination_host="known-destination",
                    auth_type="Kerberos",
                    logon_type="Network",
                    orientation="LogOn",
                    success=True,
                ),
            )
        )
    )

    assert len(result.results) == 1
    status = live.status()
    assert status.mode == "temporal_model"
    assert status.frozen_entity_dictionary is True
    assert status.entity_dictionary_sha256 == dictionary_hash
    assert status.model_generation == 1
    assert status.state_reset_count == 1
    assert service.threshold == 0.7
    assert torch.isfinite(torch.tensor(result.results[0].risk))

    unseen = live.detect(
        LiveAuthBatch(
            events=(
                LiveAuthEvent(
                    timestamp=30,
                    user="new-user",
                    source_host="new-source",
                    destination_host="new-destination",
                    auth_type="new-auth-protocol",
                    logon_type="Network",
                    orientation="LogOn",
                    success=True,
                ),
            )
        )
    )
    assert len(unseen.results) == 1
    assert live.status().oov_identifiers == {
        "auth type": 1,
        "destination host": 1,
        "destination user": 1,
        "source host": 1,
        "user": 1,
    }
