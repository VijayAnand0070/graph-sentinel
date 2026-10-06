from __future__ import annotations

import pytest

from graphsentinel.features.causal import MODEL_FEATURE_NAMES, CausalFeatureEngine
from graphsentinel.graph.temporal import NodeIdSpace, RecentNeighborStore, TemporalGraphEvent
from graphsentinel.ingestion.auth import NormalizedAuthEvent


def _graph_event(event_id: int, timestamp: int, destination: int) -> TemporalGraphEvent:
    return TemporalGraphEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_node=1,
        destination_node=destination,
        origin_host_node=10,
        message=(1.0,),
        label_redteam=0,
    )


def test_typed_node_space_has_no_user_host_collisions() -> None:
    space = NodeIdSpace(user_capacity=10, host_capacity=20)

    assert space.user(4) == 4
    assert space.host(4) == 14
    assert space.type_of(4) == "user"
    assert space.type_of(14) == "host"
    assert space.node_count == 30


def test_equal_time_events_cannot_see_each_other() -> None:
    store = RecentNeighborStore(max_neighbors=5)

    first_contexts = store.contextualize_group([_graph_event(0, 1, 20), _graph_event(1, 1, 21)])
    second_context = store.contextualize_group([_graph_event(2, 2, 22)])[0]

    assert not first_contexts[0].source_neighbors
    assert not first_contexts[1].source_neighbors
    assert len(second_context.source_neighbors) == 2


def test_neighbor_store_is_bounded_and_time_filtered() -> None:
    store = RecentNeighborStore(max_neighbors=2, window_seconds=5)
    store.contextualize_group([_graph_event(0, 1, 20)])
    store.contextualize_group([_graph_event(1, 2, 21)])
    store.contextualize_group([_graph_event(2, 3, 22)])

    assert [item.event_id for item in store.neighbors_before(1, 4)] == [1, 2]
    assert store.neighbors_before(1, 8) == ()


def test_temporal_event_uses_frozen_message_order() -> None:
    normalized = NormalizedAuthEvent(
        event_id=0,
        timestamp=1,
        src_user_id=1,
        dst_user_id=1,
        src_host_id=1,
        dst_host_id=2,
        auth_type_id=1,
        logon_type_id=1,
        orientation_id=1,
        success=1,
        label_redteam=0,
        day=0,
        hour=0,
    )
    record = next(CausalFeatureEngine().transform([normalized]))

    event = TemporalGraphEvent.from_feature_record(
        record, NodeIdSpace(user_capacity=3, host_capacity=4)
    )

    assert len(event.message) == len(MODEL_FEATURE_NAMES)
    assert event.source_node == 1
    assert event.destination_node == 5


def test_neighbor_store_rejects_repeated_group_timestamp() -> None:
    store = RecentNeighborStore()
    store.contextualize_group([_graph_event(0, 1, 20)])

    with pytest.raises(ValueError, match="strictly increase"):
        store.contextualize_group([_graph_event(1, 1, 21)])
