from __future__ import annotations

import math

import pytest

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent


def _event(
    event_id: int,
    timestamp: int,
    *,
    user: int = 1,
    src: int = 1,
    dst: int = 2,
    success: int = 1,
) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_user_id=user,
        dst_user_id=user,
        src_host_id=src,
        dst_host_id=dst,
        auth_type_id=1,
        logon_type_id=1,
        orientation_id=1,
        success=success,
        label_redteam=0,
        day=timestamp // 86_400,
        hour=(timestamp % 86_400) // 3_600,
    )


def test_equal_timestamps_share_identical_prior_state() -> None:
    events = [_event(0, 10), _event(1, 10), _event(2, 11)]

    records = list(CausalFeatureEngine().transform(events))

    assert records[0].is_new_pair == 1
    assert records[1].is_new_pair == 1
    assert records[0].pair_frequency_1h == 0
    assert records[1].pair_frequency_1h == 0
    assert records[2].is_new_pair == 0
    assert records[2].pair_frequency_1h == 2


def test_failure_context_and_deltas_are_causal() -> None:
    events = [_event(0, 1, success=0), _event(1, 3, success=1)]

    first, second = CausalFeatureEngine().transform(events)

    assert first.failures_before_success_15m == 0
    assert second.failures_before_success_15m == 1
    assert second.user_failure_rate_15m == 1.0
    assert second.delta_user_log == pytest.approx(math.log1p(2))
    assert second.user_auth_rate_5m == 1


def test_window_boundaries_exclude_expired_events() -> None:
    events = [_event(0, 1), _event(1, 301, dst=3), _event(2, 302, dst=4)]

    records = list(CausalFeatureEngine().transform(events))

    assert records[1].user_unique_dst_5m == 0
    assert records[1].user_unique_dst_1h == 1
    assert records[2].user_unique_dst_5m == 1


def test_out_of_order_stream_is_rejected() -> None:
    engine = CausalFeatureEngine()

    with pytest.raises(ValueError, match="non-decreasing"):
        list(engine.transform([_event(0, 10), _event(1, 9)]))


def test_score_group_rejects_mixed_timestamps() -> None:
    with pytest.raises(ValueError, match="shared timestamp"):
        CausalFeatureEngine().score_group([_event(0, 1), _event(1, 2)])


def test_separate_equal_timestamp_groups_are_rejected() -> None:
    engine = CausalFeatureEngine()
    engine.score_group([_event(0, 1)])

    with pytest.raises(ValueError, match="combine equal timestamps"):
        engine.score_group([_event(1, 1)])
