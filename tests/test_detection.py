import pytest

from graphsentinel.detection.fusion import FusionConfig, RiskComponents, fuse_risk
from graphsentinel.detection.path_ranker import (
    PathRanker,
    PathRankerConfig,
    ScoredAuthEvent,
    StreamingPathTracker,
)


def _scored(
    event_id: int, time: int, source: int, destination: int, risk: float = 0.9
) -> ScoredAuthEvent:
    return ScoredAuthEvent(
        event_id=event_id,
        timestamp=time,
        user_id=event_id + 100,
        source_host_id=source,
        destination_host_id=destination,
        risk=risk,
        is_new_relationship=True,
        evidence_support=0.5,
    )


def test_fusion_is_decomposable_and_bounded() -> None:
    result = fuse_risk(RiskComponents(0.9, 0.8, 0.7, 0.6, 0.5))

    assert result.score == pytest.approx(sum(result.contributions().values()))
    assert 0 <= result.score <= 1
    assert result.contributions()["tgn"] == pytest.approx(0.495)


def test_fusion_rejects_invalid_weights_and_probabilities() -> None:
    with pytest.raises(ValueError, match="sum to one"):
        FusionConfig(tgn=1, novelty=1)
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        RiskComponents(1.1, 0, 0, 0, 0)


def test_path_ranker_builds_strictly_increasing_pivot_chain() -> None:
    events = [_scored(0, 10, 1, 2), _scored(1, 20, 2, 3), _scored(2, 30, 3, 4)]

    paths = PathRanker().rank(events)

    assert paths[0].event_ids == (0, 1, 2)
    assert paths[0].host_ids == (1, 2, 3, 4)
    assert paths[0].timestamps == (10, 20, 30)


def test_path_ranker_excludes_same_time_cycles_and_low_risk_edges() -> None:
    events = [
        _scored(0, 10, 1, 2),
        _scored(1, 10, 2, 3),
        _scored(2, 20, 2, 1),
        _scored(3, 20, 2, 4, risk=0.1),
    ]

    assert PathRanker().rank(events) == []


def test_path_ranker_enforces_forward_window() -> None:
    ranker = PathRanker(PathRankerConfig(forward_window_seconds=5))

    assert ranker.rank([_scored(0, 1, 1, 2), _scored(1, 7, 2, 3)]) == []


def test_streaming_tracker_completes_paths_across_requests_transactionally() -> None:
    tracker = StreamingPathTracker()
    first = tracker.preview([_scored(0, 10, 1, 2)])
    assert first.new_paths == ()
    tracker.commit(first)

    second = tracker.preview([_scored(1, 20, 2, 3)])

    assert second.new_paths[0].event_ids == (0, 1)
    tracker.commit(second)
    with pytest.raises(RuntimeError, match="stale"):
        tracker.commit(second)


def test_streaming_tracker_ranks_the_whole_request_not_only_its_tail() -> None:
    """A replayed day arrives as requests spanning far more than the horizon.

    The horizon bounds what is carried forward between requests; it must not
    decide what gets ranked, or every path earlier than the request's last
    nine thousand seconds is silently lost -- which is what a bulk replay is
    almost entirely made of.
    """
    tracker = StreamingPathTracker()
    horizon = (
        tracker.ranker.config.forward_window_seconds * tracker.ranker.config.max_hops
    )
    chain = [_scored(0, 10_000, 1, 2), _scored(1, 10_030, 2, 3), _scored(2, 10_060, 3, 4)]
    # ... followed, in the same request, by unrelated traffic hours later.
    tail = [_scored(9, 10_060 + horizon + 600, 7, 8)]

    preview = tracker.preview([*chain, *tail])

    assert preview.new_paths[0].event_ids == (0, 1, 2)
    # What is carried forward is still bounded by the horizon.
    assert all(
        event.timestamp > tail[-1].timestamp - horizon for event in preview.next_history
    )
    tracker.commit(preview)


def test_streaming_tracker_requires_equal_times_in_one_request() -> None:
    tracker = StreamingPathTracker()
    tracker.commit(tracker.preview([_scored(0, 10, 1, 2)]))

    with pytest.raises(ValueError, match="combine equal timestamps"):
        tracker.preview([_scored(1, 10, 2, 3)])
