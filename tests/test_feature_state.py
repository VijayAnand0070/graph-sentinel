"""Feature-engine state persistence.

The property under test is that a restored engine is indistinguishable from
one that processed the whole history itself. Anything less and a restart
silently degrades detection, which is exactly the defect this exists to fix:
twelve of the 27 features are cumulative and no amount of warm-up rebuilds
them, so losing them at restart loses them for good.
"""

from __future__ import annotations

import pytest

from graphsentinel.features.causal import (MODEL_FEATURE_NAMES,
                                           CausalFeatureEngine)
from graphsentinel.ingestion.auth import NormalizedAuthEvent

SECONDS_PER_DAY = 86_400


def event(event_id: int, timestamp: int, user: int, src: int, dst: int,
          *, success: int = 1, logon: int = 1) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id, timestamp=timestamp,
        src_user_id=user, dst_user_id=user,
        src_host_id=src, dst_host_id=dst,
        auth_type_id=3, logon_type_id=logon, orientation_id=1,
        success=success, label_redteam=0,
        day=timestamp // SECONDS_PER_DAY,
        hour=(timestamp % SECONDS_PER_DAY) // 3_600,
    )


def history(count: int = 240) -> list[NormalizedAuthEvent]:
    """Traffic with repeated pairs, varied hosts and some failures.

    Deliberately exercises every state category: cumulative pair counts,
    per-user last-seen, host degree sets, logon-type histograms and all four
    rolling windows.
    """
    events = []
    for i in range(count):
        events.append(event(
            event_id=i,
            timestamp=1_000 + i * 37,
            user=i % 7,
            src=100 + (i % 11),
            dst=200 + (i % 13),
            success=0 if i % 17 == 0 else 1,
            logon=4 if i % 23 == 0 else 1,
        ))
    return events


def vector(record) -> tuple[float, ...]:
    return tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES)


def test_restored_engine_matches_one_that_saw_everything() -> None:
    """The central guarantee. Identical features, feature by feature."""
    past, future = history()[:180], history()[180:]

    continuous = CausalFeatureEngine()
    list(continuous.transform(past))
    expected = [vector(r) for r in continuous.transform(future)]

    warm = CausalFeatureEngine()
    list(warm.transform(past))
    restored = CausalFeatureEngine()
    restored.restore(warm.snapshot())
    actual = [vector(r) for r in restored.transform(future)]

    assert actual == expected


def test_a_cold_engine_gets_it_wrong() -> None:
    """Guards the test above from being vacuous.

    If a cold engine produced the same features, persistence would buy
    nothing and the first test would pass for the wrong reason.
    """
    past, future = history()[:180], history()[180:]

    continuous = CausalFeatureEngine()
    list(continuous.transform(past))
    expected = [vector(r) for r in continuous.transform(future)]

    cold = CausalFeatureEngine()
    actual = [vector(r) for r in cold.transform(future)]

    assert actual != expected


def test_cold_engine_calls_established_pairs_new() -> None:
    """The most damaging single consequence, pinned directly.

    `is_new_pair` is the strongest feature in the set. A cold engine reports
    it as 1 for pairs that are long established, because it has never
    personally seen them.
    """
    past, future = history()[:180], history()[180:]
    index = MODEL_FEATURE_NAMES.index("is_new_pair")

    warm = CausalFeatureEngine()
    list(warm.transform(past))
    warm_new = sum(vector(r)[index] for r in warm.transform(future))

    cold = CausalFeatureEngine()
    cold_new = sum(vector(r)[index] for r in cold.transform(future))

    assert cold_new > warm_new


def test_snapshot_roundtrips_through_plain_data() -> None:
    """Snapshots must survive JSON, so they are not tied to a pickle format."""
    import json

    engine = CausalFeatureEngine()
    list(engine.transform(history()))
    encoded = json.loads(json.dumps(engine.snapshot()))

    restored = CausalFeatureEngine()
    restored.restore(encoded)
    assert restored.coverage() == engine.coverage()


def test_restore_rejects_an_unknown_version() -> None:
    """A silently-ignored version mismatch would restore partial state and
    look like it worked."""
    engine = CausalFeatureEngine()
    list(engine.transform(history()))
    state = engine.snapshot()
    state["version"] = 999

    with pytest.raises(ValueError, match="not supported"):
        CausalFeatureEngine().restore(state)


def test_restore_replaces_rather_than_merges() -> None:
    """Restoring over a used engine must not leave traces of the old state."""
    first = CausalFeatureEngine()
    list(first.transform(history()[:90]))

    second = CausalFeatureEngine()
    list(second.transform(history()))
    target = second.coverage()

    first.restore(second.snapshot())
    assert first.coverage() == target


class TestCoverage:
    def test_a_fresh_engine_reports_no_history(self) -> None:
        assert CausalFeatureEngine().coverage() == {
            "known_pairs": 0,
            "known_users": 0,
            "known_source_hosts": 0,
            "known_destination_hosts": 0,
            "known_account_sources": 0,
            "last_processed_timestamp": 0,
        }

    def test_coverage_grows_with_observed_traffic(self) -> None:
        engine = CausalFeatureEngine()
        list(engine.transform(history()))
        coverage = engine.coverage()
        assert coverage["known_users"] == 7
        assert coverage["known_pairs"] > 0
        assert coverage["last_processed_timestamp"] > 0
