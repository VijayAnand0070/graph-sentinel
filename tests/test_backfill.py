"""Backfill: building warm deployment state from historical logs.

The guarantee this must provide is that a backfilled deployment behaves like
one that processed the history itself. If it does not, the tool produces a
*different* kind of wrong state rather than fixing the cold-start problem, and
the deployment would have no way to tell.
"""

from __future__ import annotations

import gzip
import json

import pytest

from graphsentinel.features.causal import (MODEL_FEATURE_NAMES,
                                           CausalFeatureEngine)
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.onboarding.backfill import (FEATURE_STATE_NAME,
                                               MANIFEST_NAME, BackfillRunner)

SECONDS_PER_DAY = 86_400


def event(event_id: int, timestamp: int, user: int, src: int, dst: int,
          *, success: int = 1) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id, timestamp=timestamp,
        src_user_id=user, dst_user_id=user,
        src_host_id=src, dst_host_id=dst,
        auth_type_id=3, logon_type_id=1, orientation_id=1,
        success=success, label_redteam=0,
        day=timestamp // SECONDS_PER_DAY,
        hour=(timestamp % SECONDS_PER_DAY) // 3_600,
    )


def history(count: int = 300) -> list[NormalizedAuthEvent]:
    return [
        event(i, 1_000 + i * 41, user=i % 9, src=100 + (i % 13), dst=200 + (i % 17),
              success=0 if i % 19 == 0 else 1)
        for i in range(count)
    ]


def vector(record) -> tuple[float, ...]:
    return tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES)


def test_backfilled_state_matches_continuous_processing(tmp_path) -> None:
    """The core guarantee: warm start is indistinguishable from never stopping."""
    past, future = history()[:220], history()[220:]

    continuous = CausalFeatureEngine()
    list(continuous.transform(past))
    expected = [vector(r) for r in continuous.transform(future)]

    runner = BackfillRunner()
    runner.run(iter(past), tmp_path)

    restored = CausalFeatureEngine()
    with gzip.open(tmp_path / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        restored.restore(json.load(handle))
    actual = [vector(r) for r in restored.transform(future)]

    assert actual == expected


def test_without_backfill_the_features_differ(tmp_path) -> None:
    """Keeps the test above from passing for the wrong reason."""
    past, future = history()[:220], history()[220:]

    continuous = CausalFeatureEngine()
    list(continuous.transform(past))
    expected = [vector(r) for r in continuous.transform(future)]

    cold = [vector(r) for r in CausalFeatureEngine().transform(future)]
    assert cold != expected


def test_manifest_records_provenance(tmp_path) -> None:
    """A state artifact with no provenance cannot be audited or reproduced."""
    result = BackfillRunner().run(iter(history()), tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_NAME).read_text(encoding="utf-8"))

    assert manifest["events"] == result.events == len(history())
    assert manifest["feature_version"] == "auth-causal-v1"
    assert manifest["feature_names"] == list(MODEL_FEATURE_NAMES)
    assert manifest["feature_coverage"]["known_users"] == 9
    # Every artifact it wrote is hashed, so tampering or truncation is detectable.
    digest = manifest["artifacts"][FEATURE_STATE_NAME]
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def test_state_file_is_not_a_pickle(tmp_path) -> None:
    """A security product must not load an executable state file at startup."""
    BackfillRunner().run(iter(history()), tmp_path)
    with gzip.open(tmp_path / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        payload = json.load(handle)          # parses as plain JSON, or this fails
    assert payload["version"] == CausalFeatureEngine.SNAPSHOT_VERSION


def test_empty_input_is_rejected(tmp_path) -> None:
    """Silently writing an empty snapshot would look like a successful backfill
    and restore as a cold engine."""
    with pytest.raises(ValueError, match="no events"):
        BackfillRunner().run(iter([]), tmp_path)


def test_without_a_checkpoint_only_feature_state_is_built(tmp_path) -> None:
    result = BackfillRunner().run(iter(history()), tmp_path)
    assert result.feature_state_path is not None
    assert result.tgn_memory_path is None
    assert result.memory_coverage == {}


def test_coverage_reflects_the_replayed_history(tmp_path) -> None:
    result = BackfillRunner().run(iter(history()), tmp_path)
    assert result.feature_coverage["known_users"] == 9
    assert result.feature_coverage["known_pairs"] > 0
    assert result.feature_coverage["last_processed_timestamp"] > 0
    assert result.events == 300


class TestParquetAdapter:
    def test_missing_columns_are_reported_by_name(self, tmp_path) -> None:
        """A parquet lacking required columns must fail loudly at read time,
        not produce silently wrong state."""
        import polars as pl

        from graphsentinel.onboarding.backfill import events_from_parquet

        path = tmp_path / "bad.parquet"
        pl.DataFrame({"event_id": [1], "timestamp": [10]}).write_parquet(path)
        with pytest.raises(ValueError, match="missing required columns"):
            list(events_from_parquet(path))

    def test_events_are_yielded_in_chronological_order(self, tmp_path) -> None:
        """The feature engine requires chronological input; replaying out of
        order would build state production never sees."""
        import polars as pl

        from graphsentinel.onboarding.backfill import events_from_parquet

        path = tmp_path / "shuffled.parquet"
        size = 50
        pl.DataFrame({
            "event_id": list(range(size)),
            "timestamp": [(i * 7919) % 9973 for i in range(size)],   # scrambled
            "src_user_id": [i % 5 for i in range(size)],
            "dst_user_id": [i % 5 for i in range(size)],
            "src_host_id": [100 + i % 7 for i in range(size)],
            "dst_host_id": [200 + i % 11 for i in range(size)],
            "auth_type_id": [3] * size,
            "logon_type_id": [1] * size,
            "orientation_id": [1] * size,
            "success": [1] * size,
        }).write_parquet(path)

        timestamps = [e.timestamp for e in events_from_parquet(path)]
        assert timestamps == sorted(timestamps)

    def test_limit_truncates_the_replay(self, tmp_path) -> None:
        import polars as pl

        from graphsentinel.onboarding.backfill import events_from_parquet

        path = tmp_path / "events.parquet"
        size = 40
        pl.DataFrame({
            "event_id": list(range(size)),
            "timestamp": [1_000 + i for i in range(size)],
            "src_user_id": [i % 5 for i in range(size)],
            "dst_user_id": [i % 5 for i in range(size)],
            "src_host_id": [100 + i % 7 for i in range(size)],
            "dst_host_id": [200 + i % 11 for i in range(size)],
            "auth_type_id": [3] * size,
            "logon_type_id": [1] * size,
            "orientation_id": [1] * size,
            "success": [1] * size,
        }).write_parquet(path)

        assert len(list(events_from_parquet(path, limit=10))) == 10
