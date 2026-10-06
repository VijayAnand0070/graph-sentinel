"""Scoped checkpoint/rollback on the feature engine and the id maps.

The live path relies on this for one invariant: after a batch fails anywhere
downstream, the engine is exactly as it was, so its rolling state and the
model's memory never disagree about what happened. "Exactly" is checked by
comparing full snapshots, not by spot-checking a feature.
"""

from __future__ import annotations

import copy

import pytest

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.ingestion.id_map import StableIdMap


def _event(event_id: int, timestamp: int, user: int, src: int, dst: int, *,
           success: int = 1) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id, timestamp=timestamp, src_user_id=user, dst_user_id=user,
        src_host_id=src, dst_host_id=dst, auth_type_id=3, logon_type_id=1, orientation_id=1,
        success=success, label_redteam=0, day=timestamp // 86_400, hour=(timestamp % 86_400) // 3_600,
    )


def _warm_engine() -> CausalFeatureEngine:
    engine = CausalFeatureEngine()
    history = [_event(i, 100 + i * 7, user=1 + i % 5, src=10 + i % 3, dst=20 + i % 4)
               for i in range(200)]
    list(engine.transform(history))
    return engine


class TestEngineRollback:
    def test_rollback_restores_the_exact_prior_state(self) -> None:
        engine = _warm_engine()
        before = copy.deepcopy(engine.snapshot())
        batch = [_event(500, 5_000, user=2, src=11, dst=23), _event(501, 5_001, user=9, src=99, dst=77)]
        checkpoint = engine.checkpoint(batch)
        list(engine.transform(batch))
        assert engine.snapshot() != before, "precondition: the batch changed something"
        engine.rollback(checkpoint)
        assert engine.snapshot() == before

    def test_rollback_deletes_entities_the_batch_introduced(self) -> None:
        engine = _warm_engine()
        batch = [_event(500, 5_000, user=9, src=99, dst=77)]      # all three are new
        coverage_before = engine.coverage()
        checkpoint = engine.checkpoint(batch)
        list(engine.transform(batch))
        assert engine.coverage()["known_users"] == coverage_before["known_users"] + 1
        engine.rollback(checkpoint)
        assert engine.coverage() == coverage_before

    def test_a_committed_batch_is_untouched_by_a_later_rollback(self) -> None:
        """Only the checkpointed batch is undone; earlier commits stand."""
        engine = _warm_engine()
        first = [_event(500, 5_000, user=2, src=11, dst=23)]
        list(engine.transform(first))
        after_first = copy.deepcopy(engine.snapshot())
        second = [_event(501, 5_100, user=2, src=11, dst=24)]
        checkpoint = engine.checkpoint(second)
        list(engine.transform(second))
        engine.rollback(checkpoint)
        assert engine.snapshot() == after_first

    def test_checkpoint_cost_scales_with_the_batch_not_the_estate(self) -> None:
        """The whole point: a warm engine must not be copied per batch."""
        engine = CausalFeatureEngine()
        list(engine.transform([_event(i, 100 + i, user=i % 400, src=1000 + i % 300, dst=2000 + i % 250)
                               for i in range(3_000)]))
        batch = [_event(9_000, 9_000, user=1, src=1000, dst=2000)]
        checkpoint = engine.checkpoint(batch)
        # Five keys (user, src, dst, two pairs) across every container: a few
        # dozen entries, against thousands of entities in the engine.
        assert len(checkpoint.entries) < 200
        assert engine.coverage()["known_users"] == 400

    def test_features_after_rollback_and_retransform_match_a_clean_run(self) -> None:
        """Rollback must leave no trace that changes what the next batch sees."""
        clean = _warm_engine()
        rolled = _warm_engine()
        batch = [_event(500, 5_000, user=2, src=11, dst=23), _event(501, 5_030, user=2, src=11, dst=23)]
        checkpoint = rolled.checkpoint(batch)
        list(rolled.transform(batch))
        rolled.rollback(checkpoint)
        expected = [r.to_dict() for r in clean.transform(batch)]
        actual = [r.to_dict() for r in rolled.transform(batch)]
        assert actual == expected


class TestIdMapRollback:
    def test_values_encoded_after_the_mark_are_forgotten(self) -> None:
        mapping = StableIdMap("hosts")
        a = mapping.encode("C1")
        mark = mapping.mark()
        b = mapping.encode("C2")
        c = mapping.encode("C3")
        assert (a, b, c) == (1, 2, 3)
        mapping.rollback(mark)
        assert mapping.lookup("C2") is None and mapping.lookup("C3") is None
        assert mapping.lookup("C1") == 1
        assert mapping.encode("C4") == 2, "ids stay dense after a rollback"

    def test_rollback_to_the_current_mark_is_a_no_op(self) -> None:
        mapping = StableIdMap("users")
        mapping.encode("U1")
        mark = mapping.mark()
        mapping.rollback(mark)
        assert mapping.lookup("U1") == 1 and len(mapping) == 2


class TestLiveEngineTransaction:
    def test_a_batch_the_model_refuses_leaves_the_features_untouched(self) -> None:
        """The divergence the transaction exists to prevent."""
        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
        from graphsentinel.api.service import DetectionService

        class RefusingService(DetectionService):
            def score_batch(self, batch):  # type: ignore[override]
                raise ValueError("model refused the batch")

        live = LiveDetectionEngine(RefusingService(threshold=0.5), id_map_dir=None)
        before = copy.deepcopy(live._features.snapshot())
        events = [LiveAuthEvent(timestamp=1_000, user="U1@DOM1", source_host="C1",
                                destination_host="C2", success=True, source="test")]
        with pytest.raises(ValueError, match="refused"):
            live.detect(LiveAuthBatch(events=events))
        assert live._features.snapshot() == before
        assert len(live._maps.users) == 1 and len(live._maps.hosts) == 1, (
            "identifiers encoded for the refused batch must be forgotten too"
        )

    def test_a_successful_batch_advances_the_engine(self) -> None:
        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
        from graphsentinel.api.service import DetectionService

        live = LiveDetectionEngine(DetectionService(threshold=0.5), id_map_dir=None)
        before = copy.deepcopy(live._features.snapshot())
        events = [LiveAuthEvent(timestamp=1_000, user="U1@DOM1", source_host="C1",
                                destination_host="C2", success=True, source="test")]
        live.detect(LiveAuthBatch(events=events))
        assert live._features.snapshot() != before
        assert live._features.coverage()["known_users"] == 1


class TestSaveState:
    """``/api/v1/feature-state/save`` must persist both halves of the
    cumulative state, or a restart restores features newer than the memory
    (caught by the end-to-end check; Finding 24)."""

    def _live(self, tmp_path, monkeypatch):
        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
        from graphsentinel.api.service import DetectionService

        monkeypatch.setenv("GRAPHSENTINEL_FEATURE_STATE", str(tmp_path / "features.json.gz"))
        live = LiveDetectionEngine(DetectionService(threshold=0.5), id_map_dir=None)
        live.detect(LiveAuthBatch(events=[LiveAuthEvent(
            timestamp=1_000, user="U1@DOM1", source_host="C1", destination_host="C2",
            success=True, source="test")]))
        return live

    def test_without_a_model_only_the_features_are_written(self, tmp_path, monkeypatch) -> None:
        live = self._live(tmp_path, monkeypatch)
        saved = live.save_state(memory_path=tmp_path / "memory.npz")
        assert (tmp_path / "features.json.gz").is_file()
        assert saved["model_memory"] is None and saved["warning"] is None
        assert not (tmp_path / "memory.npz").exists()

    def test_with_a_model_both_halves_are_written_together(self, tmp_path, monkeypatch) -> None:
        live = self._live(tmp_path, monkeypatch)
        written: list = []

        class FakeSession:
            def save_memory(self, path):
                path.write_bytes(b"npz")
                written.append(path)
                return {"path": str(path), "nodes_with_memory": 3}

        live.detection._model_session = FakeSession()  # model_loaded becomes True
        saved = live.save_state(memory_path=tmp_path / "memory.npz")
        assert written == [tmp_path / "memory.npz"]
        assert saved["model_memory"]["nodes_with_memory"] == 3
        assert saved["warning"] is None

    def test_a_loaded_model_without_a_memory_path_is_reported(self, tmp_path, monkeypatch) -> None:
        live = self._live(tmp_path, monkeypatch)

        class FakeSession:
            def save_memory(self, path):  # pragma: no cover - must not be called
                raise AssertionError("no path was configured")

        live.detection._model_session = FakeSession()
        saved = live.save_state(memory_path=None)
        assert saved["model_memory"] is None
        assert "GRAPHSENTINEL_TGN_MEMORY" in saved["warning"]
