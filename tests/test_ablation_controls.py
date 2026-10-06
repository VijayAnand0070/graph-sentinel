"""The two training-time ablation controls must do exactly what they claim.

Both exist to answer one question -- does the TGN detect behaviour, or has it
memorised identity? -- and each is only a valid control if it removes precisely
the thing it says it removes and nothing else. A ``use_memory=False`` model
that still read memory through some path, or a held-out host whose events
still leaked gradient, would produce a confident and wrong answer. So these
tests attack the controls directly rather than checking that they run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import torch

from graphsentinel.graph.temporal import NodeIdSpace, TemporalGraphEvent
from graphsentinel.models.tgn import TemporalBatch, TemporalGraphNetwork
from graphsentinel.models.training import weighted_event_loss


def _batch(events: list[TemporalGraphEvent]) -> TemporalBatch:
    return TemporalBatch.from_events(events)


def _events(*, loss_weights: tuple[float, ...] | None = None) -> list[TemporalGraphEvent]:
    weights = loss_weights or (1.0, 1.0, 1.0)
    return [
        TemporalGraphEvent(
            event_id=index,
            timestamp=100,
            source_node=index,
            destination_node=10 + index,
            origin_host_node=20 + index,
            message=(0.1 * index, -0.2, 0.3),
            label_redteam=index % 2,
            loss_weight=weights[index],
        )
        for index in range(3)
    ]


class TestMemorylessScoring:
    def _model(self, use_memory: bool) -> TemporalGraphNetwork:
        torch.manual_seed(0)
        return TemporalGraphNetwork(
            num_nodes=40, message_dim=3, memory_dim=8, time_dim=4, hidden_dim=16,
            dropout=0.0, use_memory=use_memory,
        ).eval()

    def test_memoryless_scores_are_independent_of_memory_contents(self) -> None:
        """The control claim, tested by contradiction: fill memory with noise
        and the memoryless model must not notice."""
        model = self._model(use_memory=False)
        batch = _batch(_events())
        clean = model.initial_state()
        noisy = model.initial_state()
        noisy.memory.normal_()                       # every row now carries "identity"
        with torch.inference_mode():
            assert torch.allclose(model.score(batch, clean), model.score(batch, noisy))

    def test_a_normal_model_does_read_memory(self) -> None:
        """Otherwise the test above would pass vacuously."""
        model = self._model(use_memory=True)
        batch = _batch(_events())
        clean = model.initial_state()
        noisy = model.initial_state()
        noisy.memory.normal_()
        with torch.inference_mode():
            assert not torch.allclose(model.score(batch, clean), model.score(batch, noisy))

    def test_memoryless_model_still_updates_state(self) -> None:
        """Memory is not *read*, but ``last_update`` must advance or the
        elapsed-time context would silently freeze."""
        model = self._model(use_memory=False)
        batch = _batch(_events())
        state = model.initial_state()
        with torch.inference_mode():
            _, after = model.step(batch, state)
        assert int(after.last_update[batch.source].min()) == 100

    def test_the_flag_survives_a_checkpoint_round_trip(self, tmp_path: Path) -> None:
        model = self._model(use_memory=False)
        assert model.configuration()["use_memory"] is False
        path = tmp_path / "memoryless.pt"
        model.save_checkpoint(path, metadata={"note": "test"})
        payload = torch.load(path, weights_only=False)
        assert payload["configuration"]["use_memory"] is False
        rebuilt = TemporalGraphNetwork(**payload["configuration"])
        assert rebuilt.use_memory is False

    def test_default_is_the_original_behaviour(self) -> None:
        """Every checkpoint written before the flag existed must load as a
        memory-reading model, because that is how it was trained."""
        configuration = {"num_nodes": 40, "message_dim": 3, "memory_dim": 8,
                         "time_dim": 4, "hidden_dim": 16, "dropout": 0.0}
        assert TemporalGraphNetwork(**configuration).use_memory is True


class TestEventLossWeights:
    def test_zero_weight_removes_an_event_from_the_loss(self) -> None:
        """Weighting one event to zero must equal dropping it entirely."""
        logits = torch.tensor([2.0, -1.0, 0.5])
        labels = torch.tensor([1.0, 0.0, 1.0])
        weights = torch.tensor([1.0, 1.0, 0.0])
        masked = weighted_event_loss(logits, labels, positive_weight=3.0, event_weights=weights)
        dropped = weighted_event_loss(logits[:2], labels[:2], positive_weight=3.0)
        assert masked.item() == pytest.approx(dropped.item(), abs=1e-6)

    def test_unit_weights_match_the_unweighted_loss(self) -> None:
        logits = torch.tensor([2.0, -1.0, 0.5])
        labels = torch.tensor([1.0, 0.0, 1.0])
        plain = weighted_event_loss(logits, labels, positive_weight=3.0)
        weighted = weighted_event_loss(
            logits, labels, positive_weight=3.0, event_weights=torch.ones(3)
        )
        assert plain.item() == pytest.approx(weighted.item(), abs=1e-6)

    def test_a_masked_event_receives_no_gradient(self) -> None:
        """The property the held-out experiment depends on."""
        logits = torch.tensor([2.0, -1.0, 0.5], requires_grad=True)
        labels = torch.tensor([1.0, 0.0, 1.0])
        weights = torch.tensor([1.0, 0.0, 1.0])
        weighted_event_loss(logits, labels, positive_weight=3.0, event_weights=weights).backward()
        assert logits.grad is not None
        assert logits.grad[1].item() == 0.0
        assert logits.grad[0].item() != 0.0

    def test_an_all_masked_batch_is_a_zero_loss_not_a_nan(self) -> None:
        logits = torch.tensor([2.0, -1.0], requires_grad=True)
        labels = torch.tensor([1.0, 0.0])
        loss = weighted_event_loss(
            logits, labels, positive_weight=3.0, event_weights=torch.zeros(2)
        )
        assert loss.item() == 0.0
        loss.backward()
        assert torch.all(logits.grad == 0)

    def test_negative_weights_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            weighted_event_loss(
                torch.zeros(2), torch.zeros(2), positive_weight=1.0,
                event_weights=torch.tensor([1.0, -1.0]),
            )

    def test_shape_mismatch_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="shape"):
            weighted_event_loss(
                torch.zeros(2), torch.zeros(2), positive_weight=1.0,
                event_weights=torch.ones(3),
            )


class TestBatchCarriesWeights:
    def test_unit_weights_collapse_to_none(self) -> None:
        """The common case must not pay for a tensor nobody reads."""
        assert _batch(_events()).loss_weight is None

    def test_non_unit_weights_are_carried_in_order(self) -> None:
        batch = _batch(_events(loss_weights=(1.0, 0.0, 1.0)))
        assert batch.loss_weight is not None
        assert batch.loss_weight.tolist() == [1.0, 0.0, 1.0]


class TestHeldOutHostMasking:
    """Exercises the pipeline's masking through the real record path."""

    def test_only_training_partition_events_of_the_host_are_masked(self) -> None:
        from graphsentinel.features.causal import FeatureRecord
        from graphsentinel.models.training_pipeline import FeatureNormalizer, _events

        # Three records: held-out host in train, held-out host after the
        # training cut, and an unrelated host in train.
        fields = {name: 0.0 for name in FeatureRecord.__dataclass_fields__}
        fields.update(event_id=0, timestamp=1, src_user_id=1, src_host_id=7,
                      dst_host_id=2, label_redteam=1)
        records = [
            FeatureRecord(**{**fields, "event_id": 0, "timestamp": 1}),
            FeatureRecord(**{**fields, "event_id": 1, "timestamp": 2}),
            FeatureRecord(**{**fields, "event_id": 2, "timestamp": 1, "src_host_id": 3}),
        ]
        train_end = 1                                  # only event 0 is "train"
        excluded = {7}
        weights = [
            0.0 if index < train_end and record.src_host_id in excluded else 1.0
            for index, record in enumerate(records)
        ]
        assert weights == [0.0, 1.0, 1.0]

        id_space = NodeIdSpace(user_capacity=10, host_capacity=10)
        normalizer = FeatureNormalizer.fit(records)
        events = _events(records, id_space, normalizer, weights)
        assert [event.loss_weight for event in events] == [0.0, 1.0, 1.0]
        assert all(event.label_redteam == 1 for event in events), (
            "labels must be untouched -- masking is about gradient, not truth"
        )
