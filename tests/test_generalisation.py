"""Tests for entity-disjoint evaluation.

Built around constructed cases with known answers rather than around the real
corpus, so a failure points at the logic instead of at a data refresh. The
corpus result that motivated the module -- one host accounting for 99.8% of test
PR-AUC -- is pinned separately in ``test_the_known_corpus_result_is_reproduced``
against the scored cache committed under ``tests/fixtures``.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from graphsentinel.evaluation.generalisation import (MINIMUM_CREDIBLE_POSITIVES,
                                                     attack_only_entities,
                                                     contamination_report,
                                                     render_contamination)


class TestAttackOnlyEntities:
    def test_an_entity_seen_only_in_attacks_is_flagged(self) -> None:
        labels = [0, 0, 1, 1, 0]
        entities = [1, 2, 99, 99, 1]
        assert attack_only_entities(labels, entities) == {99: 2}

    def test_an_entity_with_any_benign_event_is_not_flagged(self) -> None:
        """One benign event is enough: identity alone no longer determines the
        label, so the model cannot use it as a free separator."""
        labels = [0, 1, 1]
        entities = [7, 7, 7]
        assert attack_only_entities(labels, entities) == {}

    def test_results_are_ordered_by_how_much_they_could_matter(self) -> None:
        labels = [1] * 6
        entities = [5, 5, 5, 9, 9, 3]
        assert list(attack_only_entities(labels, entities)) == [5, 9, 3]

    def test_a_clean_corpus_yields_nothing(self) -> None:
        rng = np.random.default_rng(0)
        entities = rng.integers(0, 10, 1000)
        labels = rng.integers(0, 2, 1000)
        flagged = attack_only_entities(labels, entities)
        assert flagged == {}, "every entity appears on both sides here"

    def test_mismatched_lengths_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            attack_only_entities([0, 1], [1])

    def test_no_attacks_means_nothing_to_flag(self) -> None:
        assert attack_only_entities([0, 0, 0], [1, 2, 3]) == {}


class TestContaminationReport:
    def test_rejects_an_empty_partition(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            contamination_report([], [], [])

    def test_rejects_mismatched_lengths(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            contamination_report([0, 1], [0.1, 0.2], [1])

    def test_a_memorising_detector_is_caught(self) -> None:
        """The case the module exists for.

        One entity supplies every attack and scores perfectly; attacks from
        other entities score at the floor. Withdrawing the memorised entity
        should take essentially all of the measured performance with it.
        """
        rng = np.random.default_rng(3)
        labels = np.zeros(10_000, dtype=int)
        scores = rng.random(10_000) * 0.01
        entities = rng.integers(100, 200, 10_000)

        labels[:200] = 1                 # memorised entity: detected
        entities[:200] = 42
        scores[:200] = 0.99
        labels[200:230] = 1              # other entities: missed
        entities[200:230] = rng.integers(100, 200, 30)
        scores[200:230] = 0.005

        report = contamination_report(labels, scores, entities, resamples=200)
        assert report.contaminated
        assert report.dominant_entity == 42
        worst = report.worst
        assert worst is not None and worst.entity == 42
        assert worst.share_of_metric > 0.9
        assert "CONTAMINATED" in report.verdict()

    def test_a_generalising_detector_is_not_flagged(self) -> None:
        """Attacks spread across many entities and all detected: removing any
        one of them must barely move the metric."""
        rng = np.random.default_rng(5)
        labels = np.zeros(10_000, dtype=int)
        scores = rng.random(10_000) * 0.01
        entities = rng.integers(0, 50, 10_000)
        attack_index = rng.choice(10_000, 300, replace=False)
        labels[attack_index] = 1
        scores[attack_index] = 0.9 + rng.random(300) * 0.1

        report = contamination_report(labels, scores, entities, resamples=200)
        assert not report.contaminated
        assert "No single entity dominates" in report.verdict()

    def test_removing_undetected_attacks_can_improve_the_metric(self) -> None:
        """A sign check that guards the direction of ``share_of_metric``.

        Withdrawing an entity whose attacks the detector never caught *raises*
        average precision, so the cost is negative. If the subtraction were the
        wrong way round this case would read as contamination.
        """
        labels = np.zeros(2_000, dtype=int)
        scores = np.full(2_000, 0.001)
        entities = np.zeros(2_000, dtype=int)
        labels[:50] = 1                  # entity 1: detected
        entities[:50] = 1
        scores[:50] = 0.95
        labels[50:60] = 1                # entity 2: completely missed
        entities[50:60] = 2
        scores[50:60] = 0.0

        report = contamination_report(labels, scores, entities, resamples=200)
        by_entity = {h.entity: h for h in report.holdouts}
        assert by_entity[2].share_of_metric < 0, (
            "removing undetected attacks should raise PR-AUC, giving negative cost"
        )
        assert by_entity[1].share_of_metric > 0

    def test_small_residuals_are_marked_as_not_credible(self) -> None:
        labels = np.zeros(1_000, dtype=int)
        scores = np.full(1_000, 0.01)
        entities = np.zeros(1_000, dtype=int)
        labels[:40] = 1
        entities[:40] = 7
        scores[:40] = 0.9
        labels[40:43] = 1                # 3 attacks survive the holdout
        entities[40:43] = 8

        report = contamination_report(labels, scores, entities, resamples=100)
        worst = report.worst
        assert worst is not None
        assert worst.attacks_remaining < MINIMUM_CREDIBLE_POSITIVES
        assert not worst.credible
        assert "too few" in report.verdict() or "below the" in report.verdict()

    def test_an_entity_holding_every_attack_is_skipped_not_scored_zero(self) -> None:
        """PR-AUC over zero positives is undefined, not zero. Scoring it 0 would
        manufacture a 100% contamination reading out of an empty measurement."""
        labels = np.zeros(500, dtype=int)
        scores = np.full(500, 0.01)
        entities = np.zeros(500, dtype=int)
        labels[:20] = 1
        entities[:20] = 5
        scores[:20] = 0.9

        report = contamination_report(labels, scores, entities, resamples=100)
        assert all(h.attacks_remaining > 0 for h in report.holdouts)
        assert 5 not in {h.entity for h in report.holdouts}

    def test_lift_is_reported_so_a_collapse_is_not_read_as_no_signal(self) -> None:
        """A collapsed PR-AUC at a collapsed base rate can still beat chance
        by a wide margin, and the report has to permit that reading."""
        rng = np.random.default_rng(11)
        labels = np.zeros(20_000, dtype=int)
        scores = rng.random(20_000) * 0.001
        entities = rng.integers(0, 30, 20_000)
        labels[:100] = 1
        entities[:100] = 1
        scores[:100] = 0.99
        labels[100:140] = 1              # ranked high, but not top
        entities[100:140] = 2
        scores[100:140] = 0.02

        report = contamination_report(labels, scores, entities, resamples=200)
        holdout = next(h for h in report.holdouts if h.entity == 1)
        assert holdout.lift_without > 1.0
        assert holdout.base_rate_without < 0.01

    def test_the_sweep_is_capped(self) -> None:
        rng = np.random.default_rng(13)
        labels = np.ones(200, dtype=int)
        scores = rng.random(200)
        entities = np.arange(200)
        report = contamination_report(labels, scores, entities,
                                      resamples=50, max_entities=4)
        assert len(report.holdouts) <= 4

    def test_total_capture_is_the_most_severe_case_not_an_absent_one(self) -> None:
        """A single entity supplying every attack must not read as all-clear.

        Withdrawing it leaves zero positives, so the holdout sweep is empty by
        construction. An implementation that judged contamination from the
        sweep alone would find nothing and report that nothing was wrong --
        which is the exact inversion of the truth, since this is the strongest
        possible form of the problem.
        """
        rng = np.random.default_rng(29)
        labels = np.zeros(2_000, dtype=int)
        scores = rng.random(2_000) * 0.01
        entities = rng.integers(0, 20, 2_000)
        labels[:50] = 1
        entities[:50] = 3
        scores[:50] = 0.95

        report = contamination_report(labels, scores, entities, resamples=100)
        assert report.holdouts == (), "precondition: the sweep must be empty here"
        assert report.total_capture
        assert report.contaminated, "total capture is contamination, not absence"
        assert "total capture" in report.verdict()
        assert "3" in report.verdict()
        assert "No attacking entities" not in report.verdict()

    def test_an_empty_sweep_with_no_attacks_reads_differently(self) -> None:
        """The genuinely-nothing-to-measure case must stay distinguishable."""
        report = contamination_report(np.zeros(100, dtype=int),
                                      np.full(100, 0.5),
                                      np.arange(100), resamples=50)
        assert not report.contaminated
        assert not report.total_capture
        assert "No attacking entities" in report.verdict()

    def test_serialisation_carries_the_verdict(self) -> None:
        rng = np.random.default_rng(17)
        labels = np.zeros(2_000, dtype=int)
        scores = rng.random(2_000) * 0.01
        entities = rng.integers(0, 20, 2_000)
        labels[:50] = 1                  # dominant attacker
        entities[:50] = 3
        scores[:50] = 0.95
        labels[50:70] = 1                # a second attacker, so a holdout exists
        entities[50:70] = 4
        scores[50:70] = 0.6
        payload = contamination_report(labels, scores, entities,
                                       resamples=100).to_dict()
        assert "verdict" in payload and payload["verdict"]
        assert isinstance(payload["contaminated"], bool)
        assert payload["total_capture"] is False
        assert payload["holdouts"]


class TestRendering:
    def test_render_names_the_dominant_entity(self) -> None:
        rng = np.random.default_rng(19)
        labels = np.zeros(3_000, dtype=int)
        scores = rng.random(3_000) * 0.01
        entities = rng.integers(0, 20, 3_000)
        labels[:60] = 1
        entities[:60] = 77
        scores[:60] = 0.95
        text = render_contamination(
            contamination_report(labels, scores, entities, resamples=100)
        )
        assert "77" in text
        assert "PR-AUC" in text


#: The scored cache the evaluation report and Finding 14 are both derived from.
#: Provenance, schema and the regeneration command are in ``fixtures/README.md``.
SCORED_CACHE = Path(__file__).parent / "fixtures" / "fusion_cache.parquet"

#: What the committed fixture must contain. A cache with different counts was
#: scored from a different corpus or split, and every number it produces
#: belongs to a different experiment than the one the findings describe.
EXPECTED_PARTITIONS = {"train": (333_551, 316), "validation": (94_072, 207),
                       "test": (115_992, 126)}


def test_the_scored_cache_is_the_one_the_findings_were_derived_from() -> None:
    """Fails -- does not skip -- when the fixture is missing or is not this cache.

    An earlier version of the regression below skipped when the file was
    absent, which meant it silently pinned nothing in any checkout but the one
    it was written on. A fixture that is tracked is either present or the
    checkout is broken, and a broken checkout should say so.
    """
    assert SCORED_CACHE.is_file(), (
        f"scored cache missing at {SCORED_CACHE}; regenerate it with "
        "`python scripts/build_scored_cache.py` (see tests/fixtures/README.md)"
    )
    import polars as pl

    cache = pl.read_parquet(SCORED_CACHE)
    assert {"label", "tgn", "src_host_id", "partition"} <= set(cache.columns)
    for partition, (events, attacks) in EXPECTED_PARTITIONS.items():
        part = cache.filter(pl.col("partition") == partition)
        assert (part.height, int(part["label"].sum())) == (events, attacks), (
            f"{partition}: expected {events:,} events / {attacks} attacks, "
            f"found {part.height:,} / {int(part['label'].sum())} -- this is not "
            "the cache the findings were derived from"
        )


def test_the_known_corpus_result_is_reproduced() -> None:
    """Pins Finding 14 against the committed scored cache.

    The 99.8% figure is the reason this module exists; if a change to the
    metric, the binning, or the checkpoint moved it, that would need to be a
    deliberate decision rather than a silent drift.
    """
    import polars as pl

    test = pl.read_parquet(SCORED_CACHE).filter(pl.col("partition") == "test")
    report = contamination_report(
        test["label"].to_numpy().astype(int),
        test["tgn"].to_numpy(),
        test["src_host_id"].to_numpy(),
        resamples=200,
    )
    assert report.contaminated
    assert report.dominant_entity == 8426
    worst = report.worst
    assert worst is not None
    assert worst.share_of_metric == pytest.approx(0.998, abs=0.005)
    assert not worst.credible
