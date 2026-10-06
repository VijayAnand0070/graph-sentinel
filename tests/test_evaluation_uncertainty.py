"""Statistical machinery behind every reported number.

These tests exist because each of the three choices they pin is a way results
get overstated: unstratified resampling, unpaired comparison, and optimistic
tie handling all inflate apparent performance.
"""

from __future__ import annotations

import numpy as np
import pytest

from graphsentinel.evaluation.metrics import (average_precision,
                                              bootstrap_interval, describe,
                                              lift_over_base_rate,
                                              operating_point,
                                              paired_comparison,
                                              precision_at_k, recall_at_k,
                                              roc_auc, threshold_at_budget)


def rare_event_data(seed: int = 7, n: int = 4_000, attacks: int = 40):
    """A realistically imbalanced problem: 1% prevalence."""
    rng = np.random.default_rng(seed)
    labels = np.zeros(n, dtype=int)
    labels[rng.choice(n, attacks, replace=False)] = 1
    # A detector that is good but not perfect.
    scores = rng.beta(2, 8, size=n)
    scores[labels == 1] = rng.beta(7, 2, size=attacks)
    return labels, np.clip(scores, 0, 1)


class TestTieHandling:
    def test_a_constant_scorer_gets_the_base_rate(self) -> None:
        """Optimistic tie handling makes a useless detector look excellent.
        This is the single easiest way to publish a meaningless result."""
        labels = np.array([0, 1, 0, 1, 0, 0, 0, 0, 0, 0])
        constant = np.full(10, 0.5)
        assert average_precision(labels, constant) == pytest.approx(labels.mean(), abs=0.05)
        assert roc_auc(labels, constant) == pytest.approx(0.5)

    def test_roc_auc_averages_ranks_across_ties(self) -> None:
        assert roc_auc(np.array([0, 1]), np.array([0.5, 0.5])) == pytest.approx(0.5)

    def test_a_perfect_ranking_still_scores_one(self) -> None:
        labels = np.array([0, 0, 1, 1])
        scores = np.array([0.1, 0.2, 0.8, 0.9])
        assert average_precision(labels, scores) == pytest.approx(1.0)
        assert roc_auc(labels, scores) == pytest.approx(1.0)


class TestBootstrapIntervals:
    def test_the_interval_brackets_the_point_estimate(self) -> None:
        labels, scores = rare_event_data()
        interval = bootstrap_interval(labels, scores, resamples=200)
        assert interval.low <= interval.point <= interval.high

    def test_fewer_positives_widen_the_interval(self) -> None:
        """The property that justifies reporting intervals at all: with 126
        attacks the uncertainty is substantial and must be visible."""
        many = bootstrap_interval(*rare_event_data(attacks=400), resamples=300)
        few = bootstrap_interval(*rare_event_data(attacks=20), resamples=300)
        assert few.width > many.width

    def test_the_same_seed_reproduces_the_same_interval(self) -> None:
        labels, scores = rare_event_data()
        first = bootstrap_interval(labels, scores, resamples=200, seed=11)
        second = bootstrap_interval(labels, scores, resamples=200, seed=11)
        assert (first.low, first.high) == (second.low, second.high)

    def test_resampling_holds_prevalence_fixed(self) -> None:
        """Unstratified resampling would mix metric uncertainty with prevalence
        variability, which are different questions."""
        labels, scores = rare_event_data(attacks=40)
        interval = bootstrap_interval(labels, scores, resamples=100)
        # With prevalence fixed, a detector this separable cannot produce a
        # replicate anywhere near the base rate.
        assert interval.low > labels.mean() * 3

    def test_excludes_answers_the_significance_question(self) -> None:
        labels, scores = rare_event_data()
        interval = bootstrap_interval(labels, scores, resamples=200)
        assert interval.excludes(0.0)
        assert not interval.excludes(interval.point)


class TestPairedComparison:
    def test_a_detector_does_not_beat_itself(self) -> None:
        labels, scores = rare_event_data()
        result = paired_comparison(labels, scores, scores, resamples=200)
        assert result.difference.point == pytest.approx(0.0)
        assert not result.significant

    def test_a_clearly_better_detector_wins_significantly(self) -> None:
        labels, good = rare_event_data()
        rng = np.random.default_rng(3)
        noise = np.clip(good + rng.normal(0, 0.45, size=len(good)), 0, 1)
        result = paired_comparison(labels, good, noise, name_a="good", name_b="noisy",
                                   resamples=300)
        assert result.difference.point > 0
        assert result.significant
        assert result.fraction_a_wins > 0.9

    def test_pairing_is_tighter_than_comparing_intervals(self) -> None:
        """Why paired: two overlapping intervals can still hide a consistent
        difference, and an unpaired read would call it a non-result."""
        labels, good = rare_event_data()
        rng = np.random.default_rng(5)
        slightly_worse = np.clip(good - rng.uniform(0, 0.03, size=len(good)), 0, 1)

        a = bootstrap_interval(labels, good, resamples=300)
        b = bootstrap_interval(labels, slightly_worse, resamples=300)
        overlapping = a.low < b.high and b.low < a.high

        paired = paired_comparison(labels, good, slightly_worse, resamples=300)
        assert overlapping, "fixture no longer exercises the overlapping case"
        assert paired.difference.width < min(a.width, b.width)


class TestOperatingPoints:
    def test_threshold_respects_the_budget(self) -> None:
        labels, scores = rare_event_data()
        threshold = threshold_at_budget(labels, scores, 25.0)
        point = operating_point(labels, scores, threshold)
        assert point.false_positives_per_10k <= 25.0 * 1.05

    def test_false_positives_are_reported_per_event(self) -> None:
        """Matches every committed training report: 268 / 115,992 * 10,000 =
        23.105. A benign-only denominator would give 23.130 and silently
        invalidate comparison with artifacts already on disk."""
        labels = np.array([0] * 9_900 + [1] * 100)
        scores = np.concatenate([np.full(9_900, 0.9), np.full(100, 0.1)])
        point = operating_point(labels, scores, 0.5)
        assert point.false_positives == 9_900
        assert point.false_positives_per_10k == pytest.approx(9_900 / 10_000 * 10_000)

    def test_recall_at_k_is_bounded(self) -> None:
        labels, scores = rare_event_data()
        assert recall_at_k(labels, scores, 0) == 0.0
        assert recall_at_k(labels, scores, len(labels)) == pytest.approx(1.0)
        assert 0.0 <= precision_at_k(labels, scores, 100) <= 1.0


class TestLift:
    def test_a_rule_firing_on_everything_has_no_lift(self) -> None:
        """Recall without a base rate is not a result. This is the check that
        caught a signature with 78.6% recall and 0.9x lift."""
        labels = np.array([0] * 990 + [1] * 10)
        assert lift_over_base_rate(labels, np.ones(1_000, dtype=bool)) == pytest.approx(1.0)

    def test_a_selective_rule_has_high_lift(self) -> None:
        labels = np.array([0] * 990 + [1] * 10)
        fired = np.zeros(1_000, dtype=bool)
        fired[990:] = True          # exactly the attacks
        assert lift_over_base_rate(labels, fired) > 100


def test_describe_reports_partition_shape() -> None:
    shape = describe([0, 0, 1, 0])
    assert shape == {"events": 4, "attacks": 1, "benign": 3, "prevalence": 0.25}


class TestEntityContaminationWarning:
    """The caveat must not get separated from the numbers it applies to.

    Finding 14 established that the published test PR-AUC of 0.8210 is 99.8%
    attributable to one attacker host that carries zero benign events in
    training. The figure is defensible as a relative comparison and indefensible
    as a field-performance estimate, and the difference is invisible unless the
    report says so. A report that drops the warning is worse than one with no
    numbers at all, because it reads as a measurement of detection.
    """

    def test_the_warning_travels_in_the_structured_report(self) -> None:
        from graphsentinel.evaluation.report import ENTITY_CONTAMINATION_WARNING

        assert "not field-performance estimates" in ENTITY_CONTAMINATION_WARNING
        assert "0.0019" in ENTITY_CONTAMINATION_WARNING
        assert "Findings 14 and 20" in ENTITY_CONTAMINATION_WARNING

    def test_the_rendered_markdown_carries_it_under_the_headline(self) -> None:
        """Rendered from a synthetic report so this tests the renderer rather
        than a checked-in artefact that could drift away from it."""
        from graphsentinel.evaluation.report import (ENTITY_CONTAMINATION_WARNING,
                                                     render_markdown)

        markdown = render_markdown({
            "generated_at": 0,
            "graphsentinel_version": "test",
            "python": "3.13",
            "protocol": {
                "threshold_derived_on": "validation",
                "false_positive_budget_per_10k": 25.0,
                "bootstrap_resamples": 2000,
                "bootstrap_seed": 20240517,
                "tie_handling": "positives ranked last within equal scores",
            },
            "partitions": {},
            "detectors": {},
            "paired_comparisons": [],
            "headline": {
                "best_test_pr_auc": "tgn_only",
                "best_test_pr_auc_value": {"point": 0.8210},
                "significant_comparisons": [],
                "caveat": "wide intervals",
                "entity_contamination": ENTITY_CONTAMINATION_WARNING,
            },
        })
        assert "Entity contamination" in markdown
        assert ENTITY_CONTAMINATION_WARNING in markdown

    def test_the_shipped_report_has_not_lost_the_warning(self) -> None:
        """Guards the committed artefact, which is what a reader actually opens."""
        from pathlib import Path

        report = Path("docs/EVALUATION_REPORT.md")
        if not report.exists():          # not generated in this checkout
            pytest.skip("docs/EVALUATION_REPORT.md not present")
        text = report.read_text(encoding="utf-8")
        assert "Entity contamination" in text, (
            "the evaluation report no longer carries the Finding 14 caveat; "
            "regenerate it with `evaluation-report` rather than editing it"
        )
