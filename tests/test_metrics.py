import pytest

from graphsentinel.evaluation.metrics import (
    average_precision,
    ranking_metrics,
    roc_auc,
    select_threshold_under_budget,
)


def test_perfect_ranking_metrics() -> None:
    labels = [0, 1, 0, 1]
    scores = [0.1, 0.9, 0.2, 0.8]

    metrics = ranking_metrics(labels, scores, threshold=0.5, top_ks=(2,))

    assert average_precision(labels, scores) == 1.0
    assert roc_auc(labels, scores) == 1.0
    assert metrics["precision_at_2"] == 1.0
    assert metrics["recall_at_2"] == 1.0
    assert metrics["false_positives"] == 0


def test_tied_roc_auc_is_half() -> None:
    assert roc_auc([0, 1], [0.5, 0.5]) == 0.5
    assert average_precision([0, 1], [0.5, 0.5]) == 0.5


def test_threshold_selection_respects_false_alert_budget() -> None:
    labels = [0, 1, 0, 1, 0]
    scores = [0.95, 0.90, 0.80, 0.70, 0.10]

    selection = select_threshold_under_budget(
        labels, scores, false_positives_per_10000_budget=2_000
    )

    assert selection.threshold == pytest.approx(0.9)
    assert selection.recall == 0.5
    assert selection.false_positives == 1


def test_threshold_selection_fails_when_no_probability_cutoff_meets_budget() -> None:
    with pytest.raises(ValueError, match="no probability threshold"):
        select_threshold_under_budget([0, 1], [1.0, 0.5], false_positives_per_10000_budget=0)


def test_metrics_reject_out_of_range_scores() -> None:
    with pytest.raises(ValueError, match=r"\[0, 1\]"):
        ranking_metrics([0, 1], [0.1, 1.1], threshold=0.5)
