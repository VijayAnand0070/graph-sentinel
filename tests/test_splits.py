import pytest

from graphsentinel.evaluation.splits import SplitError, fit_chronological_split


def test_split_keeps_equal_timestamps_together() -> None:
    timestamps = [1, 2, 3, 4, 4, 5, 6, 7, 8, 9]
    labels = [0, 0, 1, 0, 0, 1, 0, 1, 0, 1]

    split = fit_chronological_split(
        timestamps,
        labels,
        train_fraction=0.4,
        validation_fraction=0.3,
    )
    assignments = split.labels(len(timestamps))

    assert assignments[3] == assignments[4]
    assert split.train_end_timestamp < split.validation_end_timestamp
    assert split.positives["validation"] > 0
    assert split.positives["test"] > 0


def test_split_rejects_randomized_time_order() -> None:
    with pytest.raises(SplitError, match="non-decreasing"):
        fit_chronological_split([1, 3, 2], [0, 1, 1])


def test_split_requires_positive_evaluation_examples() -> None:
    with pytest.raises(SplitError, match="attack-aware contiguous windows"):
        fit_chronological_split([1, 2, 3, 4, 5, 6], [1, 0, 0, 0, 0, 0])
