"""Chronological event splitting without timestamp-group leakage."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import asdict, dataclass
from itertools import pairwise


class SplitError(ValueError):
    """Raised when a defensible chronological split cannot be produced."""


@dataclass(frozen=True, slots=True)
class ChronologicalSplit:
    train_end_index: int
    validation_end_index: int
    train_start_timestamp: int
    train_end_timestamp: int
    validation_start_timestamp: int
    validation_end_timestamp: int
    test_start_timestamp: int
    test_end_timestamp: int
    counts: dict[str, int]
    positives: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def labels(self, size: int) -> list[str]:
        if size != sum(self.counts.values()):
            raise ValueError("size does not match the fitted split")
        return (
            ["train"] * self.train_end_index
            + ["validation"] * (self.validation_end_index - self.train_end_index)
            + ["test"] * (size - self.validation_end_index)
        )


def _move_cut_after_timestamp(timestamps: Sequence[int], cut: int) -> int:
    while cut < len(timestamps) and timestamps[cut] == timestamps[cut - 1]:
        cut += 1
    return cut


def fit_chronological_split(
    timestamps: Sequence[int],
    labels: Sequence[int],
    *,
    train_fraction: float = 0.70,
    validation_fraction: float = 0.15,
    require_evaluation_positives: bool = True,
) -> ChronologicalSplit:
    """Fit row-proportional cuts while keeping equal timestamps in one split."""

    if len(timestamps) != len(labels):
        raise SplitError("timestamps and labels must have equal length")
    if len(timestamps) < 3:
        raise SplitError("at least three events are required")
    if not 0 < train_fraction < 1:
        raise SplitError("train_fraction must be between zero and one")
    if not 0 < validation_fraction < 1 - train_fraction:
        raise SplitError("validation_fraction leaves no test partition")
    if any(current < previous for previous, current in pairwise(timestamps)):
        raise SplitError("timestamps must be non-decreasing")
    if any(label not in {0, 1} for label in labels):
        raise SplitError("labels must be binary")

    size = len(timestamps)
    train_cut = _move_cut_after_timestamp(timestamps, max(1, int(size * train_fraction)))
    validation_cut = _move_cut_after_timestamp(
        timestamps, max(train_cut + 1, int(size * (train_fraction + validation_fraction)))
    )
    if train_cut >= size - 1 or validation_cut >= size:
        raise SplitError("timestamp ties leave an empty validation or test partition")

    split_labels = (labels[:train_cut], labels[train_cut:validation_cut], labels[validation_cut:])
    positives = {
        "train": sum(split_labels[0]),
        "validation": sum(split_labels[1]),
        "test": sum(split_labels[2]),
    }
    if require_evaluation_positives and (positives["validation"] == 0 or positives["test"] == 0):
        raise SplitError(
            "validation/test lacks positives; define documented attack-aware contiguous windows"
        )
    counts = {
        "train": train_cut,
        "validation": validation_cut - train_cut,
        "test": size - validation_cut,
    }
    return ChronologicalSplit(
        train_end_index=train_cut,
        validation_end_index=validation_cut,
        train_start_timestamp=timestamps[0],
        train_end_timestamp=timestamps[train_cut - 1],
        validation_start_timestamp=timestamps[train_cut],
        validation_end_timestamp=timestamps[validation_cut - 1],
        test_start_timestamp=timestamps[validation_cut],
        test_end_timestamp=timestamps[-1],
        counts=counts,
        positives=positives,
    )
