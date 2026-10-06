"""Evaluation metrics for rare-event detection, with uncertainty.

Why this module exists separately
---------------------------------
Every number in this project was, for a while, a bare point estimate. The
sealed test partition holds 115,992 events and **126 attacks**, and PR-AUC is
determined almost entirely by where those 126 land. A several-point difference
between two detectors is comfortably inside the noise at that sample size, and
quoting one without an interval is a claim the data does not support.

Three decisions here are deliberate and worth stating, because each one is a
way results get overstated in this field:

**Ties break pessimistically.** Attacks are ranked *last* within a block of
equal scores. A detector that outputs a constant then scores at the base rate
rather than at whatever the tie order happened to produce.

**Bootstrap resampling is stratified.** Positives and negatives are resampled
independently so every replicate holds the prevalence fixed. Resampling events
uniformly would let a replicate draw 90 attacks instead of 126, and the
resulting interval would mix "how uncertain is this metric" with "how variable
is the prevalence", which are different questions.

**Comparisons are paired.** Two detectors scoring the same events must be
compared on the *same* resampled index set. An unpaired comparison discards
that pairing and inflates the variance of the difference, which turns real
improvements into non-results.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

import numpy as np

#: Bootstrap replicates. 2,000 gives a stable 95% percentile interval; more
#: buys little at this sample size, and fewer makes the tails jumpy.
DEFAULT_RESAMPLES = 2_000

#: Fixed so every run of the evaluation reproduces the same intervals.
DEFAULT_SEED = 1729


def average_precision(labels: np.ndarray, scores: np.ndarray) -> float:
    """Tie-aware average precision.

    The primary metric for this problem. At 0.1% prevalence a detector that
    answers "benign" for everything is 99.89% accurate and useless, and
    ROC-AUC stays near 1.0 while an unusable number of false positives sit
    above the true ones. PR-AUC measures the only thing that matters
    operationally: what is at the top of the queue.

    Ties are resolved over the whole tied block rather than per item: every
    positive inside a block of equal scores is credited with the precision at
    the END of that block. That is the expected value over random orderings
    within the tie, so the result does not depend on an arbitrary sort order.

    This matters more than it sounds. The rule, rarity and isolation-forest
    baselines emit heavily quantised scores, so most of their events sit in
    large tied blocks. Scoring those pessimistically instead -- ranking
    positives last inside each tie -- shifted their published PR-AUC by about
    4e-4, enough to make committed artifacts and freshly computed numbers
    disagree for no defensible reason. A constant scorer still lands exactly on
    the base rate under either treatment.
    """
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    positives = int(labels.sum())
    if positives == 0:
        return 0.0

    order = np.argsort(-scores, kind="stable")
    ranked_labels = labels[order]
    ranked_scores = scores[order]

    # Last index of each run of equal scores.
    block_end = np.empty(len(ranked_scores), dtype=bool)
    block_end[-1] = True
    if len(ranked_scores) > 1:
        block_end[:-1] = ranked_scores[:-1] != ranked_scores[1:]

    cumulative_positives = np.cumsum(ranked_labels)[block_end]
    examined = (np.arange(1, len(ranked_scores) + 1))[block_end]
    precision_at_block_end = cumulative_positives / examined
    positives_in_block = np.diff(np.concatenate(([0], cumulative_positives)))
    return float((positives_in_block / positives * precision_at_block_end).sum())


def roc_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    """Rank-statistic ROC-AUC.

    Reported for comparability with published work, not as evidence. On this
    data two detectors 0.23 apart in PR-AUC differ by 0.026 in ROC-AUC.
    """
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    positives, negatives = int(labels.sum()), int(len(labels) - labels.sum())
    if positives == 0 or negatives == 0:
        return 0.0
    # Tied scores must share the average of the ranks they span. Assigning
    # them arbitrary distinct ranks makes a constant scorer read as a perfect
    # one, which is the single easiest way to publish a meaningless 1.0.
    order = np.argsort(scores, kind="stable")
    ranks = np.empty(len(scores), dtype=float)
    ranks[order] = np.arange(1, len(scores) + 1, dtype=float)
    ordered = scores[order]
    start = 0
    while start < len(ordered):
        stop = start
        while stop + 1 < len(ordered) and ordered[stop + 1] == ordered[start]:
            stop += 1
        if stop > start:
            ranks[order[start:stop + 1]] = (start + stop + 2) / 2.0
        start = stop + 1
    return float((ranks[labels == 1].sum() - positives * (positives + 1) / 2)
                 / (positives * negatives))


def recall_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> float:
    """Share of attacks inside the top ``k`` by score.

    The number an analyst feels: given a shift's worth of queue, how much of
    the campaign is in it.
    """
    labels = np.asarray(labels, dtype=int)
    if labels.sum() == 0:
        return 0.0
    order = np.lexsort((labels, -np.asarray(scores, dtype=float)))
    return float(labels[order][:k].sum() / labels.sum())


def precision_at_k(labels: np.ndarray, scores: np.ndarray, k: int) -> float:
    labels = np.asarray(labels, dtype=int)
    if k <= 0:
        return 0.0
    order = np.lexsort((labels, -np.asarray(scores, dtype=float)))
    return float(labels[order][:k].sum() / min(k, len(labels)))


def threshold_at_budget(
    labels: np.ndarray, scores: np.ndarray, false_positives_per_10k: float
) -> float:
    """Lowest threshold whose false positives stay inside the budget.

    Lowest, not any: a higher threshold also satisfies the budget and throws
    away recall for nothing. Must be derived on validation only — deriving it
    on test leaks the partition it is meant to measure.
    """
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    benign = np.sort(scores[labels == 0])[::-1]
    if len(benign) == 0:
        return 0.0
    # Budget is expressed per 10,000 events, so the allowance scales with the
    # partition size, not with how many of it happen to be benign.
    allowed = int(len(labels) * false_positives_per_10k / 10_000)
    if allowed <= 0:
        return float(benign[0]) + 1e-9
    if allowed >= len(benign):
        return 0.0
    return float(benign[allowed - 1])


@dataclass(frozen=True, slots=True)
class OperatingPoint:
    threshold: float
    alerts: int
    true_positives: int
    false_positives: int
    recall: float
    precision: float
    false_positives_per_10k: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "threshold": round(self.threshold, 6),
            "alerts": self.alerts,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "false_positives_per_10k": round(self.false_positives_per_10k, 2),
        }


def operating_point(
    labels: np.ndarray, scores: np.ndarray, threshold: float
) -> OperatingPoint:
    labels = np.asarray(labels, dtype=int)
    alerted = np.asarray(scores, dtype=float) >= threshold
    true_positives = int((alerted & (labels == 1)).sum())
    false_positives = int((alerted & (labels == 0)).sum())
    positives = int(labels.sum())
    return OperatingPoint(
        threshold=threshold,
        alerts=int(alerted.sum()),
        true_positives=true_positives,
        false_positives=false_positives,
        recall=true_positives / positives if positives else 0.0,
        precision=true_positives / max(1, true_positives + false_positives),
        # Per 10,000 EVENTS, not per 10,000 benign. Verified against the
        # committed training reports: 268 / 115,992 * 10,000 = 23.105, which is
        # the figure they record. Using the benign denominator would give
        # 23.130 and silently invalidate comparisons with artifacts on disk.
        false_positives_per_10k=false_positives / max(1, len(labels)) * 10_000,
    )


@dataclass(frozen=True, slots=True)
class Interval:
    """A point estimate and the range the data actually supports."""

    point: float
    low: float
    high: float
    resamples: int

    @property
    def width(self) -> float:
        return self.high - self.low

    def excludes(self, value: float) -> bool:
        return value < self.low or value > self.high

    def to_dict(self) -> dict[str, float | int]:
        return {
            "point": round(self.point, 4),
            "ci95": [round(self.low, 4), round(self.high, 4)],
            "width": round(self.width, 4),
            "resamples": self.resamples,
        }

    def __str__(self) -> str:
        return f"{self.point:.4f} [{self.low:.4f}, {self.high:.4f}]"


def _stratified_indices(
    labels: np.ndarray, rng: np.random.Generator, resamples: int
) -> list[np.ndarray]:
    """Resampled index sets holding prevalence fixed.

    Generated once and reused across every metric and every scorer, which is
    what makes comparisons paired.
    """
    positives = np.flatnonzero(labels == 1)
    negatives = np.flatnonzero(labels == 0)
    return [
        np.concatenate([
            rng.choice(positives, size=len(positives), replace=True),
            rng.choice(negatives, size=len(negatives), replace=True),
        ])
        for _ in range(resamples)
    ]


def bootstrap_interval(
    labels: np.ndarray,
    scores: np.ndarray,
    metric: Callable[[np.ndarray, np.ndarray], float] = average_precision,
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
    confidence: float = 0.95,
) -> Interval:
    """Percentile bootstrap interval for one detector on one metric."""
    labels = np.asarray(labels, dtype=int)
    scores = np.asarray(scores, dtype=float)
    rng = np.random.default_rng(seed)
    replicates = [
        metric(labels[index], scores[index])
        for index in _stratified_indices(labels, rng, resamples)
    ]
    tail = (1.0 - confidence) / 2 * 100
    return Interval(
        point=metric(labels, scores),
        low=float(np.percentile(replicates, tail)),
        high=float(np.percentile(replicates, 100 - tail)),
        resamples=resamples,
    )


@dataclass(frozen=True, slots=True)
class Comparison:
    """A paired difference between two detectors, with its interval."""

    name_a: str
    name_b: str
    difference: Interval
    fraction_a_wins: float

    @property
    def significant(self) -> bool:
        """Does the 95% interval exclude zero?"""
        return self.difference.excludes(0.0)

    def to_dict(self) -> dict[str, object]:
        return {
            "comparison": f"{self.name_a} - {self.name_b}",
            "difference": self.difference.to_dict(),
            "fraction_a_wins": round(self.fraction_a_wins, 4),
            "significant": self.significant,
        }


def paired_comparison(
    labels: np.ndarray,
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    *,
    name_a: str = "a",
    name_b: str = "b",
    metric: Callable[[np.ndarray, np.ndarray], float] = average_precision,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
) -> Comparison:
    """Compare two detectors on identical resampled events.

    Both are scored on the *same* index set in each replicate. An unpaired
    comparison would inflate the variance of the difference and could report a
    real improvement as a non-result.
    """
    labels = np.asarray(labels, dtype=int)
    scores_a = np.asarray(scores_a, dtype=float)
    scores_b = np.asarray(scores_b, dtype=float)
    rng = np.random.default_rng(seed)
    differences = np.array([
        metric(labels[index], scores_a[index]) - metric(labels[index], scores_b[index])
        for index in _stratified_indices(labels, rng, resamples)
    ])
    return Comparison(
        name_a=name_a,
        name_b=name_b,
        difference=Interval(
            point=metric(labels, scores_a) - metric(labels, scores_b),
            low=float(np.percentile(differences, 2.5)),
            high=float(np.percentile(differences, 97.5)),
            resamples=resamples,
        ),
        fraction_a_wins=float((differences > 0).mean()),
    )


def lift_over_base_rate(labels: np.ndarray, fired: np.ndarray) -> float:
    """Recall divided by benign firing rate, for a binary rule.

    Recall alone is meaningless for a rule: one that fires on everything has
    perfect recall. Lift below 1.0 means the rule is worse than guessing, which
    is how a signature firing on 85% of benign traffic was caught here.
    """
    labels = np.asarray(labels, dtype=bool)
    fired = np.asarray(fired, dtype=bool)
    attacks, benign = int(labels.sum()), int((~labels).sum())
    if attacks == 0 or benign == 0:
        return 0.0
    recall = float((fired & labels).sum()) / attacks
    firing = float((fired & ~labels).sum()) / benign
    return recall / max(1e-12, firing)


def describe(labels: Sequence[int]) -> dict[str, float | int]:
    """Partition shape, reported alongside any metric computed on it."""
    array = np.asarray(labels, dtype=int)
    positives = int(array.sum())
    return {
        "events": int(len(array)),
        "attacks": positives,
        "benign": int(len(array) - positives),
        "prevalence": round(positives / max(1, len(array)), 6),
    }


# ---------------------------------------------------------------------------
# Training-pipeline surface
#
# These predate the uncertainty machinery above and are what the training
# pipeline and its reports are built on. Kept with their original contract --
# same names, same return shapes, same validation -- because every committed
# training report was produced by them and changing the shape would silently
# invalidate comparisons against artifacts already on disk.
# ---------------------------------------------------------------------------

DEFAULT_TOP_KS = (10, 100, 1_000)


def _validated(labels: Sequence[int], scores: Sequence[float]) -> tuple[np.ndarray, np.ndarray]:
    label_array = np.asarray(list(labels), dtype=int)
    score_array = np.asarray(list(scores), dtype=float)
    if label_array.shape != score_array.shape:
        raise ValueError("labels and scores must have the same length")
    if label_array.size == 0:
        raise ValueError("cannot compute metrics over an empty stream")
    if not np.isin(label_array, (0, 1)).all():
        raise ValueError("labels must be binary")
    if not np.isfinite(score_array).all() or score_array.min() < 0 or score_array.max() > 1:
        raise ValueError("scores must be finite probabilities in [0, 1]")
    return label_array, score_array


@dataclass(frozen=True, slots=True)
class ThresholdSelection:
    """A decision threshold chosen under an explicit false-positive budget."""

    threshold: float
    alerts: int
    false_positives: int
    false_positives_per_10000: float
    precision: float
    recall: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "threshold": self.threshold,
            "alerts": self.alerts,
            "false_positives": self.false_positives,
            "false_positives_per_10000": self.false_positives_per_10000,
            "precision": self.precision,
            "recall": self.recall,
        }


def select_threshold_under_budget(
    labels: Sequence[int],
    scores: Sequence[float],
    *,
    false_positives_per_10000_budget: float,
) -> ThresholdSelection:
    """Lowest observed score that keeps false positives inside the budget.

    Searching over observed scores rather than a grid means the returned
    threshold is always attainable. Raising when nothing fits is deliberate: a
    silent fallback would hand back a threshold that does not honour the budget
    the caller asked for.
    """
    label_array, score_array = _validated(labels, scores)
    if false_positives_per_10000_budget < 0:
        raise ValueError("false positive budget must be non-negative")
    positives = int(label_array.sum())
    events = int(label_array.size)
    allowed = false_positives_per_10000_budget / 10_000 * max(1, events)

    best: ThresholdSelection | None = None
    for candidate in sorted(set(score_array.tolist()), reverse=True):
        alerted = score_array >= candidate
        false_positives = int((alerted & (label_array == 0)).sum())
        if false_positives > allowed:
            continue
        true_positives = int((alerted & (label_array == 1)).sum())
        best = ThresholdSelection(
            threshold=float(candidate),
            alerts=int(alerted.sum()),
            false_positives=false_positives,
            false_positives_per_10000=false_positives / max(1, events) * 10_000,
            precision=true_positives / max(1, int(alerted.sum())),
            recall=true_positives / max(1, positives),
        )
    if best is None:
        raise ValueError(
            "no probability threshold satisfies the requested false positive budget"
        )
    return best


def brier_score(labels: Sequence[int], scores: Sequence[float]) -> float:
    """Mean squared error of the probabilities -- a calibration check.

    Ranking metrics say nothing about whether a 0.9 means 90%; a detector can
    rank perfectly and still be badly calibrated, which matters as soon as a
    score drives an automated action.
    """
    label_array, score_array = _validated(labels, scores)
    return float(np.mean((score_array - label_array) ** 2))


def ranking_metrics(
    labels: Sequence[int],
    scores: Sequence[float],
    *,
    threshold: float,
    top_ks: Sequence[int] = DEFAULT_TOP_KS,
) -> dict[str, float | int]:
    """The full metric block recorded in every training report."""
    label_array, score_array = _validated(labels, scores)
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be in [0, 1]")

    point = operating_point(label_array, score_array, threshold)
    metrics: dict[str, float | int] = {
        "events": int(label_array.size),
        "positives": int(label_array.sum()),
        "prevalence": float(label_array.mean()),
        "pr_auc": average_precision(label_array, score_array),
        "roc_auc": roc_auc(label_array, score_array),
        "brier_score": brier_score(label_array, score_array),
        "alerts": point.alerts,
        "false_positives": point.false_positives,
        "false_positives_per_10000": point.false_positives_per_10k,
    }
    for k in top_ks:
        metrics[f"precision_at_{k}"] = precision_at_k(label_array, score_array, k)
        metrics[f"recall_at_{k}"] = recall_at_k(label_array, score_array, k)
    return metrics
