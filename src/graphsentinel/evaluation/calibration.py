"""Calibration analysis for rare-event detectors.

Why calibration is not optional here
------------------------------------
Ranking metrics say where an event sits in the queue. They say nothing about
whether a score of 0.9 means "90% likely malicious". The two are independent:
a detector can rank perfectly and still be wildly miscalibrated.

That distinction stops being academic the moment a score gates an automated
action. GraphSentinel's response layer fires on thresholds -- 0.329 to alert,
0.85 for auto-execution -- and disables accounts and isolates hosts at the top
end. If the model's 0.9 actually corresponds to a 3% chance of compromise, a
threshold chosen from the score distribution is not the risk tolerance anyone
intended.

Measuring it under 0.1% prevalence
----------------------------------
At this prevalence most bins hold no positives at all, so a naive equal-width
reliability diagram is mostly empty cells and a few noisy ones. Two choices
follow:

* **Equal-frequency bins.** Each bin holds the same number of events rather
  than the same score range, so every bin carries enough data to estimate a
  frequency. Equal-width bins would put 99% of events in the lowest bin.
* **Wilson score intervals** on the observed frequency per bin. With a handful
  of positives, a bare ratio is not an estimate -- 1 positive in 200 events is
  0.5%, but the interval runs from roughly 0.1% to 2.8%, and a reliability
  diagram without that spread invites conclusions the data cannot support.

Do not quote ECE on this problem
--------------------------------
Expected calibration error is reported here because it is conventional, but it
is close to useless at this prevalence and should not be used as the summary.
It is a population-weighted average of per-bin error, and ~99.5% of the
population sits in bins where predicted and observed are both approximately
zero, contributing approximately zero error. Measured on this corpus it comes
out at 0.00283 whether the diagram is drawn with 10 bins or 200 -- while the
top bin is over-confident by 3.4x and the one below it by 6.8x. The number is
dominated by the region where nothing happens.

For an operational read, bin the decision region directly and report precision
against labels at each candidate threshold. ``docs/DETECTION_RESEARCH_FINDINGS``
Findings 15 and 16 carry that measurement for the shipped model.

Brier decomposition
-------------------
The Brier score splits into reliability - resolution + uncertainty (Murphy,
1973). Reported separately because they answer different questions:
*reliability* is the calibration error, *resolution* is how much the detector
separates events from the base rate, and *uncertainty* is fixed by the
prevalence and cannot be improved by any model. Quoting Brier alone hides the
fact that at 0.1% prevalence the uncertainty term dominates.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

#: Equal-frequency bins. Ten is enough to see a trend without the top bins
#: becoming single-digit-positive noise at this prevalence.
DEFAULT_BINS = 10


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation because it stays inside [0, 1] and
    remains sensible when the count is 0 or equal to the number of trials --
    both of which happen constantly in the low-score bins here, where a normal
    interval would produce negative lower bounds.
    """
    if trials == 0:
        return (0.0, 0.0)
    proportion = successes / trials
    denominator = 1 + z * z / trials
    centre = (proportion + z * z / (2 * trials)) / denominator
    spread = (z / denominator) * math.sqrt(
        proportion * (1 - proportion) / trials + z * z / (4 * trials * trials)
    )
    return (max(0.0, centre - spread), min(1.0, centre + spread))


@dataclass(frozen=True, slots=True)
class Bin:
    index: int
    events: int
    positives: int
    mean_predicted: float
    observed_frequency: float
    interval: tuple[float, float]
    score_range: tuple[float, float]

    @property
    def calibrated(self) -> bool:
        """Does the interval on the observed frequency contain the prediction?"""
        return self.interval[0] <= self.mean_predicted <= self.interval[1]

    def to_dict(self) -> dict[str, object]:
        return {
            "bin": self.index,
            "events": self.events,
            "positives": self.positives,
            "mean_predicted": round(self.mean_predicted, 6),
            "observed_frequency": round(self.observed_frequency, 6),
            "ci95": [round(self.interval[0], 6), round(self.interval[1], 6)],
            "score_range": [round(self.score_range[0], 6), round(self.score_range[1], 6)],
            "calibrated": self.calibrated,
        }


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    bins: tuple[Bin, ...]
    expected_calibration_error: float
    maximum_calibration_error: float
    brier_score: float
    reliability: float
    resolution: float
    uncertainty: float
    prevalence: float
    mean_prediction: float

    @property
    def bins_within_interval(self) -> int:
        return sum(1 for b in self.bins if b.calibrated)

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_calibration_error": round(self.expected_calibration_error, 6),
            "maximum_calibration_error": round(self.maximum_calibration_error, 6),
            "brier": {
                "score": round(self.brier_score, 6),
                "reliability": round(self.reliability, 6),
                "resolution": round(self.resolution, 6),
                "uncertainty": round(self.uncertainty, 6),
                "note": (
                    "Brier = reliability - resolution + uncertainty. Uncertainty "
                    "is fixed by prevalence and unimprovable by any model."
                ),
            },
            "prevalence": round(self.prevalence, 6),
            "mean_prediction": round(self.mean_prediction, 6),
            "bins_within_interval": self.bins_within_interval,
            "bin_count": len(self.bins),
            "bins": [b.to_dict() for b in self.bins],
        }


def _equal_frequency_edges(scores: np.ndarray, bins: int) -> np.ndarray:
    """Bin boundaries holding roughly equal counts, robust to heavy ties.

    Plain quantile edges are not sufficient here. When one score is repeated
    across most of the stream -- which is the normal condition for a rare-event
    detector, where the overwhelming majority of events score indistinguishably
    near zero -- every quantile from 0 to 0.9 returns that same value. They
    de-duplicate to a single interval, and the "reliability diagram" degenerates
    to one bin containing everything, whose mean prediction and observed
    frequency are just the stream-wide averages. That is not a wrong number so
    much as no measurement at all, and nothing in the output says so.

    That failure was observed, not hypothesised: the first calibration run over
    this corpus produced nine bins reading 0.00000 predicted against 0.00000
    observed, with every attack in the tenth.

    So after de-duplicating, the lost bins are recovered by repeatedly splitting
    whichever interval holds the most events, at the boundary that divides its
    events most evenly. A large block of identical scores cannot be split and
    settles into its own bin, while the informative region above it is
    subdivided -- which is the arrangement the diagram needs, since that region
    is where the ranking actually separates.
    """
    edges = [float(value) for value in np.unique(np.quantile(scores, np.linspace(0, 1, bins + 1)))]
    if len(edges) < 2:
        edges = [float(scores.min()), float(np.nextafter(scores.max(), np.inf))]

    ordered = np.sort(scores)
    distinct = np.unique(ordered)
    while len(edges) - 1 < bins:
        # The interval holding the most events is the one whose collapse costs
        # the most resolution, so it is the one worth splitting first.
        widest: tuple[int, int, float] | None = None
        for index in range(len(edges) - 1):
            low, high = edges[index], edges[index + 1]
            interior = distinct[(distinct > low) & (distinct < high)]
            if interior.size == 0:
                continue  # a solid block of ties: unsplittable
            start = int(np.searchsorted(ordered, low, side="left"))
            stop = int(np.searchsorted(ordered, high, side="left"))
            count = stop - start
            if count < 2 or (widest is not None and count <= widest[0]):
                continue
            # Split where the two halves come out closest in size, which puts a
            # dominant tie block alone on one side instead of straddling it.
            positions = np.searchsorted(ordered, interior, side="left")
            balance = np.abs((positions - start) - (stop - positions))
            widest = (count, index, float(interior[int(np.argmin(balance))]))
        if widest is None:
            break  # no interval can be divided further
        edges.insert(widest[1] + 1, widest[2])

    boundaries = np.array(edges, dtype=float)
    boundaries[-1] = np.nextafter(boundaries[-1], np.inf)
    return boundaries


def calibration_report(
    labels: Sequence[int], scores: Sequence[float], *, bins: int = DEFAULT_BINS
) -> CalibrationReport:
    label_array = np.asarray(list(labels), dtype=int)
    score_array = np.asarray(list(scores), dtype=float)
    if label_array.shape != score_array.shape:
        raise ValueError("labels and scores must have the same length")
    if label_array.size == 0:
        raise ValueError("cannot assess calibration over an empty stream")

    edges = _equal_frequency_edges(score_array, bins)
    assignments = np.clip(np.digitize(score_array, edges) - 1, 0, len(edges) - 2)

    prevalence = float(label_array.mean())
    built: list[Bin] = []
    weighted_error = 0.0
    maximum_error = 0.0
    reliability = 0.0
    resolution = 0.0

    for index in range(len(edges) - 1):
        mask = assignments == index
        count = int(mask.sum())
        if count == 0:
            continue
        positives = int(label_array[mask].sum())
        observed = positives / count
        predicted = float(score_array[mask].mean())
        built.append(
            Bin(
                index=index,
                events=count,
                positives=positives,
                mean_predicted=predicted,
                observed_frequency=observed,
                interval=wilson_interval(positives, count),
                score_range=(float(edges[index]), float(edges[index + 1])),
            )
        )
        gap = abs(observed - predicted)
        weighted_error += count / label_array.size * gap
        maximum_error = max(maximum_error, gap)
        reliability += count / label_array.size * (predicted - observed) ** 2
        resolution += count / label_array.size * (observed - prevalence) ** 2

    brier = float(np.mean((score_array - label_array) ** 2))
    return CalibrationReport(
        bins=tuple(built),
        expected_calibration_error=weighted_error,
        maximum_calibration_error=maximum_error,
        brier_score=brier,
        reliability=reliability,
        resolution=resolution,
        uncertainty=prevalence * (1 - prevalence),
        prevalence=prevalence,
        mean_prediction=float(score_array.mean()),
    )


def render_reliability(report: CalibrationReport, width: int = 46) -> str:
    """Text reliability diagram.

    Plotted on a log scale because at 0.1% prevalence a linear axis compresses
    every informative bin into the bottom pixel row.
    """
    lines = [
        f"{'bin':>4}{'events':>9}{'pos':>6}{'predicted':>11}{'observed':>10}  "
        f"{'observed vs predicted (log scale)':<{width}}",
        "-" * (40 + width),
    ]

    def position(value: float) -> int:
        floor = 1e-6
        value = max(value, floor)
        return int((math.log10(value) - math.log10(floor)) / -math.log10(floor) * (width - 1))

    for b in report.bins:
        row = [" "] * width
        row[position(b.mean_predicted)] = "p"
        observed_at = position(b.observed_frequency)
        row[observed_at] = "O" if row[observed_at] == " " else "*"
        flag = "" if b.calibrated else "  <- outside interval"
        lines.append(
            f"{b.index:>4}{b.events:>9,}{b.positives:>6}{b.mean_predicted:>11.5f}"
            f"{b.observed_frequency:>10.5f}  {''.join(row)}{flag}"
        )
    lines.append("")
    lines.append(
        "  p = mean predicted probability, O = observed frequency, * = both in the same cell"
    )
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class PrecisionThreshold:
    """The lowest score at which precision is *supportably* at least a target.

    "Supportably" means the Wilson lower bound clears the target, not the
    point estimate. A gate set on the point estimate is looser than it looks:
    the estimate sits in the middle of its interval, so half the plausible
    true precisions are below it.
    """

    target: float
    threshold: float
    alerts: int
    positives: int
    precision: float
    lower_bound: float

    def to_dict(self) -> dict[str, float | int]:
        return {
            "target": self.target,
            "threshold": round(self.threshold, 6),
            "alerts": self.alerts,
            "positives": self.positives,
            "precision": round(self.precision, 4),
            "lower_bound": round(self.lower_bound, 4),
        }


def threshold_for_precision(
    labels: Sequence[int],
    scores: Sequence[float],
    target: float,
    *,
    minimum_alerts: int = 20,
) -> PrecisionThreshold | None:
    """Lowest threshold whose Wilson lower bound on precision reaches ``target``.

    Walks the distinct scores from the top down and stops at the first one
    that fails, so the result is the most permissive gate the data supports.
    Returns ``None`` when no threshold with at least ``minimum_alerts`` events
    above it clears the target -- at 0.1% prevalence that is the common answer
    for targets of 90% and up, and it is an answer, not an error.
    """
    if not 0.0 < target < 1.0:
        raise ValueError("target must be strictly between 0 and 1")
    if minimum_alerts < 1:
        raise ValueError("minimum_alerts must be positive")
    label_array = np.asarray(list(labels), dtype=int)
    score_array = np.asarray(list(scores), dtype=float)
    if label_array.shape != score_array.shape:
        raise ValueError("labels and scores must have the same length")
    best: PrecisionThreshold | None = None
    for candidate in np.sort(np.unique(score_array[score_array > 0]))[::-1]:
        above = score_array >= candidate
        alerts = int(above.sum())
        if alerts < minimum_alerts:
            continue
        positives = int(label_array[above].sum())
        lower, _ = wilson_interval(positives, alerts)
        if lower < target:
            break
        best = PrecisionThreshold(
            target=target,
            threshold=float(candidate),
            alerts=alerts,
            positives=positives,
            precision=positives / alerts,
            lower_bound=lower,
        )
    return best
