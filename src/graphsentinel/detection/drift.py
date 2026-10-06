"""Detects when a live risk-score distribution has drifted from a baseline.

Every other detection module in this codebase assumes scores mean what they
meant when the alert threshold was tuned. If the live score distribution
quietly shifts — more high scores, fewer, a different shape entirely — that
assumption breaks silently: alerts stop being comparable to history even
though nothing about the alerting *pipeline* changed. This module gives that
shift a name and a number using two complementary, scipy-free statistics:

- Population Stability Index (PSI): bins both distributions identically and
  sums a weighted log-ratio of bucket populations. The standard MLOps metric
  for exactly this question, with the widely used severity cutoffs
  (< 0.1 stable, 0.1-0.25 moderate, > 0.25 significant) baked in.
- Two-sample Kolmogorov-Smirnov statistic: the maximum gap between the two
  empirical CDFs. Complements PSI because it isn't sensitive to bin-count
  choice and can catch shifts PSI's fixed binning dilutes.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

DriftSeverity = Literal["stable", "moderate", "significant"]


@dataclass(frozen=True, slots=True)
class DriftConfig:
    bin_count: int = 10
    moderate_threshold: float = 0.1
    significant_threshold: float = 0.25
    minimum_sample_size: int = 30

    def __post_init__(self) -> None:
        if self.bin_count < 2:
            raise ValueError("bin_count must be at least 2")
        if not 0 < self.moderate_threshold < self.significant_threshold:
            raise ValueError("thresholds must satisfy 0 < moderate < significant")
        if self.minimum_sample_size < 2:
            raise ValueError("minimum_sample_size must be at least 2")


@dataclass(frozen=True, slots=True)
class DriftReport:
    psi: float
    ks_statistic: float
    severity: DriftSeverity
    baseline_size: int
    current_size: int
    baseline_mean: float
    current_mean: float
    insufficient_data: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DEFAULT_DRIFT_CONFIG = DriftConfig()


def compute_drift(
    baseline: Sequence[float],
    current: Sequence[float],
    *,
    config: DriftConfig = DEFAULT_DRIFT_CONFIG,
) -> DriftReport:
    if any(not 0 <= v <= 1 for v in baseline) or any(not 0 <= v <= 1 for v in current):
        raise ValueError("all scores must be in [0, 1]")

    if len(baseline) < config.minimum_sample_size or len(current) < config.minimum_sample_size:
        return DriftReport(
            psi=0.0,
            ks_statistic=0.0,
            severity="stable",
            baseline_size=len(baseline),
            current_size=len(current),
            baseline_mean=sum(baseline) / len(baseline) if baseline else 0.0,
            current_mean=sum(current) / len(current) if current else 0.0,
            insufficient_data=True,
        )

    baseline_fractions = _bucket_fractions(baseline, config.bin_count)
    current_fractions = _bucket_fractions(current, config.bin_count)
    psi = sum(
        (curr - base) * math.log(curr / base)
        for base, curr in zip(baseline_fractions, current_fractions, strict=True)
    )
    ks_statistic = _ks_statistic(baseline, current)

    if psi >= config.significant_threshold:
        severity: DriftSeverity = "significant"
    elif psi >= config.moderate_threshold:
        severity = "moderate"
    else:
        severity = "stable"

    return DriftReport(
        psi=psi,
        ks_statistic=ks_statistic,
        severity=severity,
        baseline_size=len(baseline),
        current_size=len(current),
        baseline_mean=sum(baseline) / len(baseline),
        current_mean=sum(current) / len(current),
        insufficient_data=False,
    )


def _bucket_fractions(values: Sequence[float], bin_count: int) -> list[float]:
    counts = [0] * bin_count
    for value in values:
        index = min(int(value * bin_count), bin_count - 1)
        counts[index] += 1
    # A small floor avoids an undefined log(0/x) or divide-by-zero for an
    # empty bucket without materially distorting well-populated ones.
    floor = 1e-4
    n = len(values)
    return [max(count / n, floor) for count in counts]


def _ks_statistic(baseline: Sequence[float], current: Sequence[float]) -> float:
    """Max gap between empirical CDFs, evaluated at every distinct combined value.

    Ties must be resolved by advancing both samples' cursors together at a
    shared value before measuring the gap — a naive two-pointer merge that
    advances one side at a time overstates the statistic whenever the two
    samples share values (the common case for scores rounded to a few
    decimal places).
    """

    a = sorted(baseline)
    b = sorted(current)
    na, nb = len(a), len(b)
    combined = sorted(set(a) | set(b))
    ia = ib = 0
    max_gap = 0.0
    for x in combined:
        while ia < na and a[ia] <= x:
            ia += 1
        while ib < nb and b[ib] <= x:
            ib += 1
        gap = abs(ia / na - ib / nb)
        if gap > max_gap:
            max_gap = gap
    return max_gap
