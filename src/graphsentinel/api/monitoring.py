"""Bounded-memory operational monitoring for the scoring service."""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from threading import RLock


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1)
    return ordered[max(index, 0)]


@dataclass(frozen=True, slots=True)
class MonitoringSnapshot:
    requests: int
    failed_requests: int
    scored_events: int
    latency_ms_mean: float
    latency_ms_p50: float
    latency_ms_p95: float
    score_mean: float
    score_min: float
    score_max: float

    def to_dict(self) -> dict[str, int | float]:
        return {
            "requests": self.requests,
            "failed_requests": self.failed_requests,
            "scored_events": self.scored_events,
            "latency_ms_mean": self.latency_ms_mean,
            "latency_ms_p50": self.latency_ms_p50,
            "latency_ms_p95": self.latency_ms_p95,
            "score_mean": self.score_mean,
            "score_min": self.score_min,
            "score_max": self.score_max,
        }


class OperationalMonitor:
    """Thread-safe counters and bounded recent distributions."""

    def __init__(self, *, distribution_capacity: int = 10_000) -> None:
        if distribution_capacity <= 0:
            raise ValueError("distribution_capacity must be positive")
        self._lock = RLock()
        self._requests = 0
        self._failed_requests = 0
        self._scored_events = 0
        self._latencies: deque[float] = deque(maxlen=distribution_capacity)
        self._scores: deque[float] = deque(maxlen=distribution_capacity)

    def record_success(self, *, latency_ms: float, scores: list[float]) -> None:
        if latency_ms < 0 or any(not 0 <= score <= 1 for score in scores):
            raise ValueError("invalid latency or score observation")
        with self._lock:
            self._requests += 1
            self._scored_events += len(scores)
            self._latencies.append(latency_ms)
            self._scores.extend(scores)

    def record_failure(self, *, latency_ms: float) -> None:
        if latency_ms < 0:
            raise ValueError("latency cannot be negative")
        with self._lock:
            self._requests += 1
            self._failed_requests += 1
            self._latencies.append(latency_ms)

    def score_windows(
        self, *, baseline_size: int = 500, current_size: int = 200
    ) -> tuple[tuple[float, ...], tuple[float, ...]]:
        """Split retained score history into an earlier baseline and a recent window.

        Both windows are read from the same bounded ``_scores`` deque, so
        "baseline" means "earliest still-retained" rather than "since service
        start" once the deque's capacity has cycled — a graceful degradation
        for drift comparison, not a correctness issue, since retained history
        still spans a meaningfully earlier period than the current window.
        Returns two empty tuples if there isn't yet enough history for both.
        """

        with self._lock:
            scores = list(self._scores)
        if len(scores) < baseline_size + current_size:
            return (), ()
        return tuple(scores[:baseline_size]), tuple(scores[-current_size:])

    def snapshot(self) -> MonitoringSnapshot:
        with self._lock:
            latencies = list(self._latencies)
            scores = list(self._scores)
            return MonitoringSnapshot(
                requests=self._requests,
                failed_requests=self._failed_requests,
                scored_events=self._scored_events,
                latency_ms_mean=sum(latencies) / len(latencies) if latencies else 0.0,
                latency_ms_p50=_percentile(latencies, 0.50),
                latency_ms_p95=_percentile(latencies, 0.95),
                score_mean=sum(scores) / len(scores) if scores else 0.0,
                score_min=min(scores) if scores else 0.0,
                score_max=max(scores) if scores else 0.0,
            )
