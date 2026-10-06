"""Explainable lower bounds and supervised tabular baselines."""

from __future__ import annotations

import math
from bisect import bisect_right
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from graphsentinel.features.causal import MODEL_FEATURE_NAMES, FeatureRecord


class Baseline(Protocol):
    def predict_scores(self, records: Sequence[FeatureRecord]) -> list[float]: ...


def _sigmoid(value: float) -> float:
    if value >= 0:
        return 1 / (1 + math.exp(-value))
    exponential = math.exp(value)
    return exponential / (1 + exponential)


class RuleBaseline:
    """Transparent lateral-movement rule expressed as a smooth risk score."""

    def predict_scores(self, records: Sequence[FeatureRecord]) -> list[float]:
        scores = []
        for record in records:
            evidence = (
                1.5 * record.is_new_pair
                + 0.30 * min(record.user_unique_dst_5m, 10)
                + 0.20 * min(record.failures_before_success_15m, 10)
                + 0.25 * min(record.src_host_unique_dst_1h, 10)
                + 1.0 * record.destination_novelty
                - 3.0
            )
            scores.append(_sigmoid(evidence))
        return scores


class RarityBaseline:
    """Pure novelty baseline, deliberately independent of labels."""

    def predict_scores(self, records: Sequence[FeatureRecord]) -> list[float]:
        return [
            min(
                1.0,
                0.50 * record.pair_rarity
                + 0.25 * record.is_new_pair
                + 0.15 * record.destination_novelty
                + 0.10 * min(record.user_new_dst_ratio_1h, 1.0),
            )
            for record in records
        ]


class LogisticBaseline:
    """Class-weighted, scaled logistic regression over the frozen feature contract."""

    def __init__(self, *, random_state: int = 1729) -> None:
        try:
            from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
            from sklearn.pipeline import make_pipeline  # type: ignore[import-untyped]
            from sklearn.preprocessing import StandardScaler  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError('Install ML dependencies with: pip install -e ".[ml]"') from error
        self._pipeline = make_pipeline(
            StandardScaler(),
            LogisticRegression(
                class_weight="balanced",
                max_iter=1_000,
                random_state=random_state,
                solver="lbfgs",
            ),
        )
        self._fitted = False

    @staticmethod
    def _matrix(records: Sequence[FeatureRecord]) -> list[list[float]]:
        return [
            [float(getattr(record, feature)) for feature in MODEL_FEATURE_NAMES]
            for record in records
        ]

    def fit(self, records: Sequence[FeatureRecord]) -> LogisticBaseline:
        labels = [record.label_redteam for record in records]
        if set(labels) != {0, 1}:
            raise ValueError("logistic training requires both positive and negative events")
        self._pipeline.fit(self._matrix(records), labels)
        self._fitted = True
        return self

    def predict_scores(self, records: Sequence[FeatureRecord]) -> list[float]:
        if not self._fitted:
            raise RuntimeError("logistic baseline is not fitted")
        probabilities = self._pipeline.predict_proba(self._matrix(records))
        return [float(row[1]) for row in probabilities]

    def save(self, path: Path) -> None:
        if not self._fitted:
            raise RuntimeError("cannot save an unfitted model")
        import joblib  # type: ignore[import-untyped]

        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"schema_version": 1, "features": MODEL_FEATURE_NAMES, "model": self._pipeline},
            path,
        )


class IsolationForestBaseline:
    """Unsupervised anomaly baseline calibrated by the training empirical CDF."""

    def __init__(self, *, random_state: int = 1729, estimators: int = 200) -> None:
        if estimators <= 0:
            raise ValueError("estimators must be positive")
        try:
            from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]
        except ImportError as error:
            raise RuntimeError('Install ML dependencies with: pip install -e ".[ml]"') from error
        self._model = IsolationForest(
            n_estimators=estimators,
            contamination="auto",
            random_state=random_state,
            n_jobs=-1,
        )
        self._training_anomaly_scores: list[float] = []

    def fit(self, records: Sequence[FeatureRecord]) -> IsolationForestBaseline:
        if not records:
            raise ValueError("isolation forest training requires events")
        matrix = LogisticBaseline._matrix(records)
        self._model.fit(matrix)
        self._training_anomaly_scores = sorted(
            float(-score) for score in self._model.score_samples(matrix)
        )
        return self

    def predict_scores(self, records: Sequence[FeatureRecord]) -> list[float]:
        if not self._training_anomaly_scores:
            raise RuntimeError("isolation forest baseline is not fitted")
        raw_scores = (-self._model.score_samples(LogisticBaseline._matrix(records))).tolist()
        size = len(self._training_anomaly_scores)
        return [
            min(1.0, max(0.0, bisect_right(self._training_anomaly_scores, raw) / size))
            for raw in raw_scores
        ]
