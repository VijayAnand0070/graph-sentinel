from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from graphsentinel.features.causal import CausalFeatureEngine, FeatureRecord
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.models.baselines import (
    IsolationForestBaseline,
    LogisticBaseline,
    RarityBaseline,
    RuleBaseline,
)


def _records() -> list[FeatureRecord]:
    events = [
        NormalizedAuthEvent(
            event_id=index,
            timestamp=index + 1,
            src_user_id=1,
            dst_user_id=1,
            src_host_id=1,
            dst_host_id=2 + index,
            auth_type_id=1,
            logon_type_id=1,
            orientation_id=1,
            success=1,
            label_redteam=index % 2,
            day=0,
            hour=0,
        )
        for index in range(8)
    ]
    return list(CausalFeatureEngine().transform(events))


def test_rule_and_rarity_scores_are_probabilities() -> None:
    records = _records()
    for baseline in (RuleBaseline(), RarityBaseline()):
        scores = baseline.predict_scores(records)
        assert len(scores) == len(records)
        assert all(0 <= score <= 1 for score in scores)


def test_logistic_baseline_fits_scores_and_saves(tmp_path: Path) -> None:
    records = _records()
    model = LogisticBaseline().fit(records)

    scores = model.predict_scores(records)
    destination = tmp_path / "logistic.joblib"
    model.save(destination)

    assert len(scores) == len(records)
    assert all(0 <= score <= 1 for score in scores)
    assert destination.is_file()


def test_logistic_baseline_requires_both_classes() -> None:
    records = [replace(record, label_redteam=0) for record in _records()]

    with pytest.raises(ValueError, match="both positive and negative"):
        LogisticBaseline().fit(records)


def test_isolation_forest_returns_empirical_probability_scores() -> None:
    records = _records()
    model = IsolationForestBaseline(estimators=10).fit(records)

    scores = model.predict_scores(records)

    assert len(scores) == len(records)
    assert all(0 <= score <= 1 for score in scores)
