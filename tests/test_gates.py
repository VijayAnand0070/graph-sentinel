"""The auto-execution gate must be derivable, and derived from what it claims.

Two layers. The derivation function is checked against constructed streams
with known answers. The shipped constant is then re-derived from the committed
scored cache and compared field by field, so it cannot drift from its source
-- a new checkpoint, a changed fixture, or a hand edit all make this fail.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import polars as pl
import pytest

from graphsentinel.detection import response
from graphsentinel.detection.gates import (
    AUTO_EXECUTE_GATE,
    AUTO_EXECUTE_PRECISION_TARGET,
    AUTO_EXECUTE_THRESHOLD,
    MINIMUM_GATE_ALERTS,
)
from graphsentinel.evaluation.calibration import threshold_for_precision, wilson_interval

SCORED_CACHE = Path(__file__).parent / "fixtures" / "fusion_cache.parquet"


def _product_risk(frame: pl.DataFrame) -> np.ndarray:
    """The alert risk as the detection service computes it, from cache columns."""
    from graphsentinel.detection.fusion import (
        NoisyOrConfig,
        RiskComponents,
        apply_rule_floor,
        fuse_risk,
    )

    config = NoisyOrConfig()
    return np.array(
        [
            apply_rule_floor(
                fuse_risk(
                    RiskComponents(
                        tgn=row["tgn"],
                        novelty=row["novelty"],
                        burst=row["burst"],
                        pivot=row["pivot"],
                        corroboration=0.0,
                    ),
                    config,
                ),
                chain_detected=bool(row["chain"]),
            ).score
            for row in frame.iter_rows(named=True)
        ]
    )


class TestThresholdForPrecision:
    def test_finds_the_most_permissive_supportable_gate(self) -> None:
        """Positives at the top, then a mixed band, then noise: the gate must
        land where the lower bound last clears the target, not where the point
        estimate does."""
        scores = np.concatenate(
            [
                np.linspace(0.9, 1.0, 40),  # all positive
                np.linspace(0.5, 0.89, 40),  # half positive
                np.linspace(0.0, 0.49, 400),
            ]
        )  # all negative
        labels = np.concatenate([np.ones(40), np.tile([1, 0], 20), np.zeros(400)]).astype(int)
        result = threshold_for_precision(labels, scores, 0.75, minimum_alerts=20)
        assert result is not None
        above = scores >= result.threshold
        lower, _ = wilson_interval(int(labels[above].sum()), int(above.sum()))
        assert lower >= 0.75
        # One step more permissive must fail the target -- otherwise this was
        # not the most permissive gate.
        next_lower = np.sort(np.unique(scores[scores < result.threshold]))[-1]
        above = scores >= next_lower
        lower, _ = wilson_interval(int(labels[above].sum()), int(above.sum()))
        assert lower < 0.75

    def test_uses_the_lower_bound_not_the_point_estimate(self) -> None:
        """25 events at 80% precision: the point estimate clears 75%, the
        Wilson lower bound (about 61%) does not. No gate must be returned."""
        scores = np.concatenate([np.full(25, 0.9), np.zeros(1000)])
        labels = np.concatenate([np.array([1] * 20 + [0] * 5), np.zeros(1000)]).astype(int)
        assert threshold_for_precision(labels, scores, 0.75, minimum_alerts=20) is None

    def test_unreachable_targets_return_none_not_a_guess(self) -> None:
        rng = np.random.default_rng(0)
        scores = rng.random(5000)
        labels = (rng.random(5000) < 0.01).astype(int)
        assert threshold_for_precision(labels, scores, 0.90) is None

    def test_minimum_alerts_is_respected(self) -> None:
        scores = np.concatenate([np.full(5, 1.0), np.zeros(100)])
        labels = np.concatenate([np.ones(5), np.zeros(100)]).astype(int)
        assert threshold_for_precision(labels, scores, 0.5, minimum_alerts=20) is None
        assert threshold_for_precision(labels, scores, 0.5, minimum_alerts=5) is not None

    @pytest.mark.parametrize("target", [0.0, 1.0, 1.5])
    def test_invalid_targets_are_rejected(self, target: float) -> None:
        with pytest.raises(ValueError):
            threshold_for_precision([1, 0], [0.9, 0.1], target)


class TestShippedGate:
    def test_the_response_layer_uses_the_derived_gate(self) -> None:
        import inspect

        default = inspect.signature(response.plan_for).parameters["auto_execute_threshold"].default
        assert default == AUTO_EXECUTE_THRESHOLD == AUTO_EXECUTE_GATE.threshold

    def test_no_literal_gate_remains_in_the_response_module(self) -> None:
        import inspect

        source = inspect.getsource(response)
        assert "auto_execute_threshold: float = 0.85" not in source

    def test_the_gate_matches_its_derivation(self) -> None:
        """Re-derive from the committed cache and compare every recorded number.

        The gate is a claim about a specific model on a specific fixture. If
        either changes, the claim is stale, and this is where that surfaces.
        """
        assert SCORED_CACHE.is_file(), "committed scored cache missing"
        cache = pl.read_parquet(SCORED_CACHE)
        assert "chain" in cache.columns, "the cache predates the shared signal tracker"
        validation = cache.filter(pl.col("partition") == "validation")
        test = cache.filter(pl.col("partition") == "test")

        # The quantity the response layer compares: the fused risk, floored
        # by the chain rule, computed with the product's own functions.
        risk_validation = _product_risk(validation)
        risk_test = _product_risk(test)

        derived = threshold_for_precision(
            validation["label"].to_numpy().astype(int),
            risk_validation,
            AUTO_EXECUTE_PRECISION_TARGET,
            minimum_alerts=MINIMUM_GATE_ALERTS,
        )
        assert derived is not None
        assert derived.threshold == pytest.approx(AUTO_EXECUTE_GATE.threshold, abs=1e-6)
        assert derived.alerts == AUTO_EXECUTE_GATE.validation_alerts
        assert derived.precision == pytest.approx(AUTO_EXECUTE_GATE.validation_precision, abs=1e-4)
        assert derived.lower_bound == pytest.approx(
            AUTO_EXECUTE_GATE.validation_lower_bound, abs=1e-4
        )

        labels = test["label"].to_numpy().astype(int)
        above = risk_test >= AUTO_EXECUTE_GATE.threshold
        alerts, positives = int(above.sum()), int(labels[above].sum())
        low, high = wilson_interval(positives, alerts)
        assert alerts == AUTO_EXECUTE_GATE.test_alerts
        assert positives / alerts == pytest.approx(AUTO_EXECUTE_GATE.test_precision, abs=1e-4)
        assert (low, high) == pytest.approx(AUTO_EXECUTE_GATE.test_interval, abs=1e-4)

        for partition, risk, recorded in (
            ("validation", risk_validation, AUTO_EXECUTE_GATE.validation_benign_rate_per_10k),
            ("test", risk_test, AUTO_EXECUTE_GATE.test_benign_rate_per_10k),
        ):
            frame = cache.filter(pl.col("partition") == partition)
            benign = frame["label"].to_numpy() == 0
            rate = (
                1e4 * int((risk[benign] >= AUTO_EXECUTE_GATE.threshold).sum()) / int(benign.sum())
            )
            assert rate == pytest.approx(recorded, abs=1e-3), partition

    def test_the_gate_is_derived_on_what_the_response_layer_compares(self) -> None:
        """Finding 24: derived on the raw model probability, the gate admitted a
        different set of events from the one the product gates on."""
        assert "fused" in AUTO_EXECUTE_GATE.quantity and "floor" in AUTO_EXECUTE_GATE.quantity
        assert AUTO_EXECUTE_GATE.to_dict()["quantity"] == AUTO_EXECUTE_GATE.quantity

    def test_the_decay_from_validation_to_test_is_real_not_noise(self) -> None:
        """The intervals must not overlap, or the module's central claim --
        that precision at a fixed score does not hold across time -- would be
        unsupported by its own numbers."""
        validation_low = AUTO_EXECUTE_GATE.validation_lower_bound
        test_high = AUTO_EXECUTE_GATE.test_interval[1]
        assert test_high < validation_low
