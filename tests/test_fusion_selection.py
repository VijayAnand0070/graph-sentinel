"""Fusion operator and decision threshold must travel together.

Swapping the operator changes the score distribution. An operator paired with
the other operator's threshold silently changes the alert rate -- the numbers
still look plausible, nothing errors, and the false-positive budget the
deployment was sold on quietly stops holding. `select_fusion` returns both as
one value so that pairing cannot be got wrong by construction.
"""

from __future__ import annotations

import pytest

from graphsentinel.detection.fusion import (DEFAULT_NOISY_OR_CONFIG,
                                            OPERATING_POINTS, TEST_PR_AUC_CI,
                                            FusionConfig, NoisyOrConfig,
                                            RiskComponents, fuse_risk,
                                            select_fusion)


def components(**overrides: float) -> RiskComponents:
    base = {"tgn": 0.0, "novelty": 0.0, "burst": 0.0, "pivot": 0.0, "corroboration": 0.0}
    return RiskComponents(**{**base, **overrides})


class TestPairing:
    def test_each_operator_returns_its_own_threshold(self) -> None:
        _, noisy = select_fusion("noisy_or")
        _, linear = select_fusion("linear")
        assert noisy == pytest.approx(OPERATING_POINTS["noisy_or"]["threshold"])
        assert linear == pytest.approx(OPERATING_POINTS["linear"]["threshold"])
        assert noisy != linear

    def test_the_noisy_or_threshold_lives_on_its_config(self) -> None:
        """Carried on the config so it cannot be separated from the weights."""
        config, threshold = select_fusion("noisy_or")
        assert isinstance(config, NoisyOrConfig)
        assert config.calibrated_threshold == pytest.approx(threshold)

    def test_spellings_are_accepted(self) -> None:
        for name in ("noisy_or", "noisy-or", "NoisyOR", "  NOISY_OR  "):
            config, _ = select_fusion(name)
            assert isinstance(config, NoisyOrConfig)

    def test_an_unknown_operator_is_rejected_loudly(self) -> None:
        """Silently defaulting would give a deployment an operator it did not
        ask for, at a threshold calibrated for something else."""
        with pytest.raises(ValueError, match="unknown fusion operator"):
            select_fusion("weighted_geometric_mean")


class TestTheVeto:
    #: The threshold stored in the shipped checkpoint, calibrated during
    #: training. This is what the system actually ran at.
    DEPLOYED_CHECKPOINT_THRESHOLD = 0.4543

    def test_linear_vetoed_the_rules_at_the_deployed_threshold(self) -> None:
        """The defect that motivated noisy-OR, stated precisely.

        With tgn at zero, perfect evidence on every other channel scores 0.45
        and does not clear the 0.4543 threshold the checkpoint shipped with.
        So no amount of behavioural evidence could raise an alert alone.

        The veto is a property of the weights AND that specific threshold, not
        of linear fusion in general -- re-deriving the linear threshold on
        validation gives 0.3626, which 0.45 clears. Worth stating exactly,
        because "weighted averages always veto" would be wrong.
        """
        config, _ = select_fusion("linear")
        perfect = components(novelty=1.0, burst=1.0, pivot=1.0, corroboration=1.0)
        score = fuse_risk(perfect, config).score
        assert score == pytest.approx(0.45)
        assert score < self.DEPLOYED_CHECKPOINT_THRESHOLD

    def test_recalibrating_linear_removes_the_veto(self) -> None:
        """Half the fix was simply that the threshold had never been re-derived."""
        config, threshold = select_fusion("linear")
        perfect = components(novelty=1.0, burst=1.0, pivot=1.0, corroboration=1.0)
        assert fuse_risk(perfect, config).score >= threshold

    def test_noisy_or_has_no_veto(self) -> None:
        config, threshold = select_fusion("noisy_or")
        perfect = components(novelty=1.0, burst=1.0, pivot=1.0, corroboration=1.0)
        assert fuse_risk(perfect, config).score >= threshold

    def test_behavioural_ceiling_exposes_the_linear_problem(self) -> None:
        ceiling = FusionConfig().behavioural_ceiling()
        assert ceiling == pytest.approx(0.45)
        # Below the threshold the checkpoint was calibrated at, which is the
        # whole defect in one comparison.
        assert ceiling < 0.4543


class TestOperatorProperties:
    def test_noisy_or_is_monotonic_in_every_channel(self) -> None:
        """More evidence must never lower the score."""
        config = DEFAULT_NOISY_OR_CONFIG
        for channel in ("tgn", "novelty", "burst", "pivot", "corroboration"):
            low = fuse_risk(components(**{channel: 0.2}), config).score
            high = fuse_risk(components(**{channel: 0.9}), config).score
            assert high >= low, f"{channel} is not monotonic"

    def test_noisy_or_stays_bounded(self) -> None:
        everything = components(tgn=1.0, novelty=1.0, burst=1.0, pivot=1.0,
                                corroboration=1.0)
        assert 0.0 <= fuse_risk(everything, DEFAULT_NOISY_OR_CONFIG).score <= 1.0

    def test_weak_channels_compound(self) -> None:
        """Three mediocre signals should beat one, or the operator is just a max."""
        config = DEFAULT_NOISY_OR_CONFIG
        one = fuse_risk(components(burst=0.5), config).score
        three = fuse_risk(components(burst=0.5, corroboration=0.5, novelty=0.5), config).score
        assert three > one

    def test_linear_contributions_sum_to_the_score(self) -> None:
        config, _ = select_fusion("linear")
        result = fuse_risk(components(tgn=0.6, novelty=0.4, burst=0.2), config)
        assert sum(result.contributions().values()) == pytest.approx(result.score)

    def test_noisy_or_reports_marginal_contributions(self) -> None:
        """Marginals do not sum to the score -- the operator is not additive.
        Documented rather than hidden, so nobody reads it as a bug."""
        config, _ = select_fusion("noisy_or")
        result = fuse_risk(components(tgn=0.6, burst=0.4), config)
        contributions = result.contributions()
        assert contributions["tgn"] > 0
        assert result.dominant_channel() == "tgn"

    def test_dominant_channel_is_none_when_nothing_fired(self) -> None:
        config, _ = select_fusion("noisy_or")
        assert fuse_risk(components(), config).dominant_channel() is None


def test_operating_points_record_what_was_measured() -> None:
    """These are the numbers a deployment is choosing between; they must stay
    attached to the code that implements them."""
    assert OPERATING_POINTS["noisy_or"]["test_pr_auc"] > OPERATING_POINTS["linear"]["test_pr_auc"]
    for point in OPERATING_POINTS.values():
        assert 0.0 < point["threshold"] < 1.0
        assert 0.0 < point["test_pr_auc"] <= 1.0


class TestPureModelOperatingPoint:
    """`tgn_only` exists because the measurement said fusion costs accuracy.

    Paired bootstrap on the test partition: raw TGN minus noisy-OR is
    +0.0170 [+0.0064, +0.0317], significant. Fusion is retained for
    attribution, degradation and rule floors -- not for ranking quality -- and
    a deployment that wants the latter should be able to say so.
    """

    def test_it_is_an_exact_passthrough(self) -> None:
        config, _ = select_fusion("tgn_only")
        for probability in (0.0, 0.137, 0.5, 0.913, 1.0):
            result = fuse_risk(
                RiskComponents(tgn=probability, novelty=1.0, burst=1.0,
                               pivot=1.0, corroboration=1.0),
                config,
            )
            assert result.score == pytest.approx(probability), (
                "other channels must not leak into a pure-model score"
            )

    def test_it_carries_its_own_threshold(self) -> None:
        config, threshold = select_fusion("tgn_only")
        assert threshold == pytest.approx(OPERATING_POINTS["tgn_only"]["threshold"])
        assert config.calibrated_threshold == pytest.approx(threshold)

    def test_it_still_accepts_a_rule_floor(self) -> None:
        """Choosing the raw model must not give up the deterministic layer."""
        from graphsentinel.detection.fusion import apply_rule_floor

        config, threshold = select_fusion("tgn_only")
        quiet = fuse_risk(RiskComponents(tgn=0.01, novelty=0.0, burst=0.0,
                                         pivot=1.0, corroboration=0.0), config)
        assert quiet.score < threshold
        floored = apply_rule_floor(quiet, chain_detected=True)
        assert floored.score >= threshold
        assert floored.rule_floor == "chain_pivot"


class TestReportedUncertainty:
    def test_every_operating_point_has_an_interval(self) -> None:
        """A point estimate on 126 attacks quoted without an interval is a
        claim the data does not support."""
        assert set(TEST_PR_AUC_CI) == set(OPERATING_POINTS)

    def test_intervals_bracket_their_point_estimates(self) -> None:
        for name, (low, high) in TEST_PR_AUC_CI.items():
            point = OPERATING_POINTS[name]["test_pr_auc"]
            assert low <= point <= high, f"{name}: {point} outside [{low}, {high}]"

    def test_the_intervals_are_wide_enough_to_matter(self) -> None:
        """Recorded so nobody reads these as precise. 126 attacks is not many."""
        for name, (low, high) in TEST_PR_AUC_CI.items():
            assert high - low > 0.10, f"{name} interval is implausibly tight"

    def test_linear_and_noisy_or_intervals_do_not_overlap(self) -> None:
        """The headline comparison survives its own uncertainty."""
        assert TEST_PR_AUC_CI["linear"][1] < TEST_PR_AUC_CI["noisy_or"][0]
