"""Tests for the calibration analysis.

The properties worth pinning here are the ones that would silently produce a
plausible-looking but wrong reliability diagram: an interval that excludes the
truth, bins that lose events, or a Brier decomposition that does not actually
decompose. Each is checked against a closed form or a constructed case rather
than against a previously-observed output, so the test fails when the maths is
wrong rather than when the numbers merely move.
"""

from __future__ import annotations

import math

import numpy as np
import pytest

from graphsentinel.evaluation.calibration import (DEFAULT_BINS, Bin,
                                                  calibration_report,
                                                  render_reliability,
                                                  wilson_interval)


class TestWilsonInterval:
    def test_zero_trials_is_not_an_error(self) -> None:
        """Empty bins are the common case at 0.1% prevalence, not an edge case."""
        assert wilson_interval(0, 0) == (0.0, 0.0)

    def test_stays_inside_the_unit_interval_at_the_extremes(self) -> None:
        """The reason this is used instead of the normal approximation, which
        returns a negative lower bound for 0 successes."""
        for successes, trials in ((0, 10), (10, 10), (0, 1), (1, 1), (0, 100000)):
            low, high = wilson_interval(successes, trials)
            assert 0.0 <= low <= high <= 1.0, (successes, trials, low, high)

    def test_zero_successes_gives_a_lower_bound_of_exactly_zero(self) -> None:
        low, high = wilson_interval(0, 200)
        assert low == 0.0
        assert 0.0 < high < 0.05

    def test_matches_the_published_closed_form(self) -> None:
        """Checked against the formula rather than a remembered number.

        Wilson's interval for 1/200 is a standard worked example; deriving it
        independently here means a typo in the implementation cannot be
        absorbed by an expectation copied from the same typo.
        """
        successes, trials, z = 1, 200, 1.96
        p = successes / trials
        denominator = 1 + z * z / trials
        centre = (p + z * z / (2 * trials)) / denominator
        spread = (z / denominator) * math.sqrt(
            p * (1 - p) / trials + z * z / (4 * trials * trials)
        )
        low, high = wilson_interval(successes, trials)
        assert low == pytest.approx(centre - spread, abs=1e-12)
        assert high == pytest.approx(centre + spread, abs=1e-12)

    def test_the_interval_contains_the_point_estimate(self) -> None:
        for successes, trials in ((1, 200), (5, 50), (37, 100), (99, 100)):
            low, high = wilson_interval(successes, trials)
            assert low <= successes / trials <= high

    def test_more_data_narrows_the_interval(self) -> None:
        """Same proportion, more evidence, tighter bound."""
        widths = []
        for scale in (1, 10, 100, 1000):
            low, high = wilson_interval(1 * scale, 20 * scale)
            widths.append(high - low)
        assert widths == sorted(widths, reverse=True)

    def test_a_wider_z_gives_a_wider_interval(self) -> None:
        narrow = wilson_interval(5, 100, z=1.0)
        wide = wilson_interval(5, 100, z=2.58)
        assert (wide[1] - wide[0]) > (narrow[1] - narrow[0])


class TestCalibrationReport:
    def test_rejects_an_empty_stream(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            calibration_report([], [])

    def test_rejects_mismatched_lengths(self) -> None:
        with pytest.raises(ValueError, match="same length"):
            calibration_report([0, 1], [0.5])

    def test_every_event_lands_in_exactly_one_bin(self) -> None:
        """A silent off-by-one in the bin edges loses events at the boundary,
        which shifts every frequency without any visible error."""
        rng = np.random.default_rng(0)
        scores = rng.random(5000)
        labels = (rng.random(5000) < scores).astype(int)
        report = calibration_report(labels, scores)
        assert sum(b.events for b in report.bins) == len(labels)
        assert sum(b.positives for b in report.bins) == int(labels.sum())

    def test_the_extreme_scores_are_not_dropped(self) -> None:
        """The maximum score must fall inside the top bin, not past its edge."""
        scores = np.linspace(0.0, 1.0, 1000)
        labels = (scores > 0.5).astype(int)
        report = calibration_report(labels, scores)
        assert sum(b.events for b in report.bins) == 1000
        assert report.bins[-1].score_range[1] > 1.0

    def test_a_perfectly_calibrated_stream_has_near_zero_error(self) -> None:
        """Scores drawn as true probabilities, labels drawn from them."""
        rng = np.random.default_rng(7)
        scores = rng.random(200_000)
        labels = (rng.random(200_000) < scores).astype(int)
        report = calibration_report(labels, scores)
        assert report.expected_calibration_error < 0.01
        assert report.reliability < 0.001
        assert report.bins_within_interval >= DEFAULT_BINS - 2

    def test_a_systematically_overconfident_stream_is_detected(self) -> None:
        """The failure mode this module exists to catch: predictions inflated
        far above the frequencies that actually occur."""
        rng = np.random.default_rng(11)
        truth = rng.random(50_000) * 0.1
        labels = (rng.random(50_000) < truth).astype(int)
        scores = np.clip(truth * 5, 0, 1)          # 5x over-confident
        report = calibration_report(labels, scores)
        assert report.mean_prediction > report.prevalence * 3
        assert report.expected_calibration_error > 0.05
        assert report.bins_within_interval < DEFAULT_BINS // 2

    def test_brier_actually_decomposes(self) -> None:
        """Brier = reliability - resolution + uncertainty (Murphy 1973).

        Reported as three numbers, so the identity connecting them has to hold
        or the parts are not describing the whole. Exact only in the limit of
        within-bin constant predictions, so this checks agreement to the
        binning error rather than to floating point.
        """
        rng = np.random.default_rng(3)
        scores = rng.random(100_000)
        labels = (rng.random(100_000) < scores).astype(int)
        report = calibration_report(labels, scores, bins=50)
        reconstructed = report.reliability - report.resolution + report.uncertainty
        assert reconstructed == pytest.approx(report.brier_score, abs=5e-4)

    def test_uncertainty_is_fixed_by_prevalence_alone(self) -> None:
        """It is p(1-p) regardless of the detector, which is the whole reason
        it is reported separately."""
        labels = np.zeros(1000, dtype=int)
        labels[:30] = 1
        for scores in (np.zeros(1000), np.ones(1000), np.linspace(0, 1, 1000)):
            report = calibration_report(labels, scores)
            assert report.uncertainty == pytest.approx(0.03 * 0.97)

    def test_a_constant_predictor_has_no_resolution(self) -> None:
        """Resolution measures separation from the base rate; a detector that
        says the same thing about everything separates nothing."""
        rng = np.random.default_rng(5)
        labels = (rng.random(10_000) < 0.2).astype(int)
        report = calibration_report(labels, np.full(10_000, 0.2))
        assert report.resolution == pytest.approx(0.0, abs=1e-9)

    def test_survives_a_heavily_tied_score_distribution(self) -> None:
        """The real case: most events share a near-identical low score, so the
        quantile edges collapse and a naive implementation emits empty bins or
        divides by zero."""
        scores = np.concatenate([np.full(99_000, 1e-9), np.linspace(0.5, 1.0, 1_000)])
        labels = np.concatenate([np.zeros(99_000, dtype=int), np.ones(1_000, dtype=int)])
        report = calibration_report(labels, scores)
        assert len(report.bins) >= 2
        assert sum(b.events for b in report.bins) == len(labels)
        assert all(b.events > 0 for b in report.bins)

    def test_rare_events_do_not_produce_a_degenerate_report(self) -> None:
        """At the prevalence this system runs at, most bins hold no positives.

        The positives are concentrated at the top of the score range rather
        than sprinkled independently of it, because a detector that ranks at
        all is the case worth testing -- and it is the case that empties the
        lower bins.
        """
        rng = np.random.default_rng(13)
        scores = rng.random(100_000) ** 8
        labels = (rng.random(100_000) < scores * 0.05).astype(int)
        report = calibration_report(labels, scores)
        assert report.prevalence < 0.01
        assert any(b.positives == 0 for b in report.bins)
        for b in report.bins:
            assert b.interval[0] <= b.observed_frequency <= b.interval[1]


class TestBinCalibration:
    def test_calibrated_is_interval_containment(self) -> None:
        inside = Bin(0, 100, 5, 0.05, 0.05, (0.02, 0.11), (0.0, 0.1))
        outside = Bin(0, 100, 5, 0.90, 0.05, (0.02, 0.11), (0.0, 0.1))
        assert inside.calibrated
        assert not outside.calibrated

    def test_serialisation_round_trips_the_fields_a_reader_needs(self) -> None:
        payload = Bin(3, 100, 5, 0.05, 0.05, (0.02, 0.11), (0.0, 0.1)).to_dict()
        assert payload["bin"] == 3
        assert payload["events"] == 100
        assert payload["positives"] == 5
        assert payload["ci95"] == [0.02, 0.11]
        assert payload["calibrated"] is True


class TestRendering:
    def test_diagram_has_one_row_per_bin(self) -> None:
        rng = np.random.default_rng(17)
        scores = rng.random(10_000)
        labels = (rng.random(10_000) < scores).astype(int)
        report = calibration_report(labels, scores)
        body = [line for line in render_reliability(report).splitlines()
                if line and line[:4].strip().isdigit()]
        assert len(body) == len(report.bins)

    def test_miscalibrated_bins_are_flagged_in_the_text(self) -> None:
        rng = np.random.default_rng(19)
        truth = rng.random(20_000) * 0.1
        labels = (rng.random(20_000) < truth).astype(int)
        report = calibration_report(labels, np.clip(truth * 8, 0, 1))
        assert "outside interval" in render_reliability(report)

    def test_report_serialises_with_the_decomposition_note(self) -> None:
        rng = np.random.default_rng(23)
        scores = rng.random(1_000)
        labels = (rng.random(1_000) < scores).astype(int)
        payload = calibration_report(labels, scores).to_dict()
        assert set(payload["brier"]) == {"score", "reliability", "resolution",
                                         "uncertainty", "note"}
        assert payload["bin_count"] == len(payload["bins"])
