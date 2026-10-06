import pytest

from graphsentinel.detection.drift import DriftConfig, compute_drift


def test_config_rejects_invalid_bin_count() -> None:
    with pytest.raises(ValueError):
        DriftConfig(bin_count=1)


def test_config_rejects_threshold_ordering() -> None:
    with pytest.raises(ValueError):
        DriftConfig(moderate_threshold=0.3, significant_threshold=0.1)


def test_rejects_scores_out_of_range() -> None:
    with pytest.raises(ValueError):
        compute_drift([1.5] * 40, [0.5] * 40)


def test_insufficient_data_reports_stable_without_computing() -> None:
    report = compute_drift([0.1] * 5, [0.9] * 5, config=DriftConfig(minimum_sample_size=30))
    assert report.insufficient_data is True
    assert report.severity == "stable"
    assert report.psi == 0.0


def test_identical_distributions_report_stable_with_near_zero_psi() -> None:
    baseline = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9] * 10
    report = compute_drift(baseline, baseline)
    assert report.insufficient_data is False
    assert report.severity == "stable"
    assert report.psi == pytest.approx(0.0, abs=1e-6)
    assert report.ks_statistic == pytest.approx(0.0, abs=1e-9)


def test_completely_disjoint_distributions_report_significant() -> None:
    baseline = [0.05] * 50
    current = [0.95] * 50
    report = compute_drift(baseline, current)
    assert report.severity == "significant"
    assert report.psi > 0.25
    assert report.ks_statistic == pytest.approx(1.0)


def test_moderate_shift_is_classified_between_thresholds() -> None:
    # Computed to land PSI ~= 0.164, comfortably inside (0.1, 0.25).
    baseline = ([0.1] * 65) + ([0.9] * 35)
    current = ([0.1] * 45) + ([0.9] * 55)
    report = compute_drift(baseline, current)
    assert report.severity == "moderate"
    assert 0.1 <= report.psi < 0.25


def test_baseline_and_current_means_are_reported() -> None:
    baseline = [0.2] * 40
    current = [0.8] * 40
    report = compute_drift(baseline, current)
    assert report.baseline_mean == pytest.approx(0.2)
    assert report.current_mean == pytest.approx(0.8)


def test_ks_statistic_handles_ties_without_overstating() -> None:
    # Every value appears in both samples -> true KS distance is 0.
    shared = [0.1, 0.1, 0.5, 0.5, 0.9, 0.9] * 10
    report = compute_drift(shared, shared)
    assert report.ks_statistic == pytest.approx(0.0, abs=1e-9)


def test_sample_sizes_recorded_correctly() -> None:
    baseline = [0.5] * 41
    current = [0.5] * 37
    report = compute_drift(baseline, current)
    assert report.baseline_size == 41
    assert report.current_size == 37
