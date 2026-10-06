import pytest

from graphsentinel.api.monitoring import OperationalMonitor


def test_monitoring_tracks_bounded_latency_and_score_distributions() -> None:
    monitor = OperationalMonitor(distribution_capacity=2)
    monitor.record_success(latency_ms=1, scores=[0.1])
    monitor.record_success(latency_ms=2, scores=[0.2, 0.8])
    monitor.record_failure(latency_ms=3)

    snapshot = monitor.snapshot()

    assert snapshot.requests == 3
    assert snapshot.failed_requests == 1
    assert snapshot.scored_events == 3
    assert snapshot.latency_ms_mean == 2.5
    assert snapshot.latency_ms_p95 == 3
    assert snapshot.score_mean == pytest.approx(0.5)
    assert snapshot.score_min == 0.2
    assert snapshot.score_max == 0.8


def test_monitoring_rejects_invalid_observations() -> None:
    monitor = OperationalMonitor()

    with pytest.raises(ValueError, match="invalid"):
        monitor.record_success(latency_ms=-1, scores=[])
    with pytest.raises(ValueError, match="invalid"):
        monitor.record_success(latency_ms=1, scores=[1.1])
