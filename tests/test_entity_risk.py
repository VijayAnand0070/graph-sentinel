import pytest

from graphsentinel.detection.entity_risk import (
    AlertSignal,
    EntityRiskConfig,
    compute_entity_risk_scores,
)


def _signal(*, ts: int, risk: float, user: str, src: str, dst: str) -> AlertSignal:
    return AlertSignal(timestamp=ts, risk=risk, user=user, source_host=src, destination_host=dst)


def test_alert_signal_rejects_out_of_range_risk() -> None:
    with pytest.raises(ValueError):
        AlertSignal(timestamp=0, risk=1.5, user="u", source_host="a", destination_host="b")


def test_alert_signal_rejects_empty_entities() -> None:
    with pytest.raises(ValueError):
        AlertSignal(timestamp=0, risk=0.5, user="", source_host="a", destination_host="b")


def test_entity_risk_config_rejects_weights_not_summing_to_one() -> None:
    with pytest.raises(ValueError):
        EntityRiskConfig(risk_weight=0.5, fanout_weight=0.6)


def test_scores_are_bounded_in_unit_interval() -> None:
    signals = [_signal(ts=0, risk=1.0, user="u1", src="h1", dst="h2") for _ in range(50)]
    scores = compute_entity_risk_scores(signals, now=0)
    assert all(0 <= s.score <= 1 for s in scores)


def test_recent_alert_outranks_an_equally_risky_old_one() -> None:
    old_signal = _signal(ts=0, risk=0.9, user="u_old", src="h1", dst="h2")
    recent_signal = _signal(ts=10_000, risk=0.9, user="u_recent", src="h1", dst="h2")
    scores = compute_entity_risk_scores(
        [old_signal, recent_signal], now=10_000, config=EntityRiskConfig(half_life_seconds=100)
    )
    by_entity = {s.entity: s for s in scores if s.kind == "user"}
    assert by_entity["u_recent"].decayed_risk > by_entity["u_old"].decayed_risk


def test_decayed_risk_halves_after_one_half_life() -> None:
    config = EntityRiskConfig(half_life_seconds=1_000)
    signal = _signal(ts=0, risk=0.5, user="u1", src="h1", dst="h2")
    at_zero = compute_entity_risk_scores([signal], now=0, config=config)
    at_half_life = compute_entity_risk_scores([signal], now=1_000, config=config)
    user_zero = next(s for s in at_zero if s.entity == "u1")
    user_half = next(s for s in at_half_life if s.entity == "u1")
    # 1 - exp(-x) is not linear, so check the underlying decayed contribution
    # halved rather than the post-transform score halving exactly.
    assert user_half.decayed_risk < user_zero.decayed_risk
    assert user_half.decayed_risk == pytest.approx(1 - (1 - user_zero.decayed_risk) ** 0.5, abs=1e-9)


def test_higher_fanout_increases_score_at_equal_risk() -> None:
    low_fanout = [_signal(ts=0, risk=0.5, user="u_low", src="h1", dst="h2")]
    high_fanout = [
        _signal(ts=0, risk=0.5, user="u_high", src="h1", dst="h2"),
        _signal(ts=0, risk=0.5, user="u_high", src="h1", dst="h3"),
        _signal(ts=0, risk=0.5, user="u_high", src="h1", dst="h4"),
        _signal(ts=0, risk=0.5, user="u_high", src="h1", dst="h5"),
    ]
    scores = compute_entity_risk_scores(low_fanout + high_fanout, now=0)
    by_entity = {s.entity: s for s in scores if s.kind == "user"}
    assert by_entity["u_high"].fanout > by_entity["u_low"].fanout
    assert by_entity["u_high"].score > by_entity["u_low"].score


def test_fanout_counts_distinct_counterparts_across_roles() -> None:
    # host h1 is touched by two different users and also acts as a source
    # toward a third host — its fan-out should count all three counterparts.
    signals = [
        _signal(ts=0, risk=0.3, user="alice", src="h0", dst="h1"),
        _signal(ts=1, risk=0.3, user="bob", src="h0", dst="h1"),
        _signal(ts=2, risk=0.3, user="alice", src="h1", dst="h2"),
    ]
    scores = compute_entity_risk_scores(signals, now=2)
    h1 = next(s for s in scores if s.entity == "h1" and s.kind == "host")
    assert h1.fanout == 4  # h0, alice, bob, h2


def test_ranking_sorts_by_score_descending() -> None:
    signals = [
        _signal(ts=0, risk=0.1, user="low_risk_user", src="h1", dst="h2"),
        _signal(ts=0, risk=0.95, user="high_risk_user", src="h3", dst="h4"),
    ]
    scores = compute_entity_risk_scores(signals, now=0)
    ranks = [s.score for s in scores]
    assert ranks == sorted(ranks, reverse=True)
    # A single 2-hop alert ties its user and both hosts on score (identical
    # decayed_risk and fanout), so check the intended comparison directly
    # rather than assuming a specific entity wins the alphabetical tie-break.
    by_entity = {s.entity: s.score for s in scores}
    assert by_entity["high_risk_user"] > by_entity["low_risk_user"]


def test_top_k_truncates_results() -> None:
    signals = [
        _signal(ts=i, risk=0.5, user=f"u{i}", src=f"s{i}", dst=f"d{i}") for i in range(20)
    ]
    scores = compute_entity_risk_scores(signals, now=20, config=EntityRiskConfig(top_k=5))
    assert len(scores) == 5


def test_empty_signals_returns_empty_result() -> None:
    assert compute_entity_risk_scores([], now=0) == ()


def test_rejects_negative_now() -> None:
    with pytest.raises(ValueError):
        compute_entity_risk_scores([], now=-1)
