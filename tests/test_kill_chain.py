import pytest

from graphsentinel.detection.kill_chain import ChainHop, reconstruct_kill_chain


def _hop(alert_id: str, ts: int, actor: str, actor_kind: str, target: str, target_kind: str, risk: float = 0.8) -> ChainHop:
    return ChainHop(
        alert_id=alert_id, timestamp=ts, actor=actor, actor_kind=actor_kind,
        target=target, target_kind=target_kind, risk=risk,
    )


def test_chain_hop_rejects_empty_alert_id() -> None:
    with pytest.raises(ValueError):
        ChainHop(alert_id="", timestamp=0, actor="a", actor_kind="user", target="b", target_kind="host", risk=0.5)


def test_chain_hop_rejects_out_of_range_risk() -> None:
    with pytest.raises(ValueError):
        _hop("A1", 0, "a", "user", "b", "host", risk=1.5)


def test_empty_hops_returns_empty_graph() -> None:
    result = reconstruct_kill_chain([])
    assert result.nodes == ()
    assert result.edges == ()
    assert result.primary_path == ()
    assert result.depth == 0


def test_single_hop_produces_two_layered_nodes() -> None:
    result = reconstruct_kill_chain([_hop("A1", 100, "alice", "user", "host1", "host")])
    assert len(result.nodes) == 2
    by_entity = {n.entity: n for n in result.nodes}
    assert by_entity["alice"].layer == 0
    assert by_entity["host1"].layer == 1
    assert result.depth == 2
    assert result.edges[0].on_primary_path is True


def test_three_hop_chain_layers_increase_monotonically() -> None:
    hops = [
        _hop("A1", 100, "alice", "user", "host1", "host"),
        _hop("A2", 200, "host1", "host", "host2", "host"),
        _hop("A3", 300, "host2", "host", "host3", "host"),
    ]
    result = reconstruct_kill_chain(hops)
    by_entity = {n.entity: n.layer for n in result.nodes}
    assert by_entity["alice"] == 0
    assert by_entity["host1"] == 1
    assert by_entity["host2"] == 2
    assert by_entity["host3"] == 3
    assert result.depth == 4
    assert result.primary_path == ("user:alice", "host:host1", "host:host2", "host:host3")
    assert all(e.on_primary_path for e in result.edges)


def test_branching_picks_higher_risk_as_primary_when_lengths_tie() -> None:
    hops = [
        _hop("A1", 100, "alice", "user", "low", "host", risk=0.3),
        _hop("A2", 100, "alice", "user", "high", "host", risk=0.9),
    ]
    result = reconstruct_kill_chain(hops)
    assert result.primary_path == ("user:alice", "host:high")
    on_primary = {e.alert_id: e.on_primary_path for e in result.edges}
    assert on_primary["A2"] is True
    assert on_primary["A1"] is False


def test_diamond_convergence_layer_is_max_of_incoming_plus_one() -> None:
    hops = [
        _hop("A1", 100, "alice", "user", "b", "host"),
        _hop("A2", 100, "alice", "user", "c", "host"),
        _hop("A3", 200, "b", "host", "d", "host"),
        _hop("A4", 200, "c", "host", "d", "host"),
    ]
    result = reconstruct_kill_chain(hops)
    by_entity = {n.entity: n.layer for n in result.nodes}
    assert by_entity["d"] == 2
    assert result.depth == 3


def test_longer_chain_wins_over_shorter_higher_risk_chain() -> None:
    hops = [
        # short, very risky branch: alice -> x (1 hop)
        _hop("A1", 100, "alice", "user", "x", "host", risk=1.0),
        # long branch: alice -> p -> q -> r (3 hops, lower risk each)
        _hop("A2", 100, "alice", "user", "p", "host", risk=0.4),
        _hop("A3", 200, "p", "host", "q", "host", risk=0.4),
        _hop("A4", 300, "q", "host", "r", "host", risk=0.4),
    ]
    result = reconstruct_kill_chain(hops)
    assert result.primary_path == ("user:alice", "host:p", "host:q", "host:r")


def test_out_of_order_input_produces_same_result_as_sorted_input() -> None:
    sorted_hops = [
        _hop("A1", 100, "alice", "user", "host1", "host"),
        _hop("A2", 200, "host1", "host", "host2", "host"),
    ]
    shuffled = [sorted_hops[1], sorted_hops[0]]
    assert reconstruct_kill_chain(sorted_hops) == reconstruct_kill_chain(shuffled)


def test_first_seen_reflects_earliest_timestamp() -> None:
    hops = [
        _hop("A1", 500, "alice", "user", "host1", "host"),
        _hop("A2", 100, "someone_else", "user", "alice", "user"),
    ]
    result = reconstruct_kill_chain(hops)
    alice = next(n for n in result.nodes if n.entity == "alice")
    assert alice.first_seen == 100


def test_max_risk_aggregates_across_hops() -> None:
    hops = [
        _hop("A1", 100, "alice", "user", "host1", "host", risk=0.3),
        _hop("A2", 200, "alice", "user", "host2", "host", risk=0.9),
    ]
    result = reconstruct_kill_chain(hops)
    alice = next(n for n in result.nodes if n.entity == "alice")
    assert alice.max_risk == pytest.approx(0.9)
