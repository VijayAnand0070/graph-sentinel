import pytest

from graphsentinel.detection.risk_propagation import (
    PropagationConfig,
    PropagationEdge,
    SeedRisk,
    propagate_risk,
)


def _edge(src: str, src_kind: str, dst: str, dst_kind: str, weight: float = 1.0) -> PropagationEdge:
    return PropagationEdge(
        source=src, source_kind=src_kind, destination=dst, destination_kind=dst_kind, weight=weight
    )


def test_propagation_edge_rejects_non_positive_weight() -> None:
    with pytest.raises(ValueError):
        PropagationEdge(source="a", source_kind="host", destination="b", destination_kind="host", weight=0)


def test_seed_risk_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        SeedRisk(entity="a", kind="host", risk=1.5)


def test_config_rejects_damping_out_of_range() -> None:
    with pytest.raises(ValueError):
        PropagationConfig(damping=1.0)
    with pytest.raises(ValueError):
        PropagationConfig(damping=0.0)


def test_empty_seeds_returns_empty() -> None:
    assert propagate_risk([], []) == ()


def test_no_edges_returns_only_seeds_at_their_own_risk() -> None:
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk([], seeds)
    assert len(results) == 1
    assert results[0].entity == "attacker"
    assert results[0].is_seed is True
    assert results[0].hop_distance == 0


def test_seed_outranks_its_neighbor() -> None:
    edges = [_edge("attacker", "user", "host1", "host")]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk(edges, seeds)
    by_entity = {r.entity: r for r in results}
    assert by_entity["attacker"].propagated_risk > by_entity["host1"].propagated_risk


def test_neighbor_receives_elevated_risk_above_zero() -> None:
    edges = [_edge("attacker", "user", "host1", "host")]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk(edges, seeds)
    host1 = next(r for r in results if r.entity == "host1")
    assert host1.propagated_risk > 0
    assert host1.hop_distance == 1
    assert host1.is_seed is False


def test_risk_decays_with_hop_distance() -> None:
    edges = [
        _edge("attacker", "user", "host1", "host"),
        _edge("host1", "host", "host2", "host"),
    ]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk(edges, seeds)
    by_entity = {r.entity: r for r in results}
    assert by_entity["host1"].propagated_risk > by_entity["host2"].propagated_risk
    assert by_entity["host1"].hop_distance == 1
    assert by_entity["host2"].hop_distance == 2


def test_unreachable_node_gets_zero_risk_and_no_hop_distance() -> None:
    edges = [
        _edge("attacker", "user", "host1", "host"),
        # host2 only reachable by an edge that points AWAY from the seed component
        _edge("host9", "host", "host2", "host"),
    ]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk(edges, seeds)
    host2 = next(r for r in results if r.entity == "host2")
    assert host2.propagated_risk == 0
    assert host2.hop_distance is None


def test_multiple_paths_accumulate_more_risk_than_one() -> None:
    single_path = [_edge("seedA", "user", "shared", "host")]
    double_path = [
        _edge("seedA", "user", "shared", "host"),
        _edge("seedB", "user", "shared", "host"),
    ]
    seeds_single = [SeedRisk(entity="seedA", kind="user", risk=0.8)]
    seeds_double = [
        SeedRisk(entity="seedA", kind="user", risk=0.8),
        SeedRisk(entity="seedB", kind="user", risk=0.8),
    ]
    single_shared = next(r for r in propagate_risk(single_path, seeds_single) if r.entity == "shared")
    double_shared = next(r for r in propagate_risk(double_path, seeds_double) if r.entity == "shared")
    assert double_shared.propagated_risk > single_shared.propagated_risk


def test_higher_seed_risk_propagates_more() -> None:
    edges = [_edge("attacker", "user", "host1", "host")]
    low_seed = [SeedRisk(entity="attacker", kind="user", risk=0.3)]
    high_seed = [SeedRisk(entity="attacker", kind="user", risk=0.95)]
    low_host1 = next(r for r in propagate_risk(edges, low_seed) if r.entity == "host1")
    high_host1 = next(r for r in propagate_risk(edges, high_seed) if r.entity == "host1")
    assert high_host1.propagated_risk > low_host1.propagated_risk


def test_scores_bounded_in_unit_interval() -> None:
    edges = [
        _edge("a", "user", "b", "host"),
        _edge("b", "host", "c", "host"),
        _edge("c", "host", "a", "user"),
    ]
    seeds = [SeedRisk(entity="a", kind="user", risk=1.0), SeedRisk(entity="b", kind="host", risk=1.0)]
    results = propagate_risk(edges, seeds)
    assert all(0 <= r.propagated_risk <= 1 for r in results)


def test_top_k_truncates_results() -> None:
    edges = [_edge("attacker", "user", f"host{i}", "host") for i in range(20)]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    results = propagate_risk(edges, seeds, config=PropagationConfig(top_k=5))
    assert len(results) == 5


def test_deterministic_across_runs() -> None:
    edges = [
        _edge("attacker", "user", "host1", "host"),
        _edge("host1", "host", "host2", "host"),
        _edge("host2", "host", "host3", "host"),
    ]
    seeds = [SeedRisk(entity="attacker", kind="user", risk=0.9)]
    first = propagate_risk(edges, seeds)
    second = propagate_risk(edges, seeds)
    assert first == second
