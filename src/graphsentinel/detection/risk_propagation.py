"""Propagates confirmed-alert risk outward across the authentication graph.

The entity-risk leaderboard (``entity_risk.py``) ranks entities that ALREADY
have alert history. Risk propagation answers a different, earlier question:
which entities are graph-adjacent to a confirmed high-risk entity but have
not triggered an alert of their own yet? This is the "guilt by association"
signal an analyst reasons about implicitly when staring at a graph and
thinking "that host talks to the compromised one, I should check it too" —
this module makes it explicit and rankable, ahead of the entity's own alert.

Implemented as a damped random-walk diffusion (personalized-PageRank-style
power iteration) rather than a naive BFS spread or a hand-tuned per-hop decay
constant, because it: (a) decays with distance automatically, honoring edge
weight and path multiplicity rather than raw hop count alone, (b) accumulates
when a node is reachable from a seed via several paths, and (c) is a
convergent, deterministic fixed point rather than a heuristic.

Deliberately unnormalized: unlike textbook PageRank, the personalization
vector holds each seed's own risk value directly (not divided by the sum
across seeds), so a single isolated seed's own steady-state mass tracks its
input risk rather than being diluted by graph size. The raw accumulated mass
is then squashed through the same saturating ``1 - exp(-x)`` transform
``entity_risk.py`` uses for decayed risk, so scores stay bounded in [0, 1)
and the two modules read consistently on the same dashboard.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from math import exp
from typing import Literal

EntityKind = Literal["user", "host"]
EntityKey = tuple[str, EntityKind]


@dataclass(frozen=True, slots=True)
class PropagationEdge:
    """A directed, weighted hop in the authentication graph."""

    source: str
    source_kind: EntityKind
    destination: str
    destination_kind: EntityKind
    weight: float = 1.0

    def __post_init__(self) -> None:
        if not self.source or not self.destination:
            raise ValueError("source and destination must be non-empty")
        if self.weight <= 0:
            raise ValueError("weight must be positive")


@dataclass(frozen=True, slots=True)
class SeedRisk:
    """A confirmed high-risk entity that injects risk mass into its neighbors."""

    entity: str
    kind: EntityKind
    risk: float

    def __post_init__(self) -> None:
        if not self.entity:
            raise ValueError("entity must be non-empty")
        if not 0 <= self.risk <= 1:
            raise ValueError("risk must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class PropagationConfig:
    damping: float = 0.85
    max_iterations: int = 100
    tolerance: float = 1e-6
    top_k: int = 50

    def __post_init__(self) -> None:
        if not 0 < self.damping < 1:
            raise ValueError("damping must be in (0, 1)")
        if self.max_iterations <= 0:
            raise ValueError("max_iterations must be positive")
        if self.tolerance <= 0:
            raise ValueError("tolerance must be positive")
        if self.top_k <= 0:
            raise ValueError("top_k must be positive")


@dataclass(frozen=True, slots=True)
class PropagatedRisk:
    entity: str
    kind: EntityKind
    propagated_risk: float
    seed_risk: float
    hop_distance: int | None
    is_seed: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DEFAULT_PROPAGATION_CONFIG = PropagationConfig()


def propagate_risk(
    edges: Sequence[PropagationEdge],
    seeds: Sequence[SeedRisk],
    *,
    config: PropagationConfig = DEFAULT_PROPAGATION_CONFIG,
) -> tuple[PropagatedRisk, ...]:
    """Diffuse seed risk across the graph via damped power iteration.

    ``mass_{t+1}(v) = damping * sum_u (mass_t(u) * w(u->v) / outweight(u))
                       + (1 - damping) * seed_risk(v)``

    Every iteration re-injects each seed's own risk at full strength (the
    restart term) while damping-weighted mass flows one hop along outbound
    edges. The graph is directed and NOT symmetrized — an attacker's
    outbound authentication hops matter more than what merely points at it.
    """

    if not seeds:
        return ()

    seed_mass: dict[EntityKey, float] = {}
    for seed in seeds:
        key: EntityKey = (seed.entity, seed.kind)
        seed_mass[key] = max(seed_mass.get(key, 0.0), seed.risk)

    nodes: set[EntityKey] = set(seed_mass)
    adjacency: dict[EntityKey, list[tuple[EntityKey, float]]] = defaultdict(list)
    out_weight: dict[EntityKey, float] = defaultdict(float)
    for edge in edges:
        src: EntityKey = (edge.source, edge.source_kind)
        dst: EntityKey = (edge.destination, edge.destination_kind)
        nodes.add(src)
        nodes.add(dst)
        adjacency[src].append((dst, edge.weight))
        out_weight[src] += edge.weight

    mass: dict[EntityKey, float] = {node: seed_mass.get(node, 0.0) for node in nodes}

    for _ in range(config.max_iterations):
        next_mass: dict[EntityKey, float] = {
            node: (1 - config.damping) * seed_mass.get(node, 0.0) for node in nodes
        }
        for node in nodes:
            current = mass[node]
            if current <= 0:
                continue
            weight_sum = out_weight.get(node, 0.0)
            if weight_sum <= 0:
                continue
            for neighbor, weight in adjacency[node]:
                next_mass[neighbor] += config.damping * current * (weight / weight_sum)

        delta = sum(abs(next_mass[node] - mass[node]) for node in nodes)
        mass = next_mass
        if delta < config.tolerance:
            break

    hop_distances = _bfs_hop_distances(adjacency, seed_mass.keys())

    results = [
        PropagatedRisk(
            entity=node[0],
            kind=node[1],
            propagated_risk=min(1.0, max(0.0, 1 - exp(-mass[node]))),
            seed_risk=seed_mass.get(node, 0.0),
            hop_distance=hop_distances.get(node),
            is_seed=node in seed_mass,
        )
        for node in nodes
    ]
    results.sort(key=lambda r: (-r.propagated_risk, r.entity))
    return tuple(results[: config.top_k])


def _bfs_hop_distances(
    adjacency: Mapping[EntityKey, list[tuple[EntityKey, float]]],
    seed_keys: Iterable[EntityKey],
) -> dict[EntityKey, int]:
    distances: dict[EntityKey, int] = {}
    queue: deque[EntityKey] = deque()
    for key in seed_keys:
        distances[key] = 0
        queue.append(key)
    while queue:
        current = queue.popleft()
        for neighbor, _ in adjacency.get(current, ()):
            if neighbor in distances:
                continue
            distances[neighbor] = distances[current] + 1
            queue.append(neighbor)
    return distances
