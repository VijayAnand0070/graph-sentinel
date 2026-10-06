"""Reconstructs a per-incident kill-chain DAG from a set of alert-driven hops.

The existing incident view groups alerts into a cluster (who's involved) but
doesn't answer the question an analyst actually draws on a whiteboard: "how
did they get from A to D, in order?" This module turns an unordered alert
set into an explicit directed acyclic graph, layered by causal/chronological
depth, plus a single distinguished "primary path" — the longest chronological
chain of hops, the one sequence that most resembles an actual kill chain
rather than everything the incident's clustering happened to sweep in.

Nodes are layered via longest-path-from-any-root layering: a node's layer is
the length of the longest chronological path reaching it from a node with no
incoming edges. This is computed in a single forward sweep over hops sorted
by timestamp rather than a general topological sort, because the timestamp
order already IS a valid topological order for a causal chain (a hop's actor
must have been reachable at or before the hop's own timestamp) — replaying
hops chronologically and relaxing each target's layer against its actor's
current layer converges in one pass, no repeated relaxation needed.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

EntityKind = Literal["user", "host"]
EntityKey = tuple[str, EntityKind]


@dataclass(frozen=True, slots=True)
class ChainHop:
    """One alert-driven hop: ``actor`` reaching ``target`` at ``timestamp``."""

    alert_id: str
    timestamp: int
    actor: str
    actor_kind: EntityKind
    target: str
    target_kind: EntityKind
    risk: float

    def __post_init__(self) -> None:
        if not self.alert_id:
            raise ValueError("alert_id must be non-empty")
        if not self.actor or not self.target:
            raise ValueError("actor and target must be non-empty")
        if not 0 <= self.risk <= 1:
            raise ValueError("risk must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class ChainNode:
    entity: str
    kind: EntityKind
    layer: int
    first_seen: int
    max_risk: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ChainEdge:
    alert_id: str
    source: str
    source_kind: EntityKind
    target: str
    target_kind: EntityKind
    timestamp: int
    risk: float
    on_primary_path: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class KillChainGraph:
    nodes: tuple[ChainNode, ...]
    edges: tuple[ChainEdge, ...]
    primary_path: tuple[str, ...]
    depth: int

    def to_dict(self) -> dict[str, object]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "primary_path": list(self.primary_path),
            "depth": self.depth,
        }


def reconstruct_kill_chain(hops: Sequence[ChainHop]) -> KillChainGraph:
    if not hops:
        return KillChainGraph(nodes=(), edges=(), primary_path=(), depth=0)

    ordered = sorted(hops, key=lambda hop: (hop.timestamp, hop.alert_id))

    first_seen: dict[EntityKey, int] = {}
    max_risk: dict[EntityKey, float] = {}
    all_nodes: set[EntityKey] = set()

    for hop in ordered:
        actor_key: EntityKey = (hop.actor, hop.actor_kind)
        target_key: EntityKey = (hop.target, hop.target_kind)
        all_nodes.add(actor_key)
        all_nodes.add(target_key)
        first_seen[actor_key] = min(first_seen.get(actor_key, hop.timestamp), hop.timestamp)
        first_seen[target_key] = min(first_seen.get(target_key, hop.timestamp), hop.timestamp)
        max_risk[actor_key] = max(max_risk.get(actor_key, 0.0), hop.risk)
        max_risk[target_key] = max(max_risk.get(target_key, 0.0), hop.risk)

    layer: dict[EntityKey, int] = dict.fromkeys(all_nodes, 0)
    for hop in ordered:
        actor_key = (hop.actor, hop.actor_kind)
        target_key = (hop.target, hop.target_kind)
        candidate_layer = layer[actor_key] + 1
        if candidate_layer > layer[target_key]:
            layer[target_key] = candidate_layer

    # Longest chronological chain by hop count, tie-broken by cumulative risk.
    best_chain: dict[EntityKey, tuple[int, float, tuple[ChainHop, ...]]] = {}
    for hop in ordered:
        actor_key = (hop.actor, hop.actor_kind)
        target_key = (hop.target, hop.target_kind)
        incoming_length, incoming_risk, incoming_path = best_chain.get(actor_key, (0, 0.0, ()))
        candidate = (incoming_length + 1, incoming_risk + hop.risk, (*incoming_path, hop))
        current = best_chain.get(target_key)
        if current is None or candidate[:2] > current[:2]:
            best_chain[target_key] = candidate

    winning_path: tuple[ChainHop, ...] = ()
    if best_chain:
        _, _, winning_path = max(best_chain.values(), key=lambda entry: entry[:2])

    primary_alert_ids = {hop.alert_id for hop in winning_path}
    primary_path_entities: tuple[str, ...] = ()
    if winning_path:
        head = winning_path[0]
        primary_path_entities = (f"{head.actor_kind}:{head.actor}",)
        for hop in winning_path:
            primary_path_entities += (f"{hop.target_kind}:{hop.target}",)

    nodes = tuple(
        ChainNode(
            entity=entity,
            kind=kind,
            layer=layer[(entity, kind)],
            first_seen=first_seen[(entity, kind)],
            max_risk=max_risk[(entity, kind)],
        )
        for entity, kind in sorted(all_nodes, key=lambda key: (layer[key], first_seen[key], key[0]))
    )
    edges = tuple(
        ChainEdge(
            alert_id=hop.alert_id,
            source=hop.actor,
            source_kind=hop.actor_kind,
            target=hop.target,
            target_kind=hop.target_kind,
            timestamp=hop.timestamp,
            risk=hop.risk,
            on_primary_path=hop.alert_id in primary_alert_ids,
        )
        for hop in ordered
    )
    depth = max(layer.values(), default=-1) + 1
    return KillChainGraph(nodes=nodes, edges=edges, primary_path=primary_path_entities, depth=depth)
