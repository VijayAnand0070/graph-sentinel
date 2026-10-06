"""Bounded, time-respecting suspicious host-path ranking."""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from itertools import pairwise
from threading import RLock


@dataclass(frozen=True, slots=True)
class ScoredAuthEvent:
    event_id: int
    timestamp: int
    user_id: int
    source_host_id: int
    destination_host_id: int
    risk: float
    is_new_relationship: bool
    evidence_support: float = 0.0
    label_redteam: int = 0

    def __post_init__(self) -> None:
        if self.event_id < 0 or self.timestamp < 0:
            raise ValueError("event ID and timestamp must be non-negative")
        if not 0 <= self.risk <= 1 or not 0 <= self.evidence_support <= 1:
            raise ValueError("risk and evidence support must be in [0, 1]")
        if self.label_redteam not in {0, 1}:
            raise ValueError("label_redteam must be binary")


@dataclass(frozen=True, slots=True)
class SuspiciousPath:
    path_id: str
    event_ids: tuple[int, ...]
    host_ids: tuple[int, ...]
    user_ids: tuple[int, ...]
    timestamps: tuple[int, ...]
    score: float
    mean_edge_risk: float
    new_edge_ratio: float
    pivot_density: float
    evidence_support: float
    redteam_overlap: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PathRankerConfig:
    forward_window_seconds: int = 1_800
    max_hops: int = 5
    top_k: int = 20
    minimum_edge_risk: float = 0.5
    mean_edge_risk_weight: float = 0.55
    new_edge_ratio_weight: float = 0.20
    pivot_density_weight: float = 0.15
    evidence_support_weight: float = 0.10

    def __post_init__(self) -> None:
        if self.forward_window_seconds <= 0 or not 2 <= self.max_hops <= 10:
            raise ValueError("path window must be positive and max_hops must be in [2, 10]")
        if self.top_k <= 0:
            raise ValueError("top_k must be positive")
        if not 0 <= self.minimum_edge_risk <= 1:
            raise ValueError("minimum_edge_risk must be in [0, 1]")
        weight_sum = (
            self.mean_edge_risk_weight
            + self.new_edge_ratio_weight
            + self.pivot_density_weight
            + self.evidence_support_weight
        )
        if not math.isclose(weight_sum, 1.0, abs_tol=1e-9):
            raise ValueError("path score weights must sum to one")


class PathRanker:
    """Find paths where a newly reached host later acts as a source."""

    def __init__(self, config: PathRankerConfig | None = None) -> None:
        self.config = config or PathRankerConfig()

    def rank(self, events: list[ScoredAuthEvent]) -> list[SuspiciousPath]:
        if any(current.timestamp < previous.timestamp for previous, current in pairwise(events)):
            raise ValueError("path events must be chronological")
        eligible = [event for event in events if event.risk >= self.config.minimum_edge_risk]
        by_source: dict[int, list[ScoredAuthEvent]] = defaultdict(list)
        for event in eligible:
            by_source[event.source_host_id].append(event)
        candidates: list[tuple[ScoredAuthEvent, ...]] = []

        def extend(path: tuple[ScoredAuthEvent, ...]) -> None:
            if len(path) >= 2:
                candidates.append(path)
            if len(path) >= self.config.max_hops:
                return
            last = path[-1]
            visited_hosts = {path[0].source_host_id, *(edge.destination_host_id for edge in path)}
            for next_event in by_source.get(last.destination_host_id, ()):
                delta = next_event.timestamp - last.timestamp
                if delta <= 0 or delta > self.config.forward_window_seconds:
                    continue
                if next_event.destination_host_id in visited_hosts:
                    continue
                extend((*path, next_event))

        for event in eligible:
            extend((event,))
        unique: dict[tuple[int, ...], SuspiciousPath] = {}
        for edges in candidates:
            path = self._summarize(edges)
            unique[path.event_ids] = path
        return sorted(
            unique.values(), key=lambda path: (-path.score, path.timestamps, path.event_ids)
        )[: self.config.top_k]

    def _summarize(self, edges: tuple[ScoredAuthEvent, ...]) -> SuspiciousPath:
        edge_count = len(edges)
        mean_risk = sum(edge.risk for edge in edges) / edge_count
        new_ratio = sum(edge.is_new_relationship for edge in edges) / edge_count
        pivot_density = (edge_count - 1) / edge_count
        support = sum(edge.evidence_support for edge in edges) / edge_count
        score = (
            self.config.mean_edge_risk_weight * mean_risk
            + self.config.new_edge_ratio_weight * new_ratio
            + self.config.pivot_density_weight * pivot_density
            + self.config.evidence_support_weight * support
        )
        event_ids = tuple(edge.event_id for edge in edges)
        return SuspiciousPath(
            path_id="GS-P-" + "-".join(str(event_id) for event_id in event_ids),
            event_ids=event_ids,
            host_ids=(edges[0].source_host_id, *(edge.destination_host_id for edge in edges)),
            user_ids=tuple(edge.user_id for edge in edges),
            timestamps=tuple(edge.timestamp for edge in edges),
            score=score,
            mean_edge_risk=mean_risk,
            new_edge_ratio=new_ratio,
            pivot_density=pivot_density,
            evidence_support=support,
            redteam_overlap=any(edge.label_redteam for edge in edges),
        )


@dataclass(frozen=True, slots=True)
class StreamingPathPreview:
    state_version: int
    new_paths: tuple[SuspiciousPath, ...]
    next_history: tuple[ScoredAuthEvent, ...]
    next_known_paths: tuple[tuple[str, int], ...]


class StreamingPathTracker:
    """Transactional rolling path state spanning multiple scoring requests."""

    def __init__(self, ranker: PathRanker | None = None) -> None:
        self.ranker = ranker or PathRanker()
        self._history: tuple[ScoredAuthEvent, ...] = ()
        self._known_paths: dict[str, int] = {}
        self._state_version = 0
        self._lock = RLock()

    def preview(self, events: list[ScoredAuthEvent]) -> StreamingPathPreview:
        if not events:
            raise ValueError("streaming path preview cannot be empty")
        with self._lock:
            if self._history and events[0].timestamp <= self._history[-1].timestamp:
                raise ValueError(
                    "scoring requests must advance beyond the prior path timestamp; "
                    "combine equal timestamps in one batch"
                )
            combined = (*self._history, *events)
            horizon = self.ranker.config.forward_window_seconds * self.ranker.config.max_hops
            cutoff = events[-1].timestamp - horizon
            # What is carried forward is bounded by the horizon: a path can
            # only span forward_window x max_hops seconds, so nothing older
            # can still be extended by a future request.
            next_history = tuple(event for event in combined if event.timestamp > cutoff)
            # What is *ranked* is the whole request. A request that covers
            # more than the horizon -- a replay, a batched hour, a bulk
            # ingest -- still contains paths among its own events, and
            # ranking only its tail silently loses them. The search itself is
            # bounded by the same window per hop, so the cost is in the
            # eligible edges, not in the span.
            ranked = self.ranker.rank(self._ranking_window(combined))
            known_paths = {
                path_id: final_timestamp
                for path_id, final_timestamp in self._known_paths.items()
                if final_timestamp > cutoff
            }
            new_paths = tuple(path for path in ranked if path.path_id not in known_paths)
            known_paths.update({path.path_id: path.timestamps[-1] for path in ranked})
            return StreamingPathPreview(
                state_version=self._state_version,
                new_paths=new_paths,
                next_history=next_history,
                next_known_paths=tuple(sorted(known_paths.items())),
            )

    #: A pathological request -- one host reached by tens of thousands of
    #: high-risk edges -- would make the depth-first extension expensive. The
    #: search is then confined to the most recent slice, which is the
    #: behaviour this class had for every request before that limit.
    ranking_event_cap: int = 50_000

    def _ranking_window(self, combined: tuple[ScoredAuthEvent, ...]) -> list[ScoredAuthEvent]:
        eligible = sum(
            1 for event in combined if event.risk >= self.ranker.config.minimum_edge_risk
        )
        if eligible <= self.ranking_event_cap:
            return list(combined)
        return list(combined[-self.ranking_event_cap :])

    def commit(self, preview: StreamingPathPreview) -> int:
        with self._lock:
            if preview.state_version != self._state_version:
                raise RuntimeError("stale path preview cannot update rolling state")
            self._history = preview.next_history
            self._known_paths = dict(preview.next_known_paths)
            self._state_version += 1
            return self._state_version

    def reset(self) -> int:
        with self._lock:
            self._history = ()
            self._known_paths = {}
            self._state_version += 1
            return self._state_version
