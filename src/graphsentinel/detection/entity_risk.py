"""Composite, time-decayed risk scoring per entity (user or host).

Individual alerts describe single events; an analyst triaging a queue needs to
know which *entities* deserve attention right now, not just which events did.
This blends each entity's recent alert history — time-decayed, so a risky
event from a week ago doesn't outrank one from five minutes ago — with how
many distinct other entities it has touched recently, a fan-out signal that is
informative independent of any single alert's risk score (a user quietly
touching one new host looks very different from one touching eight).

Deliberately decoupled from the API's ``AlertRecord``: this module takes plain
``AlertSignal`` tuples so the scoring algorithm is testable and reusable
without pulling in FastAPI/Pydantic, matching how ``path_ranker.ScoredAuthEvent``
keeps the path-ranking algorithm independent of the serving layer.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Literal

EntityKind = Literal["user", "host"]


@dataclass(frozen=True, slots=True)
class AlertSignal:
    """The minimal fields entity-risk scoring needs from one alert."""

    timestamp: int
    risk: float
    user: str
    source_host: str
    destination_host: str

    def __post_init__(self) -> None:
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        if not 0 <= self.risk <= 1:
            raise ValueError("risk must be in [0, 1]")
        if not self.user or not self.source_host or not self.destination_host:
            raise ValueError("user, source_host, and destination_host must be non-empty")


@dataclass(frozen=True, slots=True)
class EntityRiskConfig:
    half_life_seconds: float = 3_600.0
    fanout_saturation: float = 8.0
    risk_weight: float = 0.7
    fanout_weight: float = 0.3
    top_k: int = 50

    def __post_init__(self) -> None:
        if self.half_life_seconds <= 0:
            raise ValueError("half_life_seconds must be positive")
        if self.fanout_saturation <= 0:
            raise ValueError("fanout_saturation must be positive")
        if self.risk_weight < 0 or self.fanout_weight < 0:
            raise ValueError("weights must be non-negative")
        if not math.isclose(self.risk_weight + self.fanout_weight, 1.0, abs_tol=1e-9):
            raise ValueError("risk_weight and fanout_weight must sum to one")
        if self.top_k <= 0:
            raise ValueError("top_k must be positive")


@dataclass(frozen=True, slots=True)
class EntityRiskScore:
    entity: str
    kind: EntityKind
    score: float
    decayed_risk: float
    fanout: int
    alert_count: int
    last_seen: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DEFAULT_ENTITY_RISK_CONFIG = EntityRiskConfig()


def compute_entity_risk_scores(
    signals: Sequence[AlertSignal],
    *,
    now: int,
    config: EntityRiskConfig = DEFAULT_ENTITY_RISK_CONFIG,
) -> tuple[EntityRiskScore, ...]:
    """Rank entities by time-decayed alert risk blended with recent fan-out.

    ``decayed_risk`` uses ``1 - exp(-Σ risk_i · 0.5^(Δt_i / half_life))``: a
    saturating accumulation (bounded in [0, 1) regardless of how many alerts
    pile up) that rewards both a single very risky event and many moderate
    ones, the same style of bounded transform the causal feature engine uses
    for novelty and rarity scores elsewhere in this codebase.
    """

    if now < 0:
        raise ValueError("now must be non-negative")

    history: dict[tuple[str, EntityKind], list[tuple[int, float]]] = defaultdict(list)
    counterparts: dict[tuple[str, EntityKind], set[tuple[str, EntityKind]]] = defaultdict(set)

    for signal in signals:
        user_key: tuple[str, EntityKind] = (signal.user, "user")
        src_key: tuple[str, EntityKind] = (signal.source_host, "host")
        dst_key: tuple[str, EntityKind] = (signal.destination_host, "host")
        for key in (user_key, src_key, dst_key):
            history[key].append((signal.timestamp, signal.risk))
        counterparts[user_key].update((src_key, dst_key))
        counterparts[src_key].update((user_key, dst_key))
        counterparts[dst_key].update((user_key, src_key))

    scores: list[EntityRiskScore] = []
    for (entity, kind), events in history.items():
        decayed_sum = sum(
            risk * (0.5 ** (max(0, now - timestamp) / config.half_life_seconds))
            for timestamp, risk in events
        )
        decayed_risk = 1 - math.exp(-decayed_sum)
        fanout = len(counterparts[(entity, kind)])
        fanout_component = min(1.0, fanout / config.fanout_saturation)
        composite = config.risk_weight * decayed_risk + config.fanout_weight * fanout_component
        scores.append(
            EntityRiskScore(
                entity=entity,
                kind=kind,
                score=min(1.0, max(0.0, composite)),
                decayed_risk=decayed_risk,
                fanout=fanout,
                alert_count=len(events),
                last_seen=max(timestamp for timestamp, _ in events),
            )
        )

    scores.sort(key=lambda s: (-s.score, -s.last_seen, s.entity))
    return tuple(scores[: config.top_k])
