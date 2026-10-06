"""Nearest-neighbor search over TGN node embeddings.

The TGN's per-node memory vector (see ``models.tgn.TGNState.memory``) is a
learned summary of an entity's recent temporal behavior — it is the same
signal the model uses internally to score risk. This module answers a
question the risk scores alone cannot: "find entities that behave like this
one," independent of whether either has triggered an alert yet. That is a
real SOC workflow — an analyst who has one confirmed-bad host wants to know
which other hosts look behaviorally similar, not just which are graph-
adjacent (that's ``risk_propagation``'s job).

Deliberately brute-force cosine similarity rather than an ANN index (FAISS,
HNSW): at LANL-bounded scale (thousands of entities, not millions) a full
scan against every other node is sub-millisecond, and skipping an ANN
dependency keeps this module import-light and exact rather than approximate.
Revisit only if entity count grows by orders of magnitude.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

EntityKind = Literal["user", "host"]


@dataclass(frozen=True, slots=True)
class EntityEmbedding:
    entity: str
    kind: EntityKind
    vector: tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.entity:
            raise ValueError("entity must be non-empty")
        if not self.vector:
            raise ValueError("vector must be non-empty")


@dataclass(frozen=True, slots=True)
class SimilarityMatch:
    entity: str
    kind: EntityKind
    similarity: float
    magnitude: float


def find_similar_entities(
    query: EntityEmbedding,
    candidates: Sequence[EntityEmbedding],
    *,
    top_k: int = 10,
    minimum_similarity: float = 0.0,
) -> tuple[SimilarityMatch, ...]:
    """Rank candidates by cosine similarity to ``query``, excluding itself.

    A zero-magnitude vector (an entity the model has never updated, e.g. one
    seen only at initialization) has no defined direction, so both the query
    and any candidate with zero magnitude are excluded rather than producing
    an undefined 0/0 similarity.
    """

    if top_k <= 0:
        raise ValueError("top_k must be positive")
    if not -1 <= minimum_similarity <= 1:
        raise ValueError("minimum_similarity must be in [-1, 1]")

    query_norm = math.sqrt(sum(v * v for v in query.vector))
    if query_norm == 0:
        return ()

    matches: list[SimilarityMatch] = []
    for candidate in candidates:
        if candidate.entity == query.entity and candidate.kind == query.kind:
            continue
        if len(candidate.vector) != len(query.vector):
            raise ValueError("all embeddings must share the same dimensionality")
        candidate_norm = math.sqrt(sum(v * v for v in candidate.vector))
        if candidate_norm == 0:
            continue
        dot = sum(a * b for a, b in zip(query.vector, candidate.vector))
        similarity = max(-1.0, min(1.0, dot / (query_norm * candidate_norm)))
        if similarity >= minimum_similarity:
            matches.append(
                SimilarityMatch(
                    entity=candidate.entity,
                    kind=candidate.kind,
                    similarity=similarity,
                    magnitude=candidate_norm,
                )
            )

    matches.sort(key=lambda m: (-m.similarity, m.entity))
    return tuple(matches[:top_k])
