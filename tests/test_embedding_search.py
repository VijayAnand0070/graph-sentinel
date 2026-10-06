import pytest

from graphsentinel.detection.embedding_search import (
    EntityEmbedding,
    find_similar_entities,
)


def _emb(entity: str, kind: str, vector: tuple[float, ...]) -> EntityEmbedding:
    return EntityEmbedding(entity=entity, kind=kind, vector=vector)


def test_entity_embedding_rejects_empty_vector() -> None:
    with pytest.raises(ValueError):
        EntityEmbedding(entity="a", kind="host", vector=())


def test_entity_embedding_rejects_empty_name() -> None:
    with pytest.raises(ValueError):
        EntityEmbedding(entity="", kind="host", vector=(1.0,))


def test_rejects_non_positive_top_k() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    with pytest.raises(ValueError):
        find_similar_entities(query, [], top_k=0)


def test_rejects_minimum_similarity_out_of_range() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    with pytest.raises(ValueError):
        find_similar_entities(query, [], minimum_similarity=1.5)


def test_zero_query_vector_returns_empty() -> None:
    query = _emb("a", "host", (0.0, 0.0))
    candidates = [_emb("b", "host", (1.0, 0.0))]
    assert find_similar_entities(query, candidates) == ()


def test_zero_candidate_vector_is_skipped() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("b", "host", (0.0, 0.0)), _emb("c", "host", (1.0, 0.0))]
    results = find_similar_entities(query, candidates)
    assert [r.entity for r in results] == ["c"]


def test_identical_direction_yields_similarity_one() -> None:
    query = _emb("a", "host", (2.0, 0.0))
    candidates = [_emb("b", "host", (5.0, 0.0))]
    results = find_similar_entities(query, candidates)
    assert results[0].similarity == pytest.approx(1.0)


def test_orthogonal_vectors_yield_similarity_zero() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("b", "host", (0.0, 1.0))]
    results = find_similar_entities(query, candidates)
    assert results[0].similarity == pytest.approx(0.0)


def test_opposite_vectors_yield_similarity_negative_one() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("b", "host", (-1.0, 0.0))]
    # The default minimum_similarity=0.0 would filter this out, since -1 < 0;
    # widen it here to observe the raw computed similarity value.
    results = find_similar_entities(query, candidates, minimum_similarity=-1.0)
    assert results[0].similarity == pytest.approx(-1.0)


def test_query_excluded_from_its_own_results_even_if_present() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("a", "host", (1.0, 0.0)), _emb("b", "host", (0.9, 0.1))]
    results = find_similar_entities(query, candidates)
    assert all(r.entity != "a" for r in results)


def test_same_name_different_kind_is_not_excluded() -> None:
    # A user and a host can share a display name; only (entity, kind) together identify the query.
    query = _emb("shared", "user", (1.0, 0.0))
    candidates = [_emb("shared", "host", (1.0, 0.0))]
    results = find_similar_entities(query, candidates)
    assert len(results) == 1
    assert results[0].kind == "host"


def test_ranks_by_descending_similarity() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [
        _emb("close", "host", (0.99, 0.01)),
        _emb("far", "host", (0.1, 0.99)),
        _emb("medium", "host", (0.7, 0.3)),
    ]
    results = find_similar_entities(query, candidates)
    assert [r.entity for r in results] == ["close", "medium", "far"]


def test_top_k_truncates_results() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb(f"h{i}", "host", (1.0, float(i) * 0.01)) for i in range(20)]
    results = find_similar_entities(query, candidates, top_k=5)
    assert len(results) == 5


def test_minimum_similarity_filters_low_matches() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("close", "host", (1.0, 0.0)), _emb("far", "host", (0.0, 1.0))]
    results = find_similar_entities(query, candidates, minimum_similarity=0.5)
    assert [r.entity for r in results] == ["close"]


def test_mismatched_dimensionality_raises() -> None:
    query = _emb("a", "host", (1.0, 0.0))
    candidates = [_emb("b", "host", (1.0, 0.0, 0.0))]
    with pytest.raises(ValueError):
        find_similar_entities(query, candidates)
