"""The vectorised feature engine must equal the streaming engine, event by event."""

from __future__ import annotations

import numpy as np
import pytest

from graphsentinel.features.causal import MODEL_FEATURE_NAMES, CausalFeatureEngine
from graphsentinel.features.vectorized import EXTRA_FEATURE_NAMES, QueryEvents, VectorizedFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent

_CATEGORICAL = {"auth_type_id", "logon_type_id", "orientation_id"}


def _stream(seed: int, n: int, *, users: int, hosts: int, span: int) -> dict[str, np.ndarray]:
    rng = np.random.default_rng(seed)
    t = np.sort(rng.integers(0, span, n)) + 1_000_000
    return {
        "t": t,
        "user": rng.integers(0, users, n),
        "src": rng.integers(0, hosts, n),
        "dst": rng.integers(0, hosts, n),
        "logon": rng.integers(0, 4, n),
        "success": (rng.random(n) > 0.15).astype(np.int64),
    }


def _reference(stream: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    engine = CausalFeatureEngine()
    events = [
        NormalizedAuthEvent(
            event_id=i, timestamp=int(stream["t"][i]), src_user_id=int(stream["user"][i]),
            dst_user_id=int(stream["user"][i]), src_host_id=int(stream["src"][i]),
            dst_host_id=int(stream["dst"][i]), auth_type_id=0, logon_type_id=int(stream["logon"][i]),
            orientation_id=0, success=int(stream["success"][i]), label_redteam=0,
            day=int(stream["t"][i]) // 86_400, hour=(int(stream["t"][i]) % 86_400) // 3_600,
        )
        for i in range(len(stream["t"]))
    ]
    records = list(engine.transform(events))
    return {
        name: np.array([getattr(r, name) for r in records], dtype=np.float64)
        for name in (*MODEL_FEATURE_NAMES, *EXTRA_FEATURE_NAMES)
        if name not in _CATEGORICAL
    }


def _vectorized(stream: dict[str, np.ndarray], cuts: list[int]) -> dict[str, np.ndarray]:
    """Run in chunks split at the given timestamps (each a chunk's first time)."""
    engine = VectorizedFeatureEngine()
    bounds = [int(stream["t"][0])] + cuts + [int(stream["t"][-1]) + 1]
    parts: list[dict[str, np.ndarray]] = []
    for lo, hi in zip(bounds[:-1], bounds[1:], strict=True):
        mask = (stream["t"] >= lo) & (stream["t"] < hi)
        if mask.any():
            parts.append(engine.chunk({k: v[mask] for k, v in stream.items()}))
    return {k: np.concatenate([p[k] for p in parts]).astype(np.float64) for k in parts[0]}


@pytest.mark.parametrize(
    ("seed", "users", "hosts", "span", "cuts"),
    [
        (1, 6, 9, 4_000, []),  # dense: many ties, every window busy
        (2, 30, 40, 200_000, [60_000, 60_001, 150_000]),  # windows crossing chunk edges
        (3, 12, 15, 400_000, [90_000, 190_000, 290_000]),  # 24 h windows across chunks
    ],
)
def test_equals_streaming_engine(seed: int, users: int, hosts: int, span: int, cuts: list[int]) -> None:
    stream = _stream(seed, 3_000, users=users, hosts=hosts, span=span)
    cuts = [1_000_000 + c for c in cuts]
    expected = _reference(stream)
    got = _vectorized(stream, cuts)
    for name, values in expected.items():
        np.testing.assert_allclose(got[name], values, rtol=0, atol=1e-9, err_msg=name)


def _brute_extra(stream: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    t, u, s, d = stream["t"], stream["user"], stream["src"], stream["dst"]
    n = len(t)
    us = np.zeros(n)
    sd = np.zeros(n)
    su = np.zeros(n)
    for i in range(n):
        prior = t < t[i]
        us[i] = float(np.any(prior & (u == u[i]) & (s == s[i])))
        sd[i] = float(np.any(prior & (s == s[i]) & (d == d[i])))
        window = prior & (t > t[i] - 3_600) & (s == s[i])
        su[i] = len(set(u[window].tolist()))
    return {"user_src_seen_before": us, "src_dst_seen_before": sd, "src_host_unique_users_1h": su}


def test_host_centric_features() -> None:
    """Checked against a brute-force definition as well as the streaming engine."""
    stream = _stream(7, 1_500, users=10, hosts=8, span=30_000)
    got = _vectorized(stream, [1_000_000 + 12_000])
    streaming = _reference(stream)
    for name, values in _brute_extra(stream).items():
        np.testing.assert_allclose(got[name], values, atol=0, err_msg=name)
        np.testing.assert_allclose(streaming[name], values, atol=0, err_msg=f"streaming {name}")


def test_counterfactual_query_matches_a_real_event() -> None:
    """Querying an event that did happen, with its own destination, reproduces
    its features; swapping the destination changes only destination-dependent ones."""
    stream = _stream(11, 2_000, users=8, hosts=12, span=50_000)
    engine = VectorizedFeatureEngine()
    engine.begin_chunk(stream)
    q = QueryEvents(t=stream["t"], user=stream["user"], src=stream["src"], dst=stream["dst"],
                    logon=stream["logon"], success=stream["success"])
    real = engine.query(q)
    swapped = engine.query(QueryEvents(t=q.t, user=q.user, src=q.src, dst=(q.dst + 1) % 12,
                                       logon=q.logon, success=q.success))
    engine.end_chunk()
    reference = _reference(stream)
    for name, values in reference.items():
        np.testing.assert_allclose(real[name].astype(float), values, atol=1e-9, err_msg=name)
    for name in ("user_auth_rate_5m", "user_unique_dst_1h", "delta_user_log", "src_host_unique_dst_1h"):
        np.testing.assert_allclose(swapped[name], real[name], err_msg=name)


def test_rejects_overlapping_chunks() -> None:
    stream = _stream(5, 200, users=4, hosts=4, span=1_000)
    engine = VectorizedFeatureEngine()
    engine.chunk(stream)
    with pytest.raises(ValueError, match="after the previous chunk"):
        engine.chunk(stream)
