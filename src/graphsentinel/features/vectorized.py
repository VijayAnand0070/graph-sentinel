"""Exact, vectorised computation of the causal features for a whole chunk of events.

:class:`~graphsentinel.features.causal.CausalFeatureEngine` scores one event at a
time in Python, about 9,000 events per second: a full-rate LANL day (7-8 M
authentications) takes a quarter of an hour and a fortnight most of a day. This
computes the same features for a chunk of events at once with sorts and binary
searches and carries the cumulative state from chunk to chunk, so a fortnight
takes minutes. Backfilling a new estate from its historical logs and building
full-rate research corpora both need that.

The semantics are the engine's, exactly:

* every feature of an event reads only events with a strictly earlier
  timestamp, so events sharing a timestamp are scored against the same state;
* windows are open intervals, ``(t - w, t)``;
* a pair is "new" on its first occurrence in stream order.

``tests/test_vectorized_features.py`` checks equality with the engine event by
event, across chunk boundaries and on streams dense with ties.

Two things the engine cannot do. :meth:`VectorizedFeatureEngine.query` answers
*counterfactual* questions -- the features an event would have had with another
source or destination host, against the same history -- which a self-supervised
model needs for its negative examples. And three host-centric features the
engine does not compute (``EXTRA_FEATURE_NAMES``) describe one host using many
accounts, the shape of credential hopping from a beachhead.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import numpy as np

from graphsentinel.features.causal import MODEL_FEATURE_NAMES

#: Radix for (key, time) composites. Times are rebased to the first event, so
#: this bounds the span of one engine's history (136 years), not the epoch.
_RADIX = np.int64(1 << 32)
MAX_WINDOW_SECONDS = 86_400
#: Every window except the 24 h distinct-destination one is at most an hour.
_SHORT_CONTEXT_SECONDS = 3_600
_SHIFT = np.int64(32)

#: Host-centric features computed here in addition to the engine's 27.
EXTRA_FEATURE_NAMES = (
    "user_src_seen_before",
    "src_dst_seen_before",
    "src_host_unique_users_1h",
)

_EVENT_FIELDS = ("t", "user", "src", "dst", "logon", "success")


def _as_int64(values: np.ndarray) -> np.ndarray:
    return np.ascontiguousarray(values, dtype=np.int64)


def _pair(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """One int64 key for an (a, b) pair of non-negative ids below 2**31."""
    return (a << _SHIFT) | b


def _combined(key: np.ndarray, t: np.ndarray) -> np.ndarray:
    return key * _RADIX + t


class _Timeline:
    """Occurrences of keys in time: counts and sums over ``(t - w, t)`` or ``(-inf, t)``.

    Keys must be non-negative and below 2**31 and times non-negative, so a
    (key, time) composite fits an int64 and orders by key, then time.
    """

    def __init__(self, key: np.ndarray, t: np.ndarray, values: np.ndarray | None = None) -> None:
        combined = _combined(key, t)
        order = np.argsort(combined, kind="stable")
        self._c = combined[order]
        self._sum = (
            None
            if values is None
            else np.concatenate(([0], np.cumsum(values[order], dtype=np.int64)))
        )

    def _bounds(self, key: np.ndarray, t: np.ndarray, window: int | None) -> tuple[np.ndarray, np.ndarray]:
        hi = np.searchsorted(self._c, _combined(key, t), "left")
        if window is None:
            lo = np.searchsorted(self._c, key * _RADIX, "left")
        else:
            # t - window may be negative; the composite then falls into the
            # previous key's range above every time that key can hold, so the
            # search still lands on this key's first entry.
            lo = np.searchsorted(self._c, _combined(key, t - window), "right")
        return lo, hi

    def count(self, key: np.ndarray, t: np.ndarray, window: int | None = None) -> np.ndarray:
        lo, hi = self._bounds(key, t, window)
        return hi - lo

    def total(self, key: np.ndarray, t: np.ndarray, window: int | None = None) -> np.ndarray:
        if self._sum is None:
            raise ValueError("this timeline was built without values")
        lo, hi = self._bounds(key, t, window)
        return self._sum[hi] - self._sum[lo]

    def last_before(self, key: np.ndarray, t: np.ndarray) -> np.ndarray:
        """Time of the key's latest occurrence strictly before ``t``, else -1."""
        if len(self._c) == 0:
            return np.full(len(key), -1, dtype=np.int64)
        idx = np.searchsorted(self._c, _combined(key, t), "left") - 1
        prev = self._c[np.clip(idx, 0, None)]
        base = key * _RADIX
        valid = (idx >= 0) & (prev >= base)
        return np.where(valid, prev - base, -1)


class _DistinctWindow:
    """How many distinct values a key had in ``(t - w, t)``.

    Each (key, value) occurrence at time s covers the query times (s, s + w).
    Merging the occurrences of one (key, value) into disjoint runs makes the
    distinct count at t the number of the key's runs that cover t:
    ``#(start < t) - #(end <= t)``.
    """

    def __init__(self, key: np.ndarray, value: np.ndarray, t: np.ndarray, window: int) -> None:
        pair = _pair(key, value)
        order = np.lexsort((t, pair))
        pair_s, t_s = pair[order], t[order]
        if len(pair_s):
            keep = np.ones(len(pair_s), dtype=bool)
            keep[1:] = (pair_s[1:] != pair_s[:-1]) | (t_s[1:] != t_s[:-1])
            pair_s, t_s = pair_s[keep], t_s[keep]
        new_run = np.ones(len(pair_s), dtype=bool)
        if len(pair_s):
            new_run[1:] = (pair_s[1:] != pair_s[:-1]) | (t_s[1:] >= t_s[:-1] + window)
        run_starts = np.flatnonzero(new_run)
        run_ends = np.concatenate((run_starts[1:] - 1, [len(t_s) - 1])) if len(run_starts) else run_starts
        run_key = pair_s[run_starts] >> _SHIFT
        self._starts = np.sort(_combined(run_key, t_s[run_starts]))
        self._ends = np.sort(_combined(run_key, t_s[run_ends] + window))

    def count(self, key: np.ndarray, t: np.ndarray) -> np.ndarray:
        query = _combined(key, t)
        floor = key * _RADIX
        started = np.searchsorted(self._starts, query, "left") - np.searchsorted(self._starts, floor, "left")
        ended = np.searchsorted(self._ends, query, "right") - np.searchsorted(self._ends, floor, "left")
        return started - ended


class _SortedCounts:
    """A sorted key set with per-key counts and last times (the cumulative registry)."""

    def __init__(self) -> None:
        self.keys = np.empty(0, dtype=np.int64)
        self.count = np.empty(0, dtype=np.int64)
        self.last = np.empty(0, dtype=np.int64)

    def lookup(self, keys: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        idx = np.searchsorted(self.keys, keys)
        found = idx < len(self.keys)
        found[found] = self.keys[idx[found]] == keys[found]
        return np.where(found, idx, 0), found

    def counts_of(self, keys: np.ndarray) -> np.ndarray:
        idx, found = self.lookup(keys)
        return np.where(found, self.count[idx] if len(self.count) else 0, 0)

    def last_of(self, keys: np.ndarray) -> np.ndarray:
        idx, found = self.lookup(keys)
        return np.where(found, self.last[idx] if len(self.last) else -1, -1)

    def merge(self, keys: np.ndarray, t: np.ndarray) -> None:
        """Fold one chunk's occurrences in (keys need not be unique)."""
        if not len(keys):
            return
        uniq, inverse, counts = np.unique(keys, return_inverse=True, return_counts=True)
        last = np.full(len(uniq), -1, dtype=np.int64)
        np.maximum.at(last, inverse, t)
        all_keys = np.concatenate((self.keys, uniq))
        all_count = np.concatenate((self.count, counts.astype(np.int64)))
        all_last = np.concatenate((self.last, last))
        merged, inv = np.unique(all_keys, return_inverse=True)
        count = np.zeros(len(merged), dtype=np.int64)
        np.add.at(count, inv, all_count)
        last_merged = np.full(len(merged), -1, dtype=np.int64)
        np.maximum.at(last_merged, inv, all_last)
        self.keys, self.count, self.last = merged, count, last_merged


class _Grown:
    """An int64 array indexed by entity id that grows on demand."""

    def __init__(self, fill: int) -> None:
        self.fill = fill
        self.values = np.full(1024, fill, dtype=np.int64)

    def ensure(self, max_id: int) -> None:
        if max_id >= len(self.values):
            size = max(max_id + 1, 2 * len(self.values))
            grown = np.full(size, self.fill, dtype=np.int64)
            grown[: len(self.values)] = self.values
            self.values = grown

    def get(self, ids: np.ndarray) -> np.ndarray:
        if not len(ids):
            return np.empty(0, dtype=np.int64)
        self.ensure(int(ids.max()))
        return self.values[ids]


@dataclass(frozen=True)
class QueryEvents:
    """Events to featurise (real or counterfactual). Absolute timestamps."""

    t: np.ndarray
    user: np.ndarray
    src: np.ndarray
    dst: np.ndarray
    logon: np.ndarray
    success: np.ndarray


def _events(mapping: Mapping[str, np.ndarray]) -> dict[str, np.ndarray]:
    return {name: _as_int64(mapping[name]) for name in _EVENT_FIELDS}


class VectorizedFeatureEngine:
    """Chunked, exact feature computation with state carried between chunks.

    Protocol per chunk (chronological, each chunk later than the last)::

        engine.begin_chunk(events)        # arrays: t, user, src, dst, logon, success
        features = engine.query(QueryEvents(...))   # any number of queries
        engine.end_chunk()                # fold the chunk into the history

    :meth:`chunk` is the one-call form for real events.
    """

    def __init__(self) -> None:
        self._origin: int | None = None
        self._last_timestamp: int | None = None
        # cumulative registries (events before the current chunk)
        self._pairs = _SortedCounts()  # (user, dst): count, last
        self._src_dst = _SortedCounts()  # (src, dst): seen
        self._user_src = _SortedCounts()  # (user, src): seen
        self._user_logon = _SortedCounts()  # (user, logon): count
        self._user_last = _Grown(-1)
        self._user_total = _Grown(0)
        self._user_degree = _Grown(0)
        self._user_kinds = _Grown(0)
        self._src_degree = _Grown(0)
        self._dst_degree = _Grown(0)
        # Earlier chunks' tail, for windows reaching back before the chunk: the
        # last hour of everything, and the last 24 h of (t, user, dst) for the
        # one 24 h window. Keeping 24 h of every column doubled peak memory.
        self._context: dict[str, np.ndarray] | None = None
        self._context_long: dict[str, np.ndarray] | None = None
        self._chunk: dict[str, np.ndarray] | None = None
        self._structures: dict[str, object] = {}
        self._window_arrays: tuple[dict[str, np.ndarray], dict[str, np.ndarray]] = ({}, {})

    # ------------------------------------------------------------------ chunk lifecycle
    def chunk(self, events: Mapping[str, np.ndarray]) -> dict[str, np.ndarray]:
        """Features for one chunk of real events, then fold it in."""
        self.begin_chunk(events)
        chunk = self._chunk
        assert chunk is not None
        out = self.query(
            QueryEvents(
                t=chunk["t_abs"], user=chunk["user"], src=chunk["src"], dst=chunk["dst"],
                logon=chunk["logon"], success=chunk["success"],
            )
        )
        self.end_chunk()
        return out

    def begin_chunk(self, events: Mapping[str, np.ndarray]) -> None:
        if self._chunk is not None:
            raise RuntimeError("end_chunk() the previous chunk first")
        ev = _events(events)
        t_abs = ev["t"]
        if not len(t_abs):
            raise ValueError("a chunk cannot be empty")
        if np.any(np.diff(t_abs) < 0):
            raise ValueError("events must be in non-decreasing timestamp order")
        if self._last_timestamp is not None and t_abs[0] <= self._last_timestamp:
            raise ValueError("a chunk must start after the previous chunk's last timestamp")
        if self._origin is None:
            self._origin = int(t_abs[0]) - MAX_WINDOW_SECONDS
        t = t_abs - self._origin
        if int(t.max()) + MAX_WINDOW_SECONDS >= int(_RADIX):
            raise ValueError("history span exceeds the time radix")
        for name in ("user", "src", "dst", "logon"):
            if len(ev[name]) and (ev[name].min() < 0 or ev[name].max() >= (1 << 31)):
                raise ValueError(f"{name} ids must be in [0, 2**31)")
        user, src, dst, logon, success = ev["user"], ev["src"], ev["dst"], ev["logon"], ev["success"]
        pair = _pair(user, dst)

        # a pair is new on its first occurrence in stream order, if the history never had it
        _idx, in_history = self._pairs.lookup(pair)
        is_new = np.zeros(len(t), dtype=np.int64)
        _uniq, first = np.unique(pair, return_index=True)
        first_unseen = first[~in_history[first]]
        is_new[first_unseen] = 1

        chunk = {
            "t_abs": t_abs, "t": t, "user": user, "src": src, "dst": dst, "logon": logon,
            "success": success, "pair": pair, "is_new": is_new,
        }
        # window history: the tail of earlier chunks, then this chunk
        short_keys = ("t", "user", "src", "dst", "success", "pair", "is_new")
        long_keys = ("t", "user", "dst")
        if self._context is not None and self._context_long is not None:
            window = {k: np.concatenate((self._context[k], chunk[k])) for k in short_keys}
            window_long = {k: np.concatenate((self._context_long[k], chunk[k])) for k in long_keys}
        else:
            window = {k: chunk[k] for k in short_keys}
            window_long = {k: chunk[k] for k in long_keys}
        self._chunk = chunk
        self._build(chunk, window, window_long, first_unseen)

    def end_chunk(self) -> None:
        chunk = self._chunk
        if chunk is None:
            raise RuntimeError("no chunk in progress")
        user, src, dst, logon, t = chunk["user"], chunk["src"], chunk["dst"], chunk["logon"], chunk["t"]
        # degrees grow by the pairs first seen in this chunk
        new_pairs = chunk["is_new"].astype(bool)
        _add_counts(self._user_degree, user[new_pairs])
        _add_counts(self._dst_degree, dst[new_pairs])
        sd = _pair(src, dst)
        _idx, sd_known = self._src_dst.lookup(sd)
        _u, sd_first = np.unique(sd, return_index=True)
        sd_new_first = sd_first[~sd_known[sd_first]]
        _add_counts(self._src_degree, src[sd_new_first])
        ul = _pair(user, logon)
        _idx, ul_known = self._user_logon.lookup(ul)
        _u, ul_first = np.unique(ul, return_index=True)
        ul_new_first = ul_first[~ul_known[ul_first]]
        _add_counts(self._user_kinds, user[ul_new_first])
        # per-user totals and last times
        _add_counts(self._user_total, user)
        self._user_last.ensure(int(user.max()))
        np.maximum.at(self._user_last.values, user, t)
        # registries
        self._pairs.merge(chunk["pair"], t)
        self._src_dst.merge(sd, t)
        self._user_src.merge(_pair(user, src), t)
        self._user_logon.merge(ul, t)
        # keep the tails the next chunk's windows reach back into
        window, window_long = self._window_arrays
        keep = window["t"] >= int(t[-1]) - _SHORT_CONTEXT_SECONDS
        self._context = {k: v[keep] for k, v in window.items()}
        keep_long = window_long["t"] >= int(t[-1]) - MAX_WINDOW_SECONDS
        self._context_long = {k: v[keep_long] for k, v in window_long.items()}
        self._last_timestamp = int(chunk["t_abs"][-1])
        self._chunk = None
        self._structures = {}
        self._window_arrays = ({}, {})

    # ------------------------------------------------------------------ indexes
    def _build(
        self,
        chunk: dict[str, np.ndarray],
        window: dict[str, np.ndarray],
        window_long: dict[str, np.ndarray],
        first_unseen: np.ndarray,
    ) -> None:
        user, src, dst, t = chunk["user"], chunk["src"], chunk["dst"], chunk["t"]
        s: dict[str, object] = {}
        # cumulative, within the chunk
        s["user_chunk"] = _Timeline(user, t)
        uniq_pairs = np.unique(chunk["pair"])
        s["pair_codes"] = uniq_pairs
        s["pair_chunk"] = _Timeline(np.searchsorted(uniq_pairs, chunk["pair"]), t)
        s["new_pair_by_user"] = _Timeline(user[first_unseen], t[first_unseen])
        s["new_pair_by_dst"] = _Timeline(dst[first_unseen], t[first_unseen])
        sd = _pair(src, dst)
        _idx, sd_known = self._src_dst.lookup(sd)
        _u, sd_first = np.unique(sd, return_index=True)
        sd_new = sd_first[~sd_known[sd_first]]
        s["new_sd_by_src"] = _Timeline(src[sd_new], t[sd_new])
        uniq_sd = np.unique(sd)
        s["sd_codes"] = uniq_sd
        s["sd_chunk"] = _Timeline(np.searchsorted(uniq_sd, sd), t)
        us = _pair(user, src)
        uniq_us = np.unique(us)
        s["us_codes"] = uniq_us
        s["us_chunk"] = _Timeline(np.searchsorted(uniq_us, us), t)
        ul = _pair(user, chunk["logon"])
        uniq_ul = np.unique(ul)
        s["ul_codes"] = uniq_ul
        s["ul_chunk"] = _Timeline(np.searchsorted(uniq_ul, ul), t)
        _idx, ul_known = self._user_logon.lookup(ul)
        _u, ul_first = np.unique(ul, return_index=True)
        ul_new = ul_first[~ul_known[ul_first]]
        s["new_ul_by_user"] = _Timeline(user[ul_new], t[ul_new])
        # windows over the last 24 h plus the chunk
        wt, wu, ws, wd = window["t"], window["user"], window["src"], window["dst"]
        uniq_wp = np.unique(window["pair"])
        s["wpair_codes"] = uniq_wp
        s["pair_window"] = _Timeline(np.searchsorted(uniq_wp, window["pair"]), wt)
        s["user_window"] = _Timeline(wu, wt)
        s["user_fail"] = _Timeline(wu, wt, 1 - window["success"])
        s["user_new"] = _Timeline(wu, wt, window["is_new"])
        s["user_dst_5m"] = _DistinctWindow(wu, wd, wt, 300)
        s["user_dst_1h"] = _DistinctWindow(wu, wd, wt, 3_600)
        s["user_dst_24h"] = _DistinctWindow(window_long["user"], window_long["dst"], window_long["t"], 86_400)
        s["src_dst_1h"] = _DistinctWindow(ws, wd, wt, 3_600)
        s["dst_user_1h"] = _DistinctWindow(wd, wu, wt, 3_600)
        s["src_user_1h"] = _DistinctWindow(ws, wu, wt, 3_600)
        self._structures = s
        self._window_arrays = (window, window_long)

    # ------------------------------------------------------------------ features
    def query(self, q: QueryEvents) -> dict[str, np.ndarray]:
        """Features for arbitrary events of the current chunk's time span, read
        against the history strictly before each event's timestamp."""
        if self._chunk is None or self._origin is None:
            raise RuntimeError("begin_chunk() first")
        s = self._structures
        t = _as_int64(q.t) - self._origin
        user, src, dst = _as_int64(q.user), _as_int64(q.src), _as_int64(q.dst)
        logon, success = _as_int64(q.logon), _as_int64(q.success)
        hour = ((t + self._origin) % 86_400) // 3_600

        # the account
        user_chunk: _Timeline = s["user_chunk"]  # type: ignore[assignment]
        user_total = self._user_total.get(user) + user_chunk.count(user, t)
        user_last = np.maximum(self._user_last.get(user), user_chunk.last_before(user, t))
        user_seen = user_total > 0

        # the account-destination pair
        pair = _pair(user, dst)
        pair_code = _codes(s["pair_codes"], pair)  # type: ignore[arg-type]
        pair_chunk: _Timeline = s["pair_chunk"]  # type: ignore[assignment]
        pair_total = self._pairs.counts_of(pair) + pair_chunk.count(pair_code, t)
        pair_last = np.maximum(self._pairs.last_of(pair), pair_chunk.last_before(pair_code, t))
        pair_seen = pair_total > 0
        wpair_code = _codes(s["wpair_codes"], pair)  # type: ignore[arg-type]

        user_window: _Timeline = s["user_window"]  # type: ignore[assignment]
        user_fail: _Timeline = s["user_fail"]  # type: ignore[assignment]
        user_new: _Timeline = s["user_new"]  # type: ignore[assignment]
        fail_n = user_fail.count(user, t, 900)
        fails = user_fail.total(user, t, 900)
        new_n = user_new.count(user, t, 3_600)
        new_s = user_new.total(user, t, 3_600)

        user_degree = self._user_degree.get(user) + s["new_pair_by_user"].count(user, t)  # type: ignore[attr-defined]
        src_degree = self._src_degree.get(src) + s["new_sd_by_src"].count(src, t)  # type: ignore[attr-defined]
        dst_degree = self._dst_degree.get(dst) + s["new_pair_by_dst"].count(dst, t)  # type: ignore[attr-defined]

        ul = _pair(user, logon)
        ul_code = _codes(s["ul_codes"], ul)  # type: ignore[arg-type]
        category = self._user_logon.counts_of(ul) + s["ul_chunk"].count(ul_code, t)  # type: ignore[attr-defined]
        kinds = self._user_kinds.get(user) + s["new_ul_by_user"].count(user, t)  # type: ignore[attr-defined]
        smoothed = (category + 1) / (user_total + kinds + 1)

        sd = _pair(src, dst)
        sd_seen = (self._src_dst.counts_of(sd) + s["sd_chunk"].count(_codes(s["sd_codes"], sd), t)) > 0  # type: ignore[attr-defined,arg-type]
        us = _pair(user, src)
        us_seen = (self._user_src.counts_of(us) + s["us_chunk"].count(_codes(s["us_codes"], us), t)) > 0  # type: ignore[attr-defined,arg-type]

        angle = 2 * np.pi * hour / 24
        with np.errstate(divide="ignore", invalid="ignore"):
            out: dict[str, np.ndarray] = {
                "success": success,
                "hour_sin": np.sin(angle),
                "hour_cos": np.cos(angle),
                "delta_user_log": np.where(user_seen, np.log1p(np.maximum(t - user_last, 0)), 0.0),
                "delta_pair_log": np.where(pair_seen, np.log1p(np.maximum(t - pair_last, 0)), 0.0),
                "user_seen_before": user_seen.astype(np.int64),
                "pair_seen_before": pair_seen.astype(np.int64),
                "is_new_pair": (~pair_seen).astype(np.int64),
                "pair_frequency_1h": s["pair_window"].count(wpair_code, t, 3_600),  # type: ignore[attr-defined]
                "pair_rarity": 1.0 / np.sqrt(pair_total + 1),
                "user_unique_dst_5m": s["user_dst_5m"].count(user, t),  # type: ignore[attr-defined]
                "user_unique_dst_1h": s["user_dst_1h"].count(user, t),  # type: ignore[attr-defined]
                "user_unique_dst_24h": s["user_dst_24h"].count(user, t),  # type: ignore[attr-defined]
                "user_auth_rate_5m": user_window.count(user, t, 300),
                "user_failure_rate_15m": np.where(fail_n > 0, fails / np.maximum(fail_n, 1), 0.0),
                "failures_before_success_15m": np.where(success == 1, fails, 0),
                "user_new_dst_ratio_1h": np.where(new_n > 0, new_s / np.maximum(new_n, 1), 0.0),
                "src_host_unique_dst_1h": s["src_dst_1h"].count(src, t),  # type: ignore[attr-defined]
                "dst_inbound_users_1h": s["dst_user_1h"].count(dst, t),  # type: ignore[attr-defined]
                "destination_novelty": 1.0 / (dst_degree + 1),
                "user_historical_degree": user_degree,
                "src_host_historical_degree": src_degree,
                "dst_historical_degree": dst_degree,
                "rare_logon_score": -np.log(smoothed),
                "user_src_seen_before": us_seen.astype(np.int64),
                "src_dst_seen_before": sd_seen.astype(np.int64),
                "src_host_unique_users_1h": s["src_user_1h"].count(src, t),  # type: ignore[attr-defined]
            }
        return out


def _codes(sorted_keys: np.ndarray, keys: np.ndarray) -> np.ndarray:
    """Dense code of each key in a sorted key set; absent keys get a code no
    occurrence carries (``len(sorted_keys)``)."""
    idx = np.searchsorted(sorted_keys, keys)
    present = idx < len(sorted_keys)
    present[present] = sorted_keys[idx[present]] == keys[present]
    return np.where(present, idx, len(sorted_keys)).astype(np.int64)


def _add_counts(target: _Grown, ids: np.ndarray) -> None:
    if not len(ids):
        return
    target.ensure(int(ids.max()))
    np.add.at(target.values, ids, 1)


#: The engine's 27 model features plus the three host-centric ones, in model order.
ALL_FEATURE_NAMES = tuple(MODEL_FEATURE_NAMES) + EXTRA_FEATURE_NAMES

__all__ = [
    "ALL_FEATURE_NAMES",
    "EXTRA_FEATURE_NAMES",
    "MAX_WINDOW_SECONDS",
    "QueryEvents",
    "VectorizedFeatureEngine",
]
