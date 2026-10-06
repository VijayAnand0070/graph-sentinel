"""Measured statistics of the real corpus, from which benign traffic is drawn.

Everything a generated event needs -- who authenticates, from where, to what,
with which auth and logon types, at what hour -- is sampled from what the real
corpus actually contains rather than from a hand-written model of it. Finding 4
recorded what happens otherwise: a generator encoding an intuition about attack
topology validated the detector against that intuition rather than against
reality.

Only benign events from the warm-up prefix are profiled, so the generated
traffic continues the same population the model's memory was warmed on.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import numpy as np

if TYPE_CHECKING:  # pragma: no cover - annotations only
    import polars as pl

SECONDS_PER_DAY = 86_400

#: One benign behaviour a user has actually exhibited: the tuple resampled
#: to produce a synthetic benign event for that user.
BenignTuple = tuple[int, int, int, int, int, int, int]
_TUPLE_COLUMNS = (
    "dst_user_id",
    "src_host_id",
    "dst_host_id",
    "auth_type_id",
    "logon_type_id",
    "orientation_id",
    "success",
)


@dataclass
class CorpusProfile:
    hour_weights: tuple[float, ...]
    user_profiles: dict[int, list[BenignTuple]]
    user_activity: dict[int, int]
    source_host_counts: dict[int, int]
    destination_host_counts: dict[int, int]
    users_by_source_host: dict[int, list[int]]
    user_destinations: dict[int, set[int]]
    events_per_second: float
    last_timestamp: int
    profiled_events: int
    _user_ids: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64), repr=False)
    _user_weights: np.ndarray = field(default_factory=lambda: np.zeros(0), repr=False)
    _dst_ids: np.ndarray = field(default_factory=lambda: np.zeros(0, dtype=np.int64), repr=False)
    _dst_weights: np.ndarray = field(default_factory=lambda: np.zeros(0), repr=False)

    def __post_init__(self) -> None:
        if len(self.hour_weights) != 24:
            raise ValueError("hour_weights must have 24 entries")
        users = sorted(self.user_profiles)
        self._user_ids = np.asarray(users, dtype=np.int64)
        weights = np.asarray([self.user_activity[u] for u in users], dtype=float)
        self._user_weights = weights / weights.sum() if weights.sum() else weights
        hosts = sorted(self.destination_host_counts)
        self._dst_ids = np.asarray(hosts, dtype=np.int64)
        dst = np.asarray([self.destination_host_counts[h] for h in hosts], dtype=float)
        self._dst_weights = dst / dst.sum() if dst.sum() else dst

    # ------------------------------------------------------------------ build
    @classmethod
    def measure(cls, frame: pl.DataFrame, *, max_users: int | None = None) -> CorpusProfile:
        """Profile a polars frame of feature records (benign rows only are used)."""
        import polars as pl

        benign = frame.filter(pl.col("label_redteam") == 0).sort("timestamp", "event_id")
        if benign.height == 0:
            raise ValueError("cannot profile a corpus with no benign events")

        timestamps = benign["timestamp"].to_numpy()
        hours = (timestamps % SECONDS_PER_DAY) // 3_600
        histogram = np.bincount(hours, minlength=24).astype(float)
        hour_weights = tuple(float(v) for v in histogram / histogram.max())

        span = int(timestamps[-1] - timestamps[0]) or 1
        events_per_second = benign.height / span

        activity = Counter(benign["src_user_id"].to_list())
        keep = {u for u, _ in activity.most_common(max_users)} if max_users else set(activity)
        keep.discard(0)  # id 0 is the unknown sentinel

        columns = {name: benign[name].to_list() for name in ("src_user_id", *_TUPLE_COLUMNS)}
        profiles: dict[int, list[BenignTuple]] = defaultdict(list)
        users_by_host: dict[int, set[int]] = defaultdict(set)
        user_destinations: dict[int, set[int]] = defaultdict(set)
        source_counts: Counter[int] = Counter()
        destination_counts: Counter[int] = Counter()
        for index, user in enumerate(columns["src_user_id"]):
            row = cast(BenignTuple, tuple(int(columns[name][index]) for name in _TUPLE_COLUMNS))
            src_host, dst_host = row[1], row[2]
            source_counts[src_host] += 1
            destination_counts[dst_host] += 1
            if user in keep:
                profiles[user].append(row)
                users_by_host[src_host].add(user)
                user_destinations[user].add(dst_host)
        source_counts.pop(0, None)
        destination_counts.pop(0, None)

        return cls(
            hour_weights=hour_weights,
            user_profiles=dict(profiles),
            user_activity={u: activity[u] for u in profiles},
            source_host_counts=dict(source_counts),
            destination_host_counts=dict(destination_counts),
            users_by_source_host={h: sorted(us) for h, us in users_by_host.items()},
            user_destinations=dict(user_destinations),
            events_per_second=events_per_second,
            last_timestamp=int(timestamps[-1]),
            profiled_events=benign.height,
        )

    # --------------------------------------------------------------- sampling
    def sample_user(self, rng: np.random.Generator) -> int:
        return int(rng.choice(self._user_ids, p=self._user_weights))

    def sample_behaviour(self, user: int, rng: np.random.Generator) -> BenignTuple:
        options = self.user_profiles[user]
        return options[int(rng.integers(len(options)))]

    def sample_destination(
        self, rng: np.random.Generator, *, exclude: Collection[int] = frozenset()
    ) -> int:
        """A destination host weighted by how often it is actually reached.

        Servers are targets; weighting by in-degree makes the attacker go where
        the value is, which is also where legitimate traffic goes.
        """
        for _ in range(64):
            host = int(rng.choice(self._dst_ids, p=self._dst_weights))
            if host not in exclude:
                return host
        # A heavy account may have reached most of the estate; fall back to
        # the explicit complement, still weighted, rather than giving up.
        mask = np.array([h not in exclude for h in self._dst_ids.tolist()])
        if not mask.any():
            raise RuntimeError("every destination host is excluded; nothing novel remains")
        weights = self._dst_weights[mask]
        return int(rng.choice(self._dst_ids[mask], p=weights / weights.sum()))

    def hour_weight(self, timestamp: int) -> float:
        return self.hour_weights[(timestamp % SECONDS_PER_DAY) // 3_600]

    def candidate_attacker_hosts(
        self, *, low_quantile: float = 0.50, high_quantile: float = 0.95
    ) -> list[int]:
        """Ordinary busy workstations: hosts with benign out-degree in the
        middle of the distribution, and at least one profiled user.

        Excludes the quiet tail (a host with three events has no benign
        history worth speaking of) and the extreme top (a domain controller
        as "compromised workstation" is a different scenario).
        """
        hosts = [h for h in self.source_host_counts if h in self.users_by_source_host]
        if not hosts:
            return []
        counts = np.asarray([self.source_host_counts[h] for h in hosts], dtype=float)
        low, high = np.quantile(counts, [low_quantile, high_quantile])
        return sorted(h for h, c in zip(hosts, counts, strict=False) if low <= c <= high)

    def summary(self) -> dict[str, object]:
        return {
            "profiled_events": self.profiled_events,
            "users": len(self.user_profiles),
            "source_hosts": len(self.source_host_counts),
            "destination_hosts": len(self.destination_host_counts),
            "events_per_second": round(self.events_per_second, 5),
            "events_per_day": round(self.events_per_second * SECONDS_PER_DAY, 1),
            "peak_hour": int(np.argmax(self.hour_weights)),
            "last_timestamp": self.last_timestamp,
        }
