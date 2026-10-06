"""Leakage-safe rolling features for chronological authentication events."""

from __future__ import annotations

import copy
import math
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import asdict, dataclass
from itertools import groupby
from typing import Any

from graphsentinel.ingestion.auth import NormalizedAuthEvent


@dataclass(frozen=True, slots=True)
class FeatureRecord:
    """One normalized event plus features computed strictly from timestamps before it."""

    event_id: int
    timestamp: int
    day: int
    src_user_id: int
    dst_user_id: int
    src_host_id: int
    dst_host_id: int
    auth_type_id: int
    logon_type_id: int
    orientation_id: int
    success: int
    label_redteam: int
    hour_sin: float
    hour_cos: float
    delta_user_log: float
    delta_pair_log: float
    user_seen_before: int
    pair_seen_before: int
    is_new_pair: int
    pair_frequency_1h: int
    pair_rarity: float
    user_unique_dst_5m: int
    user_unique_dst_1h: int
    user_unique_dst_24h: int
    user_auth_rate_5m: int
    user_failure_rate_15m: float
    failures_before_success_15m: int
    user_new_dst_ratio_1h: float
    src_host_unique_dst_1h: int
    dst_inbound_users_1h: int
    destination_novelty: float
    user_historical_degree: int
    src_host_historical_degree: int
    dst_historical_degree: int
    rare_logon_score: float
    #: Host-centric features (feature version 2). Defaults keep records built
    #: from version-1 feature files readable; the engine always computes them.
    #: Has this account authenticated from this source host before?
    user_src_seen_before: int = 0
    #: Has this source host reached this destination before?
    src_dst_seen_before: int = 0
    #: Distinct accounts the source host used in the last hour: one host using
    #: many accounts is the shape of credential hopping from a beachhead.
    src_host_unique_users_1h: int = 0

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


MODEL_FEATURE_NAMES = (
    "success",
    "auth_type_id",
    "logon_type_id",
    "orientation_id",
    "hour_sin",
    "hour_cos",
    "delta_user_log",
    "delta_pair_log",
    "user_seen_before",
    "pair_seen_before",
    "is_new_pair",
    "pair_frequency_1h",
    "pair_rarity",
    "user_unique_dst_5m",
    "user_unique_dst_1h",
    "user_unique_dst_24h",
    "user_auth_rate_5m",
    "user_failure_rate_15m",
    "failures_before_success_15m",
    "user_new_dst_ratio_1h",
    "src_host_unique_dst_1h",
    "dst_inbound_users_1h",
    "destination_novelty",
    "user_historical_degree",
    "src_host_historical_degree",
    "dst_historical_degree",
    "rare_logon_score",
)


@dataclass(frozen=True, slots=True)
class EngineCheckpoint:
    """What :meth:`CausalFeatureEngine.checkpoint` captured; opaque to callers."""

    last_processed_timestamp: int | None
    entries: list[tuple[dict[object, object], object, bool, object]]


class _RollingDistinct:
    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._events: dict[int, deque[tuple[int, int]]] = defaultdict(deque)
        self._counts: dict[int, Counter[int]] = defaultdict(Counter)

    def count_before(self, key: int, timestamp: int) -> int:
        self._prune(key, timestamp)
        return len(self._counts[key])

    def add(self, key: int, timestamp: int, value: int) -> None:
        self._events[key].append((timestamp, value))
        self._counts[key][value] += 1

    def _prune(self, key: int, timestamp: int) -> None:
        events = self._events[key]
        counts = self._counts[key]
        cutoff = timestamp - self.window_seconds
        while events and events[0][0] <= cutoff:
            _, value = events.popleft()
            counts[value] -= 1
            if counts[value] == 0:
                del counts[value]

    def snapshot(self) -> dict[str, object]:
        return {
            "window_seconds": self.window_seconds,
            "events": {k: list(v) for k, v in self._events.items() if v},
            "counts": {k: dict(v) for k, v in self._counts.items() if v},
        }

    def restore(self, state: dict[str, Any]) -> None:
        self.window_seconds = int(state["window_seconds"])
        self._events = defaultdict(deque)
        for key, values in state["events"].items():
            self._events[int(key)] = deque(tuple(v) for v in values)
        self._counts = defaultdict(Counter)
        for key, values in state["counts"].items():
            self._counts[int(key)] = Counter({int(k): int(v) for k, v in values.items()})


class _RollingBinary:
    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._events: dict[int, deque[tuple[int, int]]] = defaultdict(deque)
        self._sums: Counter[int] = Counter()

    def stats_before(self, key: int, timestamp: int) -> tuple[int, int]:
        self._prune(key, timestamp)
        return len(self._events[key]), self._sums[key]

    def add(self, key: int, timestamp: int, value: int) -> None:
        self._events[key].append((timestamp, value))
        self._sums[key] += value

    def _prune(self, key: int, timestamp: int) -> None:
        events = self._events[key]
        cutoff = timestamp - self.window_seconds
        while events and events[0][0] <= cutoff:
            _, value = events.popleft()
            self._sums[key] -= value

    def snapshot(self) -> dict[str, object]:
        return {
            "window_seconds": self.window_seconds,
            "events": {k: list(v) for k, v in self._events.items() if v},
            "sums": dict(self._sums),
        }

    def restore(self, state: dict[str, Any]) -> None:
        self.window_seconds = int(state["window_seconds"])
        self._events = defaultdict(deque)
        for key, values in state["events"].items():
            self._events[int(key)] = deque(tuple(v) for v in values)
        self._sums = Counter({int(k): int(v) for k, v in state["sums"].items()})


class _RollingFrequency:
    def __init__(self, window_seconds: int) -> None:
        self.window_seconds = window_seconds
        self._events: dict[tuple[int, int], deque[int]] = defaultdict(deque)

    def count_before(self, key: tuple[int, int], timestamp: int) -> int:
        events = self._events[key]
        cutoff = timestamp - self.window_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        return len(events)

    def add(self, key: tuple[int, int], timestamp: int) -> None:
        self._events[key].append(timestamp)

    def snapshot(self) -> dict[str, object]:
        return {
            "window_seconds": self.window_seconds,
            # Pair keys are tuples, which a dict-keyed snapshot cannot carry
            # portably, so they travel as (key, values) pairs.
            "events": [[list(k), list(v)] for k, v in self._events.items() if v],
        }

    def restore(self, state: dict[str, Any]) -> None:
        self.window_seconds = int(state["window_seconds"])
        self._events = defaultdict(deque)
        for key, values in state["events"]:
            self._events[(int(key[0]), int(key[1]))] = deque(int(v) for v in values)


class CausalFeatureEngine:
    """Stateful scorer with an explicit score-before-update contract.

    Events sharing a timestamp are scored as a group against the same prior state. This enforces
    the blueprint's strict ``history timestamp < current timestamp`` rule even when many records
    occur in the same second.
    """

    def __init__(self) -> None:
        self._last_processed_timestamp: int | None = None
        self._last_user: dict[int, int] = {}
        self._last_pair: dict[tuple[int, int], int] = {}
        self._pair_total: Counter[tuple[int, int]] = Counter()
        self._user_destinations: dict[int, set[int]] = defaultdict(set)
        self._src_destinations: dict[int, set[int]] = defaultdict(set)
        self._dst_users: dict[int, set[int]] = defaultdict(set)
        self._user_logons: dict[int, Counter[int]] = defaultdict(Counter)
        self._user_event_total: Counter[int] = Counter()
        self._user_sources: dict[int, set[int]] = defaultdict(set)
        self._user_dst_5m = _RollingDistinct(300)
        self._user_dst_1h = _RollingDistinct(3_600)
        self._user_dst_24h = _RollingDistinct(86_400)
        self._src_dst_1h = _RollingDistinct(3_600)
        self._dst_user_1h = _RollingDistinct(3_600)
        self._user_auth_5m = _RollingBinary(300)
        self._user_failures_15m = _RollingBinary(900)
        self._user_new_dst_1h = _RollingBinary(3_600)
        self._pair_1h = _RollingFrequency(3_600)
        self._src_user_1h = _RollingDistinct(3_600)

    # ------------------------------------------------------------------
    # State persistence
    #
    # Twelve of the 27 features are cumulative -- they answer "has this ever
    # happened", over _pair_total, _user_destinations, _src_destinations,
    # _dst_users, _last_user, _last_pair and _user_logons. No amount of
    # warm-up reconstructs them: measured against a full-history reference,
    # `is_new_pair` was still 42% divergent after 200,000 events of warm-up,
    # and only 0.3% of events received fully correct features.
    #
    # The engine was constructed fresh on every process start and never
    # persisted, so each restart discarded all of it. A live stream only moves
    # forward, so that state is never rebuilt -- the service came back up
    # permanently less accurate than it went down, with no signal that
    # anything had changed.
    #
    # Snapshots make the state an artifact: built once from historical logs at
    # onboarding, restored on every start.
    # ------------------------------------------------------------------
    #: Version 2 adds the host-centric state (``user_sources``, ``src_user_1h``).
    #: A version-1 snapshot still restores; those three features then start
    #: cold, which ``coverage()`` makes visible.
    SNAPSHOT_VERSION = 2

    def snapshot(self) -> dict[str, object]:
        """Serialisable copy of all engine state."""
        return {
            "version": self.SNAPSHOT_VERSION,
            "last_processed_timestamp": self._last_processed_timestamp,
            "last_user": dict(self._last_user),
            # tuple keys travel as pair lists
            "last_pair": [[list(k), v] for k, v in self._last_pair.items()],
            "pair_total": [[list(k), v] for k, v in self._pair_total.items()],
            "user_destinations": {k: sorted(v) for k, v in self._user_destinations.items() if v},
            "src_destinations": {k: sorted(v) for k, v in self._src_destinations.items() if v},
            "dst_users": {k: sorted(v) for k, v in self._dst_users.items() if v},
            "user_logons": {k: dict(v) for k, v in self._user_logons.items() if v},
            "user_event_total": dict(self._user_event_total),
            "user_sources": {k: sorted(v) for k, v in self._user_sources.items() if v},
            "rolling": {
                "user_dst_5m": self._user_dst_5m.snapshot(),
                "user_dst_1h": self._user_dst_1h.snapshot(),
                "user_dst_24h": self._user_dst_24h.snapshot(),
                "src_dst_1h": self._src_dst_1h.snapshot(),
                "dst_user_1h": self._dst_user_1h.snapshot(),
                "user_auth_5m": self._user_auth_5m.snapshot(),
                "user_failures_15m": self._user_failures_15m.snapshot(),
                "user_new_dst_1h": self._user_new_dst_1h.snapshot(),
                "pair_1h": self._pair_1h.snapshot(),
                "src_user_1h": self._src_user_1h.snapshot(),
            },
        }

    def restore(self, state: dict[str, Any]) -> None:
        """Rebuild engine state from a snapshot, replacing anything present."""
        version = int(state.get("version", 0))
        if version not in (1, self.SNAPSHOT_VERSION):
            raise ValueError(
                f"feature state snapshot version {version} is not supported "
                f"(expected {self.SNAPSHOT_VERSION}); rebuild it from source logs"
            )
        self._last_processed_timestamp = state["last_processed_timestamp"]
        self._last_user = {int(k): int(v) for k, v in state["last_user"].items()}
        self._last_pair = {(int(k[0]), int(k[1])): int(v) for k, v in state["last_pair"]}
        self._pair_total = Counter(
            {(int(k[0]), int(k[1])): int(v) for k, v in state["pair_total"]}
        )
        self._user_destinations = defaultdict(set)
        for key, values in state["user_destinations"].items():
            self._user_destinations[int(key)] = set(values)
        self._src_destinations = defaultdict(set)
        for key, values in state["src_destinations"].items():
            self._src_destinations[int(key)] = set(values)
        self._dst_users = defaultdict(set)
        for key, values in state["dst_users"].items():
            self._dst_users[int(key)] = set(values)
        self._user_logons = defaultdict(Counter)
        for key, values in state["user_logons"].items():
            self._user_logons[int(key)] = Counter({int(k): int(v) for k, v in values.items()})
        self._user_event_total = Counter(
            {int(k): int(v) for k, v in state["user_event_total"].items()}
        )
        rolling = state["rolling"]
        self._user_dst_5m.restore(rolling["user_dst_5m"])
        self._user_dst_1h.restore(rolling["user_dst_1h"])
        self._user_dst_24h.restore(rolling["user_dst_24h"])
        self._src_dst_1h.restore(rolling["src_dst_1h"])
        self._dst_user_1h.restore(rolling["dst_user_1h"])
        self._user_auth_5m.restore(rolling["user_auth_5m"])
        self._user_failures_15m.restore(rolling["user_failures_15m"])
        self._user_new_dst_1h.restore(rolling["user_new_dst_1h"])
        self._pair_1h.restore(rolling["pair_1h"])
        self._user_sources = defaultdict(set)
        for key, values in state.get("user_sources", {}).items():
            self._user_sources[int(key)] = set(values)
        self._src_user_1h = _RollingDistinct(3_600)
        if "src_user_1h" in rolling:
            self._src_user_1h.restore(rolling["src_user_1h"])

    def coverage(self) -> dict[str, int]:
        """How much history this engine is carrying.

        Exposed so a deployment can tell a warm engine from a cold one rather
        than inferring it from detection quality after the fact.
        """
        return {
            "known_pairs": len(self._pair_total),
            "known_users": len(self._user_event_total),
            "known_source_hosts": len(self._src_destinations),
            "known_destination_hosts": len(self._dst_users),
            "known_account_sources": sum(len(v) for v in self._user_sources.values()),
            "last_processed_timestamp": self._last_processed_timestamp or 0,
        }

    # ------------------------------------------------------------------
    # Scoped transactions
    #
    # The live path needs "score this batch, and if anything downstream
    # fails, leave the engine exactly as it was". It used to get that by
    # deep-copying the whole engine per batch and swapping on success. With
    # the warm state a deployment must run with (543,615 events of history),
    # that copy takes minutes and, on the event loop, freezes the service.
    #
    # A batch can only touch state keyed by the users, hosts and pairs it
    # contains, so the checkpoint copies exactly those entries -- O(batch)
    # rather than O(estate) -- and rollback restores or deletes them. It is
    # generic over every dict-shaped container the engine and its trackers
    # hold, so a container added later is covered without being enumerated.
    # ------------------------------------------------------------------
    def _containers(self) -> list[dict[object, object]]:
        found: list[dict[object, object]] = []
        for value in vars(self).values():
            if isinstance(value, dict):
                found.append(value)
            elif isinstance(value, (_RollingDistinct, _RollingBinary, _RollingFrequency)):
                found.extend(v for v in vars(value).values() if isinstance(v, dict))
        return found

    def checkpoint(self, events: Sequence[NormalizedAuthEvent]) -> EngineCheckpoint:
        """Copy the state a batch can reach, so it can be undone at O(batch) cost."""
        keys: set[object] = set()
        for event in events:
            keys.update((
                event.src_user_id, event.src_host_id, event.dst_host_id,
                (event.src_user_id, event.dst_host_id),
                (event.src_host_id, event.dst_host_id),
            ))
        entries: list[tuple[dict[object, object], object, bool, object]] = []
        for container in self._containers():
            for key in keys:
                if key in container:
                    entries.append((container, key, True, copy.deepcopy(container[key])))
                else:
                    entries.append((container, key, False, None))
        return EngineCheckpoint(self._last_processed_timestamp, entries)

    def rollback(self, checkpoint: EngineCheckpoint) -> None:
        """Restore every entry the checkpoint captured; delete ones created since."""
        for container, key, existed, saved in checkpoint.entries:
            if existed:
                container[key] = saved
            else:
                container.pop(key, None)
        self._last_processed_timestamp = checkpoint.last_processed_timestamp

    def transform(self, events: Iterable[NormalizedAuthEvent]) -> Iterator[FeatureRecord]:
        previous_timestamp: int | None = None
        for timestamp, grouped in groupby(events, key=lambda event: event.timestamp):
            if previous_timestamp is not None and timestamp < previous_timestamp:
                raise ValueError("Events must be non-decreasing by timestamp")
            group = tuple(grouped)
            yield from self.score_group(group)
            previous_timestamp = timestamp

    def score_group(self, events: Sequence[NormalizedAuthEvent]) -> tuple[FeatureRecord, ...]:
        if not events:
            return ()
        timestamp = events[0].timestamp
        if any(event.timestamp != timestamp for event in events):
            raise ValueError("score_group requires one shared timestamp")
        if (
            self._last_processed_timestamp is not None
            and timestamp <= self._last_processed_timestamp
        ):
            raise ValueError(
                "score_group timestamps must strictly increase; combine equal timestamps"
            )
        records = tuple(self._score(event) for event in events)
        for event in events:
            self._update(event)
        self._last_processed_timestamp = timestamp
        return records

    def _score(self, event: NormalizedAuthEvent) -> FeatureRecord:
        pair = (event.src_user_id, event.dst_host_id)
        user_seen = event.src_user_id in self._last_user
        pair_seen = pair in self._last_pair
        user_last = self._last_user.get(event.src_user_id, event.timestamp)
        pair_last = self._last_pair.get(pair, event.timestamp)
        pair_total = self._pair_total[pair]

        auth_count, _ = self._user_auth_5m.stats_before(event.src_user_id, event.timestamp)
        failure_count, failures = self._user_failures_15m.stats_before(
            event.src_user_id, event.timestamp
        )
        new_count, new_destinations = self._user_new_dst_1h.stats_before(
            event.src_user_id, event.timestamp
        )
        user_total = self._user_event_total[event.src_user_id]
        logon_counts = self._user_logons[event.src_user_id]
        category_count = logon_counts[event.logon_type_id]
        observed_categories = len(logon_counts)
        smoothed_probability = (category_count + 1) / (user_total + observed_categories + 1)

        hour_angle = 2 * math.pi * event.hour / 24
        return FeatureRecord(
            event_id=event.event_id,
            timestamp=event.timestamp,
            day=event.day,
            src_user_id=event.src_user_id,
            dst_user_id=event.dst_user_id,
            src_host_id=event.src_host_id,
            dst_host_id=event.dst_host_id,
            auth_type_id=event.auth_type_id,
            logon_type_id=event.logon_type_id,
            orientation_id=event.orientation_id,
            success=event.success,
            label_redteam=event.label_redteam,
            hour_sin=math.sin(hour_angle),
            hour_cos=math.cos(hour_angle),
            delta_user_log=math.log1p(event.timestamp - user_last) if user_seen else 0.0,
            delta_pair_log=math.log1p(event.timestamp - pair_last) if pair_seen else 0.0,
            user_seen_before=int(user_seen),
            pair_seen_before=int(pair_seen),
            is_new_pair=int(not pair_seen),
            pair_frequency_1h=self._pair_1h.count_before(pair, event.timestamp),
            pair_rarity=1.0 / math.sqrt(pair_total + 1),
            user_unique_dst_5m=self._user_dst_5m.count_before(event.src_user_id, event.timestamp),
            user_unique_dst_1h=self._user_dst_1h.count_before(event.src_user_id, event.timestamp),
            user_unique_dst_24h=self._user_dst_24h.count_before(event.src_user_id, event.timestamp),
            user_auth_rate_5m=auth_count,
            user_failure_rate_15m=failures / failure_count if failure_count else 0.0,
            failures_before_success_15m=failures if event.success else 0,
            user_new_dst_ratio_1h=new_destinations / new_count if new_count else 0.0,
            src_host_unique_dst_1h=self._src_dst_1h.count_before(
                event.src_host_id, event.timestamp
            ),
            dst_inbound_users_1h=self._dst_user_1h.count_before(event.dst_host_id, event.timestamp),
            destination_novelty=1.0 / (len(self._dst_users[event.dst_host_id]) + 1),
            user_historical_degree=len(self._user_destinations[event.src_user_id]),
            src_host_historical_degree=len(self._src_destinations[event.src_host_id]),
            dst_historical_degree=len(self._dst_users[event.dst_host_id]),
            rare_logon_score=-math.log(smoothed_probability),
            user_src_seen_before=int(event.src_host_id in self._user_sources.get(event.src_user_id, ())),
            src_dst_seen_before=int(event.dst_host_id in self._src_destinations.get(event.src_host_id, ())),
            src_host_unique_users_1h=self._src_user_1h.count_before(event.src_host_id, event.timestamp),
        )

    def _update(self, event: NormalizedAuthEvent) -> None:
        pair = (event.src_user_id, event.dst_host_id)
        is_new = int(event.dst_host_id not in self._user_destinations[event.src_user_id])
        self._user_dst_5m.add(event.src_user_id, event.timestamp, event.dst_host_id)
        self._user_dst_1h.add(event.src_user_id, event.timestamp, event.dst_host_id)
        self._user_dst_24h.add(event.src_user_id, event.timestamp, event.dst_host_id)
        self._src_dst_1h.add(event.src_host_id, event.timestamp, event.dst_host_id)
        self._dst_user_1h.add(event.dst_host_id, event.timestamp, event.src_user_id)
        self._user_auth_5m.add(event.src_user_id, event.timestamp, 1)
        self._user_failures_15m.add(event.src_user_id, event.timestamp, 1 - event.success)
        self._user_new_dst_1h.add(event.src_user_id, event.timestamp, is_new)
        self._pair_1h.add(pair, event.timestamp)
        self._last_user[event.src_user_id] = event.timestamp
        self._last_pair[pair] = event.timestamp
        self._pair_total[pair] += 1
        self._user_destinations[event.src_user_id].add(event.dst_host_id)
        self._src_destinations[event.src_host_id].add(event.dst_host_id)
        self._dst_users[event.dst_host_id].add(event.src_user_id)
        self._user_logons[event.src_user_id][event.logon_type_id] += 1
        self._user_event_total[event.src_user_id] += 1
        self._user_sources[event.src_user_id].add(event.src_host_id)
        self._src_user_1h.add(event.src_host_id, event.timestamp, event.src_user_id)
