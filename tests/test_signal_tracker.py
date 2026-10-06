"""One signal state for every scoring path.

Finding 24: the live gateway, the scored-cache builder behind the evaluation
report, the training pipeline's fused threshold and the prevention instrument
each assembled the pivot state by hand, and three of the four disagreed with
the product. ``SignalTracker`` is the single implementation; these tests pin
that it behaves like the gateway (score before update, chain-aware pivot) and
that the offline scorer and the live engine now compute the same channel for
the same events.
"""

from __future__ import annotations

from graphsentinel.detection.signals import ChainPivotTracker, SignalTracker, explicit_signals
from graphsentinel.features.causal import CausalFeatureEngine, FeatureRecord
from graphsentinel.ingestion.auth import NormalizedAuthEvent


def _event(event_id: int, timestamp: int, user: int, src: int, dst: int) -> NormalizedAuthEvent:
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_user_id=user,
        dst_user_id=user,
        src_host_id=src,
        dst_host_id=dst,
        auth_type_id=3,
        logon_type_id=1,
        orientation_id=1,
        success=1,
        label_redteam=0,
        day=timestamp // 86_400,
        hour=(timestamp % 86_400) // 3_600,
    )


def _records(events: list[NormalizedAuthEvent]) -> list[FeatureRecord]:
    return list(CausalFeatureEngine().transform(events))


class TestSignalTracker:
    def test_a_walk_is_a_chain_once_three_onward_hops_precede_it(self) -> None:
        """A -> B -> C -> D -> E -> F: the fifth move has three prior onward
        hops behind it (the first move starts from a host nobody reached), so
        it is the first the rule calls a chain -- hop index 4, as Finding 21
        measured."""
        hosts = [100, 101, 102, 103, 104, 105, 106]
        events = [
            _event(i, 1_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(6)
        ]

        def detections(tracker: SignalTracker) -> list[bool]:
            detected = []
            for record in _records(events):
                signals, chain = tracker.signals(record)
                detected.append(chain)
                if chain:
                    assert signals.pivot == 1.0
                tracker.observe_group([record])
            return detected

        finding_13 = SignalTracker(
            chains=ChainPivotTracker(window_seconds=300, minimum_prior_hops=3, require_novel=False)
        )
        assert detections(finding_13) == [False, False, False, False, True, True]
        # The shipped rule (Finding 25) needs three prior *novel* hops: the same
        # move as Finding 13's rule on a walk into hosts never reached before.
        assert detections(SignalTracker()) == [False, False, False, False, True, True]

    def test_scoring_reads_state_from_before_the_group(self) -> None:
        """Two events at one timestamp: neither sees the other, exactly as the
        gateway scores a request against the state before it."""
        hosts = [100, 101, 102, 103, 104, 105]
        walk = [_event(i, 1_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(4)]
        # The fifth move, and a sixth from the host it reaches, in the same second.
        same_second = [
            _event(10, 1_100, user=7, src=hosts[4], dst=hosts[5]),
            _event(11, 1_100, user=7, src=hosts[5], dst=999),
        ]
        records = _records(walk + same_second)
        tracker = SignalTracker()
        for record in records[:4]:
            tracker.signals(record)
            tracker.observe_group([record])
        group = records[4:]
        chains = [tracker.signals(record)[1] for record in group]
        tracker.observe_group(group)
        # The fifth move continues the chain; the move from 105 cannot, because
        # 105 was only reached in this same group, which is not observed yet.
        assert chains == [True, False]

    def test_matches_the_hand_rolled_gateway_ordering(self) -> None:
        """The tracker is the gateway's former inline code, moved. Same numbers."""
        events = []
        stamp = 1_000
        for i in range(60):
            stamp += 15
            user = 1 + i % 4
            events.append(
                _event(i, stamp, user=user, src=10 + (i % 5), dst=10 + ((i + 1 + user) % 6))
            )
        records = _records(events)

        tracker = SignalTracker()
        via_tracker = []
        from itertools import groupby

        for _ts, grouped in groupby(records, key=lambda r: r.timestamp):
            group = list(grouped)
            for record in group:
                signals, chain = tracker.signals(record)
                via_tracker.append((signals.pivot, chain))
            tracker.observe_group(group)

        chains = ChainPivotTracker()
        by_hand = []
        for _ts, grouped in groupby(records, key=lambda r: r.timestamp):
            group = list(grouped)
            for record in group:
                chains.advance(record.timestamp)
                chain = chains.is_chain_hop(
                    record.src_user_id,
                    record.src_host_id,
                    record.dst_host_id,
                    success=bool(record.success),
                )
                signals = explicit_signals(
                    record, prior_destination_hosts=set(), chain_tracker=chains
                )
                by_hand.append((signals.pivot, chain))
            for record in group:
                chains.observe(
                    record.src_user_id, record.src_host_id, record.dst_host_id, record.timestamp
                )
        assert via_tracker == by_hand

    def test_the_any_source_pivot_is_not_what_the_tracker_computes(self) -> None:
        """The channel the old cache scored: a host reached by *anyone* recently.
        The tracker requires the same account to be moving."""
        events = [
            _event(0, 1_000, user=1, src=10, dst=20),  # someone reaches 20
            _event(1, 1_010, user=2, src=20, dst=30),  # a different user leaves 20
        ]
        records = _records(events)
        tracker = SignalTracker()
        tracker.signals(records[0])
        tracker.observe_group([records[0]])
        signals, chain = tracker.signals(records[1])
        assert chain is False
        any_source = explicit_signals(records[1], prior_destination_hosts={20})
        assert any_source.pivot == 1.0
        assert signals.pivot < 1.0


class TestOfflineAndLivePathsAgree:
    def test_the_cache_builder_and_the_live_engine_compute_the_same_pivot(self, tmp_path) -> None:
        """The e2e claim in miniature: the same events through the live engine
        (no model, frozen maps off) and through the cache builder's loop give
        the same novelty, burst and pivot."""
        from itertools import groupby

        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
        from graphsentinel.api.service import DetectionService

        raw = []
        stamp = 5_000
        for i in range(40):
            stamp += 10 if i % 7 else 0
            user = f"U{1 + i % 3}@D"
            raw.append(
                LiveAuthEvent(
                    timestamp=stamp,
                    user=user,
                    source_host=f"C{10 + i % 4}",
                    destination_host=f"C{20 + (i * 3) % 5}",
                    success=True,
                    source="test",
                )
            )
        live = LiveDetectionEngine(DetectionService(threshold=0.5), id_map_dir=None)
        live_components = []
        for _ts, grouped in groupby(raw, key=lambda e: e.timestamp):
            response = live.detect(LiveAuthBatch(events=tuple(grouped)))
            live_components.extend(dict(r.components or {}) for r in response.results)

        # Offline: the same events normalised through the live engine's own
        # maps, then the cache builder's loop (tracker + groups).
        maps = live._maps
        normalized = [
            _event(
                i,
                e.timestamp,
                user=maps.users.lookup(e.user),
                src=maps.hosts.lookup(e.source_host),
                dst=maps.hosts.lookup(e.destination_host),
            )
            for i, e in enumerate(raw)
        ]
        records = _records(normalized)
        tracker = SignalTracker()
        offline = []
        for _ts, grouped in groupby(records, key=lambda r: r.timestamp):
            group = list(grouped)
            for record in group:
                signals, _chain = tracker.signals(record)
                offline.append(
                    {"novelty": signals.novelty, "burst": signals.burst, "pivot": signals.pivot}
                )
            tracker.observe_group(group)

        assert len(offline) == len(live_components) == 40
        for mine, theirs in zip(offline, live_components, strict=True):
            for channel in ("novelty", "burst", "pivot"):
                assert abs(mine[channel] - theirs[channel]) < 1e-9, channel


class TestFailedLogonsDoNotMove:
    def test_a_failed_hop_neither_reaches_nor_counts(self) -> None:
        """Four novel hops where the middle two failed: the account never
        entered those hosts, so there is no chain to continue."""
        from dataclasses import replace

        from graphsentinel.detection.signals import ChainPivotTracker

        hosts = [100, 101, 102, 103, 104, 105]
        events = [
            _event(i, 1_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(5)
        ]
        events = [replace(e, success=0) if e.event_id in (1, 2) else e for e in events]
        tracker = SignalTracker(
            chains=ChainPivotTracker(window_seconds=1_800, minimum_prior_hops=2, require_novel=True)
        )
        detected = []
        for record in _records(events):
            _signals, chain = tracker.signals(record)
            detected.append(chain)
            tracker.observe_group([record])
        # With the failures counted this would fire at index 3; it does not.
        assert detected == [False, False, False, False, False]
        assert len(tracker.destinations) == 3  # the three successful destinations

    def test_a_guessed_password_does_not_make_the_hop_familiar(self) -> None:
        """The demo attacker fails once or twice into each host before getting
        in. ``FeatureRecord.is_new_pair`` counts the failure as a sighting of
        the pair, so the success that follows is "not new"; a chain rule that
        took novelty from that feature never fired on this attacker at all.
        The tracker judges novelty from the reaches it was actually given."""
        from dataclasses import replace

        hosts = [100, 101, 102, 103, 104, 105]
        events = []
        stamp = 1_000
        for i in range(5):  # each hop: one failure, then the success
            failure = _event(len(events), stamp, user=7, src=hosts[i], dst=hosts[i + 1])
            events.append(replace(failure, success=0))
            stamp += 7
            events.append(_event(len(events), stamp, user=7, src=hosts[i], dst=hosts[i + 1]))
            stamp += 13
        records = _records(events)
        # The feature's view: every success is a pair already seen (by its failure).
        assert [r.is_new_pair for r in records if r.success] == [0, 0, 0, 0, 0]
        tracker = SignalTracker()  # the shipped rule: three prior novel hops
        detected = []
        for record in records:
            _signals, chain = tracker.signals(record)
            detected.append((record.success, chain))
            tracker.observe_group([record])
        successes = [chain for success, chain in detected if success]
        assert successes == [False, False, False, False, True]
        assert not any(chain for success, chain in detected if not success)

    def test_retracing_a_known_path_is_still_not_a_chain(self) -> None:
        """Novelty is cumulative over the account's successful reaches: the
        second walk along the same path adds no novel hops."""
        hosts = [100, 101, 102, 103, 104, 105]
        walk = [_event(i, 1_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(5)]
        again = [
            _event(10 + i, 3_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(5)
        ]
        tracker = SignalTracker()
        detected = []
        for record in _records(walk + again):
            _signals, chain = tracker.signals(record)
            detected.append(chain)
            tracker.observe_group([record])
        assert detected[:5] == [False, False, False, False, True]
        assert detected[5:] == [False] * 5

    def test_the_hop_itself_must_be_novel_and_successful(self) -> None:
        """After three novel hops the account is "moving" for the whole
        window, and the pivot channel says so on every move it makes from a
        reached host. The rule is stricter: only the next *novel* successful
        hop is a chain hop -- not a failed attempt, not a return to a host the
        account already reached. On the full-rate day this is the difference
        between 114 and 4.3 benign events per 10,000 (Finding 27)."""
        from dataclasses import replace

        hosts = [100, 101, 102, 103, 104, 105]
        walk = [_event(i, 1_000 + i * 20, user=7, src=hosts[i], dst=hosts[i + 1]) for i in range(4)]
        # Then, from the last host reached: a failed novel attempt, a move back
        # to a host already reached, and finally a successful novel hop.
        tail = [
            replace(_event(10, 1_200, user=7, src=hosts[4], dst=hosts[5]), success=0),
            _event(11, 1_220, user=7, src=hosts[4], dst=hosts[1]),
            _event(12, 1_240, user=7, src=hosts[4], dst=hosts[5]),
        ]
        tracker = SignalTracker()
        seen = []
        for record in _records(walk + tail):
            signals, chain = tracker.signals(record)
            seen.append((signals.pivot, chain))
            tracker.observe_group([record])
        pivots = [p for p, _ in seen]
        chains = [c for _, c in seen]
        assert chains == [False, False, False, False, False, False, True]
        # The pivot channel is the looser question and is 1.0 on all three.
        assert pivots[4:] == [1.0, 1.0, 1.0]
