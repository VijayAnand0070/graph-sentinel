"""Shared explicit security signals for offline evaluation and live detection.

The pivot signal and why it needs a window
------------------------------------------
``pivot`` asks whether this event's SOURCE host was itself reached as a
destination earlier -- a foothold now being used to extend reach. That is the
defining shape of lateral movement, and it is the one signal here that no
per-event feature can express, because it depends on the history of a
*different* edge.

Implemented against an unbounded set of every host ever reached, the signal
destroys itself. Measured over the 543,615-event corpus, an unbounded set
fires on:

    1,000 events   ->  50.0% of traffic   (152 hosts accumulated)
    50,000 events  ->  64.4%              (3,098 hosts)
    543,615 events ->  85.7%              (10,548 hosts)

In a finite estate every host eventually becomes some other host's
destination, so the set converges on "all hosts" and the signal converges on
the constant 1.0. It carries progressively less information the longer the
system runs -- which is the worst possible failure mode, because it degrades
silently and looks like it is working.

The fix is a time window. A host reached ten minutes ago is a meaningful
pivot origin; a host reached three weeks ago is just a host. The window is set
to the same 1,800 seconds the path ranker uses for chaining hops, so the two
components agree on what "recently" means -- a pivot the signal reports should
be one the path ranker can actually build a chain from.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from graphsentinel.features.causal import FeatureRecord

#: Matches PathRankerConfig.forward_window_seconds so the pivot signal and the
#: path ranker share a definition of "recently reached".
DEFAULT_PIVOT_WINDOW_SECONDS = 1_800


@dataclass(frozen=True, slots=True)
class ExplicitSignals:
    novelty: float
    burst: float
    pivot: float


@dataclass
class RecentDestinations:
    """Time-windowed set of recently reached hosts.

    Supports ``in`` so it drops straight into :func:`explicit_signals` where a
    plain ``set`` was used before.

    Entries are held in arrival order alongside a reference count per host, so
    eviction is amortised O(1) and a host reached repeatedly stays present
    until its *last* sighting ages out rather than its first.
    """

    window_seconds: int = DEFAULT_PIVOT_WINDOW_SECONDS
    _entries: deque[tuple[int, int]] = field(default_factory=deque)
    _counts: dict[int, int] = field(default_factory=dict)
    _latest: int = 0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("pivot window must be positive")

    def add(self, host_id: int, timestamp: int) -> None:
        self._entries.append((timestamp, host_id))
        self._counts[host_id] = self._counts.get(host_id, 0) + 1
        self._latest = max(self._latest, timestamp)
        self._evict()

    def advance(self, timestamp: int) -> None:
        """Move the clock forward without adding anything.

        Needed because a quiet period must still age entries out; otherwise a
        gap in traffic would freeze the window open.
        """
        self._latest = max(self._latest, timestamp)
        self._evict()

    def _evict(self) -> None:
        cutoff = self._latest - self.window_seconds
        while self._entries and self._entries[0][0] < cutoff:
            _timestamp, host_id = self._entries.popleft()
            remaining = self._counts.get(host_id, 0) - 1
            if remaining <= 0:
                self._counts.pop(host_id, None)
            else:
                self._counts[host_id] = remaining

    def __contains__(self, host_id: object) -> bool:
        return host_id in self._counts

    def __len__(self) -> int:
        return len(self._counts)

    def clear(self) -> None:
        self._entries.clear()
        self._counts.clear()
        self._latest = 0


#: A chain needs to be a chain. Requiring prior hops by the SAME account is
#: what separates "an attacker walking the estate" from "a workstation that was
#: reached and then talked to its file server".
#: Chosen by measuring the false-positive cost of every candidate against the
#: 25-per-10,000 budget, rather than by picking a plausible-looking number:
#:
#:     rule                        chain hits    FP/10k    within budget
#:     chain 3+ hops /  600s               10      77.5    no
#:     chain 4+ hops /  600s                9      30.7    no
#:     chain 5+ hops /  600s                8      13.0    yes
#:     chain 4+ hops /  300s                9       4.6    yes  <- selected
#:     chain 5+ hops /  300s                8       1.0    yes
#:
#: 4 hops in 300 seconds catches the most chain events of any rule that fits,
#: at 18% of the budget. Tightening the window matters more than requiring
#: more hops: an attacker moving through five hosts in five minutes is doing
#: something an administrator does not.
#:
#: That table was measured on the *sampled* corpus, and Finding 25 showed
#: it does not survive full rate: on an unsampled day the same 4-hop/300 s
#: rule flags 715-855 benign events per 10,000 -- sampling one event in
#: several hundred had hidden almost every benign multi-hop pattern.
#: Requiring *novel* hops (moves to a host the account has never reached)
#: is what makes a chain rule usable at full rate: four novel hops in
#: 1,800 s falls to 0-9 per 10,000 by the end of a single cold day and keeps
#: falling as history accumulates, while detecting 44 of 100 unseen
#: campaigns at the attacker's fourth move and, allowed to trigger the
#: unattended action, preventing 13.9% of hops against 0.75% before. These
#: are the shipped defaults; ``detection/policy.py`` reads them from the
#: environment, ``scripts/chain_rule_study.py`` and
#: ``scripts/chain_rule_hourly.py`` regenerate the tables.
DEFAULT_CHAIN_WINDOW_SECONDS = 1_800
DEFAULT_MINIMUM_PRIOR_HOPS = 3
DEFAULT_REQUIRE_NOVEL = True


@dataclass
class ChainPivotTracker:
    """Detects an account continuing a multi-hop path through the estate.

    The original pivot asked "was this event's source host recently a
    destination of *anyone*?". Measured over the 543,615-event corpus that
    fires on 47.05% of benign traffic -- it describes ordinary client-server
    behaviour, and no weight can rescue a signal that describes half the data.

    Requiring the same account to have reached the source, and to have already
    made prior hops inside a tight window, measures the thing that actually
    matters: a credential moving. Measured on the same two datasets:

    ============================================  ========  ===========  ======
    definition                                     chain      LANL         lift
                                                   recall     benign
    ============================================  ========  ===========  ======
    any-source pivot (previous)                     42.9%      47.052%     0.9x
    same-user chain, 3+ hops, 1800s                 35.7%       3.693%     9.7x
    same-user chain, 3+ hops,  600s                 35.7%       0.775%    46.1x
    same-user chain, 4+ hops,  600s                 32.1%       0.307%   104.8x
    ============================================  ========  ===========  ======

    Seven points of chain recall for sixty times the selectivity. A channel at
    0.775% can carry real weight inside a false-positive budget; one at 47%
    cannot, at any weight.
    """

    window_seconds: int = DEFAULT_CHAIN_WINDOW_SECONDS
    minimum_prior_hops: int = DEFAULT_MINIMUM_PRIOR_HOPS
    #: Count only *novel* onward hops -- moves to a destination the account
    #: has never successfully reached before, by this tracker's own history.
    #: An account retracing its usual path through the estate is then not a
    #: chain; an account walking into hosts it has never touched is. Measured
    #: in Finding 25. Not ``FeatureRecord.is_new_pair``: the feature engine
    #: counts a failed attempt as a sighting of the pair, so an attacker who
    #: guesses a password before each hop would make every hop look familiar
    #: and walk through the rule (Finding 27).
    require_novel: bool = DEFAULT_REQUIRE_NOVEL
    #: (timestamp, user, host) for hosts each account has reached.
    _reached: deque[tuple[int, int, int]] = field(default_factory=deque)
    _reached_counts: dict[tuple[int, int], int] = field(default_factory=dict)
    #: Hop timestamps per account, so "already moving" is measurable.
    _hops: dict[int, deque[int]] = field(default_factory=dict)
    #: The same hops in arrival order, so eviction walks only what expired
    #: rather than every account's deque on every event -- at a full-rate
    #: day (7.3 M events, 18 K accounts) the per-account scan was the
    #: difference between minutes and hours.
    _hop_log: deque[tuple[int, int]] = field(default_factory=deque)
    #: Every host each account has ever successfully reached: the novelty test.
    _reached_ever: dict[int, set[int]] = field(default_factory=dict)
    _latest: int = 0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("chain window must be positive")
        if self.minimum_prior_hops < 0:
            raise ValueError("minimum_prior_hops cannot be negative")

    def advance(self, timestamp: int) -> None:
        self._latest = max(self._latest, timestamp)
        cutoff = self._latest - self.window_seconds
        while self._reached and self._reached[0][0] < cutoff:
            _timestamp, user, host = self._reached.popleft()
            key = (user, host)
            remaining = self._reached_counts.get(key, 0) - 1
            if remaining <= 0:
                self._reached_counts.pop(key, None)
            else:
                self._reached_counts[key] = remaining
        # Hops arrive in time order, so the oldest global entry for an account
        # is that account's oldest hop; popping both keeps them aligned.
        while self._hop_log and self._hop_log[0][0] < cutoff:
            _timestamp, user = self._hop_log.popleft()
            hops = self._hops.get(user)
            if hops:
                hops.popleft()
                if not hops:
                    del self._hops[user]

    def continues_chain(self, user_id: int, source_host_id: int) -> bool:
        """Is this account moving onward from a host it recently reached, with
        the prior hops behind it? The pivot channel's question: it is true of
        every move the account makes from a reached host while the hops are
        inside the window, whatever the move is."""
        return (user_id, source_host_id) in self._reached_counts and len(
            self._hops.get(user_id, ())
        ) >= self.minimum_prior_hops

    def is_chain_hop(
        self, user_id: int, source_host_id: int, destination_host_id: int, *, success: bool
    ) -> bool:
        """Is this event itself the next hop of a chain? The rule's question,
        and stricter than :meth:`continues_chain`: the event must be a
        successful authentication (a failed logon reaches nothing) and, when
        the rule counts novel hops, its destination must be one the account
        has never successfully reached. An account that made three novel hops
        and then keeps authenticating from those hosts to the servers it
        always uses is not chaining on every such event; on a full-rate day
        that difference is 114 against 4.3 benign events per 10,000 (Finding
        27)."""
        if not success or not self.continues_chain(user_id, source_host_id):
            return False
        if self.require_novel:
            return destination_host_id not in self._reached_ever.get(user_id, ())
        return True

    def observe(
        self, user_id: int, source_host_id: int, destination_host_id: int, timestamp: int
    ) -> None:
        """Fold one successful reach in. Call after scoring it, never before.

        Whether the move is novel -- a destination this account has never
        successfully reached -- is the tracker's own judgement, from the
        reaches it has been given; the caller decides only which events are
        reaches (successful authentications).
        """
        reached_ever = self._reached_ever.setdefault(user_id, set())
        novel = destination_host_id not in reached_ever
        counts_as_hop = novel or not self.require_novel
        if counts_as_hop and (user_id, source_host_id) in self._reached_counts:
            self._hops.setdefault(user_id, deque()).append(timestamp)
            self._hop_log.append((timestamp, user_id))
        reached_ever.add(destination_host_id)
        self._reached.append((timestamp, user_id, destination_host_id))
        key = (user_id, destination_host_id)
        self._reached_counts[key] = self._reached_counts.get(key, 0) + 1
        self.advance(timestamp)

    def __len__(self) -> int:
        return len(self._reached_counts)

    def clear(self) -> None:
        self._reached.clear()
        self._reached_counts.clear()
        self._hops.clear()
        self._hop_log.clear()
        self._reached_ever.clear()
        self._latest = 0


#: Defaults for the fan-out rule, chosen on unlabelled full-rate LANL training
#: days by benign cost alone: the most sensitive setting within one flag per
#: million authentications (0.91 per million measured). See
#: ``scripts/fanout_baseline_study.py`` and :class:`FanOutTracker`.
DEFAULT_FANOUT_WINDOW_SECONDS = 3_600
DEFAULT_FANOUT_MINIMUM_ACCOUNTS = 8
DEFAULT_FANOUT_MINIMUM_NOVEL_MOVES = 5
DEFAULT_FANOUT_BASELINE_LIMIT = 2.0
DEFAULT_FANOUT_BASELINE_DAYS = 7


@dataclass
class FanOutTracker:
    """Detects one host reaching new hosts with several accounts: a beachhead.

    The chain rule follows a *credential* through the estate and is blind, by
    construction, to the other shape of lateral movement: an attacker who stays
    on one compromised host and uses the several credentials harvested there to
    reach one new host after another. In the prevention instrument only 2 of 50
    such fan-out campaigns were acted on; LANL's labelled red team is almost
    entirely this shape (one source host, 104 accounts, 301 destinations).

    A fan-out hop is a successful authentication from source host ``s`` to a
    host ``s`` has never successfully reached, when ``s`` has already, within
    the window, used at least ``minimum_accounts`` distinct accounts and made
    at least ``minimum_novel_moves`` such novel moves. Novelty is this
    tracker's own success-only history, for the reason the chain rule's is: a
    failed attempt reaches nothing and must not spend the novelty of a host.

    **Compared with the host itself.** A fixed threshold is dominated by
    infrastructure: on full-rate LANL a few hub hosts use thousands of
    accounts an hour and reach new hosts all day, so even 100 accounts and 100
    novel moves flag ~210 of every million events. The rule therefore also
    requires the host's *baseline* -- the median, over its previous active days
    (up to ``baseline_days``), of its daily maximum of accounts in the window --
    to be at most ``baseline_limit``: an ordinary workstation, suddenly acting
    like a hub. A host with no history has baseline 0.
    """

    window_seconds: int = DEFAULT_FANOUT_WINDOW_SECONDS
    minimum_accounts: int = DEFAULT_FANOUT_MINIMUM_ACCOUNTS
    minimum_novel_moves: int = DEFAULT_FANOUT_MINIMUM_NOVEL_MOVES
    baseline_limit: float = DEFAULT_FANOUT_BASELINE_LIMIT
    baseline_days: int = DEFAULT_FANOUT_BASELINE_DAYS
    #: per host: the current day and its maximum accounts-in-window so far
    _today: dict[int, tuple[int, int]] = field(default_factory=dict)
    #: per host: daily maxima of earlier active days (most recent last)
    _history: dict[int, deque[int]] = field(default_factory=dict)
    #: (timestamp, source, account, novel) for successful moves in the window
    _moves: deque[tuple[int, int, int, bool]] = field(default_factory=deque)
    _accounts: dict[int, dict[int, int]] = field(default_factory=dict)
    _novel: dict[int, int] = field(default_factory=dict)
    _reached_ever: dict[int, set[int]] = field(default_factory=dict)
    _latest: int = 0

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("fan-out window must be positive")
        if self.minimum_accounts < 1 or self.minimum_novel_moves < 0:
            raise ValueError("fan-out thresholds must be positive")

    def advance(self, timestamp: int) -> None:
        self._latest = max(self._latest, timestamp)
        cutoff = self._latest - self.window_seconds
        while self._moves and self._moves[0][0] <= cutoff:
            _t, source, account, novel = self._moves.popleft()
            accounts = self._accounts[source]
            remaining = accounts[account] - 1
            if remaining:
                accounts[account] = remaining
            else:
                del accounts[account]
                if not accounts:
                    del self._accounts[source]
            if novel:
                left = self._novel[source] - 1
                if left:
                    self._novel[source] = left
                else:
                    del self._novel[source]

    def baseline(self, source_host_id: int) -> float:
        """Median of the host's daily maxima over its previous active days."""
        history = self._history.get(source_host_id)
        if not history:
            return 0.0
        ordered = sorted(history)
        mid = len(ordered) // 2
        return float(ordered[mid]) if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2

    def _note(self, source_host_id: int, accounts: int) -> None:
        day = self._latest // 86_400
        current = self._today.get(source_host_id)
        if current is None or current[0] != day:
            if current is not None:
                history = self._history.setdefault(source_host_id, deque(maxlen=self.baseline_days))
                history.append(current[1])
            self._today[source_host_id] = (day, accounts)
        elif accounts > current[1]:
            self._today[source_host_id] = (day, accounts)

    def is_fanout_hop(self, source_host_id: int, destination_host_id: int, *, success: bool) -> bool:
        """The rule's decision for one event, read from state before its group.

        Also records the host's current account count for its daily baseline
        (every event counts, as in the costing study), so call it once per event.
        """
        accounts = len(self._accounts.get(source_host_id, ()))
        baseline = self.baseline(source_host_id)
        self._note(source_host_id, accounts)
        if not success or destination_host_id in self._reached_ever.get(source_host_id, ()):
            return False
        return (
            accounts >= self.minimum_accounts
            and self._novel.get(source_host_id, 0) >= self.minimum_novel_moves
            and baseline <= self.baseline_limit
        )

    def observe(self, user_id: int, source_host_id: int, destination_host_id: int, timestamp: int) -> None:
        """Fold one successful authentication in. Call after scoring, never before."""
        reached = self._reached_ever.setdefault(source_host_id, set())
        novel = destination_host_id not in reached
        reached.add(destination_host_id)
        self._moves.append((timestamp, source_host_id, user_id, novel))
        accounts = self._accounts.setdefault(source_host_id, {})
        accounts[user_id] = accounts.get(user_id, 0) + 1
        if novel:
            self._novel[source_host_id] = self._novel.get(source_host_id, 0) + 1
        self.advance(timestamp)

    def clear(self) -> None:
        self._moves.clear()
        self._accounts.clear()
        self._novel.clear()
        self._reached_ever.clear()
        self._today.clear()
        self._history.clear()
        self._latest = 0


def explicit_signals(
    record: FeatureRecord,
    *,
    prior_destination_hosts: set[int] | RecentDestinations,
    chain_tracker: ChainPivotTracker | None = None,
) -> ExplicitSignals:
    """Derive the three behavioural channels for one event.

    ``chain_tracker`` supplies the chain-aware pivot. When omitted the signal
    falls back to the any-source test, which is retained only so existing
    callers keep working -- it fires on 47% of benign traffic and should not be
    relied on. See :class:`ChainPivotTracker`.

    The fan-out fallback is kept in both paths: it is the term that actually
    carries signal on the LANL corpus, where the attacks contain no pivots at
    all but do show source hosts reaching many destinations.
    """
    novelty = max(float(record.is_new_pair), record.destination_novelty)
    burst = 1 - math.exp(-(record.user_auth_rate_5m + record.user_unique_dst_5m) / 10)

    if chain_tracker is not None:
        chaining = chain_tracker.continues_chain(record.src_user_id, record.src_host_id)
    else:
        chaining = record.src_host_id in prior_destination_hosts

    pivot = 1.0 if chaining else min(1.0, record.src_host_unique_dst_1h / 5)
    return ExplicitSignals(novelty=novelty, burst=burst, pivot=pivot)


@dataclass
class SignalTracker:
    """The stream state behind :func:`explicit_signals`, advanced one way.

    Before this existed, four callers -- the live gateway, the scored-cache
    builder behind the evaluation report, the training pipeline's fused
    threshold, and the prevention instrument -- each assembled the pivot
    state by hand, and three of them disagreed: the gateway used the
    same-account chain, the cache and the training pipeline used the
    any-source test the module documents as unusable, and the training
    pipeline's set was not even windowed. The published operating point was
    therefore calibrated on a channel the product does not compute
    (Finding 24). Every path now goes through this class, so the offline
    evaluation scores exactly what the deployed path scores.

    Protocol: for each timestamp group, call :meth:`signals` for every event
    (scoring reads state from *before* the group), then :meth:`observe_group`
    once. The chain tracker's clock advances on every call.
    """

    chains: ChainPivotTracker = field(default_factory=ChainPivotTracker)
    destinations: RecentDestinations = field(default_factory=RecentDestinations)
    #: The host-centric companion of the chain rule (:class:`FanOutTracker`).
    fanouts: FanOutTracker = field(default_factory=FanOutTracker)

    def signals(self, record: FeatureRecord) -> tuple[ExplicitSignals, bool]:
        """The three channels for one event, and whether it is a chain hop."""
        self.chains.advance(record.timestamp)
        self.destinations.advance(record.timestamp)
        chain_detected = self.chains.is_chain_hop(
            record.src_user_id,
            record.src_host_id,
            record.dst_host_id,
            success=bool(record.success),
        )
        return (
            explicit_signals(
                record, prior_destination_hosts=self.destinations, chain_tracker=self.chains
            ),
            chain_detected,
        )

    def fanout_hop(self, record: FeatureRecord) -> bool:
        """Is this event a fan-out hop? Reads state from before its group, like
        :meth:`signals`; call it for every event of a group before
        :meth:`observe_group`."""
        self.fanouts.advance(record.timestamp)
        return self.fanouts.is_fanout_hop(record.src_host_id, record.dst_host_id, success=bool(record.success))

    def observe_group(self, records: Iterable[FeatureRecord]) -> None:
        """Fold a scored timestamp group in. Call after scoring it, never before.

        Only a *successful* authentication reaches a destination. A failed
        logon establishes no presence there, so it is neither a reached host
        for the pivot window nor a hop for the chain rule; counting it would
        let a password-spraying account "walk" through hosts it never
        entered, and would let the failures an attacker leaves behind count
        toward the very chain that is supposed to measure movement. The
        failures are not shown to the chain tracker at all, so its novelty
        test cannot be spent by them either.
        """
        for record in records:
            if not record.success:
                continue
            self.destinations.add(record.dst_host_id, record.timestamp)
            self.chains.observe(
                record.src_user_id, record.src_host_id, record.dst_host_id, record.timestamp
            )
            self.fanouts.observe(
                record.src_user_id, record.src_host_id, record.dst_host_id, record.timestamp
            )

    def clear(self) -> None:
        self.chains.clear()
        self.destinations.clear()
        self.fanouts.clear()
