"""The fan-out rule: one host reaching new hosts with several accounts."""

from __future__ import annotations

from graphsentinel.detection.signals import FanOutTracker


def _moves(tracker: FanOutTracker, moves: list[tuple[int, int, int, int, bool]]) -> list[bool]:
    """(t, user, src, dst, success) in time order; returns the rule per move."""
    fired = []
    for t, user, src, dst, success in moves:
        tracker.advance(t)
        fired.append(tracker.is_fanout_hop(src, dst, success=success))
        if success:
            tracker.observe(user, src, dst, t)
    return fired


def test_fires_on_the_move_after_enough_accounts_and_novel_moves() -> None:
    tracker = FanOutTracker(window_seconds=3_600, minimum_accounts=3, minimum_novel_moves=3)
    fired = _moves(tracker, [(10, 1, 100, 1, True), (20, 2, 100, 2, True), (30, 3, 100, 3, True), (40, 4, 100, 4, True)])
    assert fired == [False, False, False, True]


def test_one_account_is_not_a_fan_out() -> None:
    tracker = FanOutTracker(minimum_accounts=3, minimum_novel_moves=3)
    fired = _moves(tracker, [(t, 1, 100, t, True) for t in range(1, 20)])
    assert not any(fired)


def test_failed_attempts_neither_reach_nor_count() -> None:
    tracker = FanOutTracker(minimum_accounts=2, minimum_novel_moves=2)
    fired = _moves(
        tracker,
        [(1, 1, 100, 1, False), (2, 2, 100, 2, False), (3, 3, 100, 3, False),  # spraying: nothing reached
         (4, 1, 100, 1, True), (5, 2, 100, 2, True), (6, 3, 100, 3, True)],
    )
    # host 1 was only attempted before, so the first success to it is still novel;
    # the rule needs two prior novel successful moves by two accounts
    assert fired == [False, False, False, False, False, True]


def test_revisiting_a_reached_host_is_not_a_hop() -> None:
    tracker = FanOutTracker(minimum_accounts=2, minimum_novel_moves=2)
    fired = _moves(tracker, [(1, 1, 100, 1, True), (2, 2, 100, 2, True), (3, 3, 100, 1, True), (4, 3, 100, 3, True)])
    assert fired == [False, False, False, True]


def test_moves_age_out_of_the_window() -> None:
    tracker = FanOutTracker(window_seconds=100, minimum_accounts=2, minimum_novel_moves=2)
    fired = _moves(tracker, [(1, 1, 100, 1, True), (2, 2, 100, 2, True), (200, 3, 100, 3, True), (201, 4, 100, 4, True)])
    assert fired == [False, False, False, False]


def test_a_host_that_is_always_a_hub_is_not_a_beachhead() -> None:
    """Day 1: a hub reaches many hosts with many accounts (its normal); day 2 the
    same pattern is not a fan-out. A workstation doing it for the first time is."""
    tracker = FanOutTracker(window_seconds=3_600, minimum_accounts=3, minimum_novel_moves=3, baseline_limit=2)
    day1 = [(100 + k, k, 500, 1_000 + k, True) for k in range(20)]  # hub 500, day 0
    _moves(tracker, day1)
    day2 = [(86_400 + 100 + k, k, 500, 2_000 + k, True) for k in range(10)]
    assert not any(_moves(tracker, day2))
    workstation = [(86_400 + 5_000 + k, k, 700, 3_000 + k, True) for k in range(6)]
    assert _moves(tracker, workstation)[3:] == [True, True, True]
    assert tracker.baseline(500) >= 3 and tracker.baseline(700) == 0.0
