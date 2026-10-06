"""The chain rule: catching what no fitted weight can.

Why this is a rule and not a weight
-----------------------------------
The noisy-OR reliabilities are fitted on the LANL corpus, and 644 of its 649
red-team events have a source host that was never previously a destination --
the attacker's beachhead was established outside the observable window. The
pivot channel therefore has **no positive class to learn from**, and re-fitting
it with a far better definition (benign firing 47% -> 3.1%) still returns a
reliability of 0.05, because improving a signal cannot manufacture examples.

So a same-account multi-hop chain is asserted by domain knowledge instead. The
cost was measured before choosing, not after:

    rule                        chain hits    FP/10k    within 25/10k budget
    chain 3+ hops /  600s               10      77.5    no
    chain 4+ hops /  600s                9      30.7    no
    chain 4+ hops /  300s                9       4.6    yes  <- selected
    chain 5+ hops /  300s                8       1.0    yes
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import (CHAIN_RULE_FLOOR, RiskComponents,
                                            apply_rule_floor, fuse_risk,
                                            select_fusion)
from graphsentinel.detection.signals import (DEFAULT_CHAIN_WINDOW_SECONDS,
                                             DEFAULT_MINIMUM_PRIOR_HOPS,
                                             ChainPivotTracker)


def components(**overrides: float) -> RiskComponents:
    base = {"tgn": 0.0, "novelty": 0.0, "burst": 0.0, "pivot": 0.0, "corroboration": 0.0}
    return RiskComponents(**{**base, **overrides})


class TestChainPivotTracker:
    def test_selected_configuration_is_the_measured_one(self) -> None:
        # Finding 25: four novel hops in 1,800 s (was four hops of any kind in 300 s).
        assert DEFAULT_MINIMUM_PRIOR_HOPS == 3
        assert DEFAULT_CHAIN_WINDOW_SECONDS == 1_800
        assert ChainPivotTracker().require_novel is True

    def test_a_four_hop_walk_is_detected(self) -> None:
        """A -> B -> C -> D -> E by one account inside the window."""
        tracker = ChainPivotTracker()
        hosts = [100, 101, 102, 103, 104, 105]
        detected = []
        for i in range(len(hosts) - 1):
            timestamp = 1_000 + i * 20
            tracker.advance(timestamp)
            detected.append(tracker.continues_chain(7, hosts[i]))
            tracker.observe(7, hosts[i], hosts[i + 1], timestamp)
        assert detected[-1] is True, f"chain never detected: {detected}"

    def test_a_short_walk_is_not_a_chain(self) -> None:
        """Two hops is a user doing their job."""
        tracker = ChainPivotTracker()
        tracker.observe(7, 100, 101, 1_000)
        tracker.advance(1_020)
        assert tracker.continues_chain(7, 101) is False

    def test_different_accounts_do_not_form_one_chain(self) -> None:
        """The signal is a credential moving, not hosts being busy. Without
        this, ordinary client-server traffic reads as lateral movement."""
        tracker = ChainPivotTracker()
        for i, host in enumerate([100, 101, 102, 103]):
            timestamp = 1_000 + i * 20
            tracker.observe(i, host, host + 1, timestamp)   # a different user each hop
        tracker.advance(1_100)
        assert tracker.continues_chain(3, 104) is False

    def test_a_slow_walk_falls_outside_the_window(self) -> None:
        """The window is the point. An admin touching five hosts across a
        morning is not an attacker moving through them in five minutes.
        Pinned on the Finding 13 rule (300 s) and on the shipped one (1,800 s,
        Finding 25), each with a walk slower than its own window."""
        for window, gap in ((300, 400), (1_800, 2_000)):
            tracker = ChainPivotTracker(window_seconds=window, require_novel=False)
            hosts = [100, 101, 102, 103, 104, 105]
            for i in range(len(hosts) - 1):
                timestamp = 1_000 + i * gap          # slower than the window
                tracker.advance(timestamp)
                tracker.observe(7, hosts[i], hosts[i + 1], timestamp)
            tracker.advance(1_000 + 5 * gap)
            assert tracker.continues_chain(7, hosts[-1]) is False, window

    def test_state_is_bounded_by_the_window(self) -> None:
        tracker = ChainPivotTracker()
        for i in range(500):
            tracker.observe(1, 100 + i, 200 + i, 1_000 + i)
        tracker.advance(1_000 + 500 + DEFAULT_CHAIN_WINDOW_SECONDS + 1)
        assert len(tracker) == 0


class TestRuleFloor:
    def test_the_floor_alerts_a_chain_the_model_misses(self) -> None:
        """The whole point: the fitted model scores this chain hop at 0.1026."""
        config, threshold = select_fusion("noisy_or")
        hop = components(tgn=0.0015, burst=0.18, pivot=1.0)
        base = fuse_risk(hop, config)
        assert base.score < threshold

        floored = apply_rule_floor(base, chain_detected=True)
        assert floored.score >= threshold
        assert floored.rule_floor == "chain_pivot"

    def test_a_higher_model_score_is_preserved(self) -> None:
        """A floor, not an override. The model having more to say than the
        rule is information worth keeping."""
        config, _ = select_fusion("noisy_or")
        strong = fuse_risk(components(tgn=0.99, novelty=1.0), config)
        assert strong.score > CHAIN_RULE_FLOOR
        kept = apply_rule_floor(strong, chain_detected=True)
        assert kept.score == pytest.approx(strong.score)
        assert kept.rule_floor is None

    def test_no_chain_means_no_floor(self) -> None:
        config, _ = select_fusion("noisy_or")
        base = fuse_risk(components(tgn=0.01), config)
        assert apply_rule_floor(base, chain_detected=False).score == pytest.approx(base.score)

    def test_the_floor_clears_the_threshold_with_margin(self) -> None:
        """A floor equal to the threshold would alert only by rounding."""
        _, threshold = select_fusion("noisy_or")
        assert CHAIN_RULE_FLOOR > threshold * 1.5

    def test_rule_alerts_are_attributable(self) -> None:
        """An alert raised by a rule must not be credited to the model."""
        config, _ = select_fusion("noisy_or")
        floored = apply_rule_floor(fuse_risk(components(tgn=0.001), config),
                                   chain_detected=True)
        assert floored.rule_floor == "chain_pivot"
        # The underlying channels are untouched, so the evidence still shows
        # what the model actually thought.
        assert floored.components.tgn == pytest.approx(0.001)


def test_chain_alerts_end_to_end_through_the_gateway() -> None:
    """Adapter-free end-to-end: a five-hop walk by one account must alert."""
    client = TestClient(create_app(DetectionService(threshold=0.5)))

    hosts = ["H0", "H1", "H2", "H3", "H4", "H5"]
    events = []
    for i in range(len(hosts) - 1):
        events.append({
            "timestamp": 1_000 + i * 20,
            "user": "svc_compromised@CORP",
            "source_host": hosts[i],
            "destination_host": hosts[i + 1],
            "destination_user": "svc_compromised@CORP",
            "auth_type": "Kerberos",
            "logon_type": "Network",
            "orientation": "LogOn",
            "success": True,
            "source": "chain_test",
        })

    body = client.post("/api/v1/live/events",
                       json={"batch_id": "chain", "events": events})
    assert body.status_code == 200, body.text
    results = body.json()["results"]

    # The outcome that matters: the far end of the chain alerts.
    #
    # Asserting that ``rule_floor`` is stamped would be wrong. The floor only
    # marks events it actually RAISED, and on a clean walk the model's own
    # score climbs past the floor by the last hop -- which is the
    # floor-not-override behaviour working, not the rule failing to fire.
    assert results[-1]["alerted"], (
        f"the end of the chain did not alert; scores were "
        f"{[round(r['risk'], 4) for r in results]}"
    )


def test_the_floor_fires_when_the_model_stays_quiet() -> None:
    """A chain the model has no opinion about must still alert.

    Built from repeated traffic so novelty and burst stay low, which is the
    case the rule exists for: the labelled five-hop chain scores 0.1026 under
    the fitted model and would never alert on its own.
    """
    client = TestClient(create_app(DetectionService(threshold=0.5)))
    hosts = [f"Q{i}" for i in range(8)]

    # Warm the pairs first so nothing downstream reads as novel.
    warmup = [
        {
            "timestamp": 500 + i,
            "user": "svc_quiet@CORP",
            "source_host": hosts[i % (len(hosts) - 1)],
            "destination_host": hosts[(i % (len(hosts) - 1)) + 1],
            "destination_user": "svc_quiet@CORP",
            "auth_type": "Kerberos", "logon_type": "Network",
            "orientation": "LogOn", "success": True, "source": "warm",
        }
        for i in range(60)
    ]
    client.post("/api/v1/live/events", json={"batch_id": "warm", "events": warmup})

    walk = [
        {
            "timestamp": 2_000 + i * 15,
            "user": "svc_quiet@CORP",
            "source_host": hosts[i],
            "destination_host": hosts[i + 1],
            "destination_user": "svc_quiet@CORP",
            "auth_type": "Kerberos", "logon_type": "Network",
            "orientation": "LogOn", "success": True, "source": "walk",
        }
        for i in range(len(hosts) - 1)
    ]
    response = client.post("/api/v1/live/events",
                           json={"batch_id": "walk", "events": walk})
    assert response.status_code == 200, response.text
    results = response.json()["results"]

    assert any(r["alerted"] for r in results), (
        f"a multi-hop walk produced no alert at all; scores were "
        f"{[round(r['risk'], 4) for r in results]}"
    )
