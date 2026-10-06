"""The prevention instrument must count correctly before it measures anything.

Every test here drives the harness with a stub scorer, so what is checked is
the accounting -- detection latency in hops, prevented hops under each
semantics, benign cost -- not any model. A harness that miscounts by one hop
would shift every prevention number in the study, silently.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.simulation.campaigns import FAMILIES, plan_campaign
from graphsentinel.simulation.generator import generate_benign, generate_stream
from graphsentinel.simulation.prevention import (
    CampaignOutcome,
    EntityNames,
    EventOutcome,
    measure_prevention,
    render_prevention,
)
from graphsentinel.simulation.profile import CorpusProfile

DAY = 86_400


@pytest.fixture(scope="module")
def frame() -> pl.DataFrame:
    """A small benign corpus: 40 users on 12 hosts, business-hours heavy."""
    rng = np.random.default_rng(0)
    rows = []
    t = 0
    for event_id in range(6_000):
        t += int(rng.integers(5, 40))
        user = int(rng.integers(1, 41))
        src = 1 + (user % 12)                       # each user has a home host
        dst = int(rng.integers(20, 60))             # servers 20..59
        hour_ok = 8 <= (t % DAY) // 3_600 <= 18 or rng.random() < 0.15
        if not hour_ok:
            continue
        rows.append({
            "event_id": event_id, "timestamp": t, "src_user_id": user, "dst_user_id": user,
            "src_host_id": src, "dst_host_id": dst, "auth_type_id": 3, "logon_type_id": 1,
            "orientation_id": 1, "success": 1, "label_redteam": 0,
        })
    return pl.DataFrame(rows)


@pytest.fixture(scope="module")
def profile(frame: pl.DataFrame) -> CorpusProfile:
    return CorpusProfile.measure(frame)


class TestProfile:
    def test_hour_weights_reflect_the_measured_day(self, profile: CorpusProfile) -> None:
        assert len(profile.hour_weights) == 24
        assert max(profile.hour_weights) == 1.0
        assert profile.hour_weights[12] > profile.hour_weights[3]

    def test_every_profiled_user_has_behaviour_to_resample(self, profile: CorpusProfile) -> None:
        assert profile.user_profiles
        assert all(profile.user_profiles[u] for u in profile.user_profiles)
        assert 0 not in profile.user_profiles

    def test_candidate_attacker_hosts_are_ordinary_and_populated(self, profile: CorpusProfile) -> None:
        hosts = profile.candidate_attacker_hosts()
        assert hosts
        for host in hosts:
            assert profile.users_by_source_host[host], "an attacker host needs accounts to harvest"

    def test_an_empty_corpus_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="no benign"):
            CorpusProfile.measure(pl.DataFrame({"label_redteam": [1], "timestamp": [1],
                                                "event_id": [1], "src_user_id": [1]}))


class TestCampaignPlanning:
    def test_fanout_keeps_one_source_and_spreads_to_novel_destinations(self, profile) -> None:
        spec = plan_campaign(profile, np.random.default_rng(1), campaign_id="F1",
                             family="fanout", hops=6, interval_seconds=60, start_timestamp=10 * DAY)
        assert {h.src_host_id for h in spec.hops} == {spec.attacker_host_id}
        destinations = [h.dst_host_id for h in spec.hops]
        assert len(set(destinations)) == 6, "each hop reaches a different host"
        for hop in spec.hops:
            assert hop.dst_host_id not in profile.user_destinations.get(hop.src_user_id, set()), (
                "the credential's owner must never have gone there"
            )
        assert [h.timestamp for h in spec.hops] == [10 * DAY + 60 * i for i in range(6)]

    def test_campaigns_sharing_a_credential_do_not_share_destinations(self, profile) -> None:
        """The chain rule's novelty is cumulative, so a stream that compromises
        the same account twice must send it somewhere new both times."""
        reserved: dict[int, set[int]] = {}
        first = plan_campaign(profile, np.random.default_rng(11), campaign_id="C1",
                              family="chain", hops=3, interval_seconds=30,
                              start_timestamp=10 * DAY, reserved=reserved)
        account = first.hops[0].src_user_id
        assert reserved[account] == {h.dst_host_id for h in first.hops}
        # Keep compromising the same workstation until the same account is
        # picked again; every hop of every campaign stays novel for its account.
        seen: dict[int, list[int]] = {account: [h.dst_host_id for h in first.hops]}
        again = None
        for seed in range(12, 40):
            spec = plan_campaign(profile, np.random.default_rng(seed), campaign_id=f"C{seed}",
                                 family="chain", hops=2, interval_seconds=30,
                                 start_timestamp=11 * DAY, attacker_host_id=first.attacker_host_id,
                                 reserved=reserved)
            for hop in spec.hops:
                seen.setdefault(hop.src_user_id, []).append(hop.dst_host_id)
            if spec.hops[0].src_user_id == account:
                again = spec
                break
        assert again is not None, "the workstation's accounts should recur within 28 tries"
        assert not ({h.dst_host_id for h in first.hops} & {h.dst_host_id for h in again.hops})
        for user, destinations in seen.items():
            assert len(destinations) == len(set(destinations)), user

    def test_chain_pivots_through_each_destination_under_one_account(self, profile) -> None:
        spec = plan_campaign(profile, np.random.default_rng(2), campaign_id="C1",
                             family="chain", hops=5, interval_seconds=30, start_timestamp=10 * DAY)
        assert len({h.src_user_id for h in spec.hops}) == 1
        assert spec.hops[0].src_host_id == spec.attacker_host_id
        for previous, current in zip(spec.hops, spec.hops[1:], strict=False):
            assert current.src_host_id == previous.dst_host_id

    def test_attacker_host_has_benign_history(self, profile) -> None:
        """The property Finding 14 says the real corpus lacks."""
        for family in FAMILIES:
            spec = plan_campaign(profile, np.random.default_rng(3), campaign_id="X",
                                 family=family, hops=3, interval_seconds=60, start_timestamp=DAY)
            assert profile.source_host_counts[spec.attacker_host_id] > 0

    @pytest.mark.parametrize("bad", [dict(hops=0), dict(interval_seconds=0), dict(family="worm")])
    def test_invalid_specs_are_rejected(self, profile, bad) -> None:
        params = dict(campaign_id="B", family="chain", hops=3, interval_seconds=60,
                      start_timestamp=DAY)
        params.update(bad)
        with pytest.raises(ValueError):
            plan_campaign(profile, np.random.default_rng(0), **params)


class TestGenerator:
    def test_benign_rate_tracks_the_measurement(self, profile) -> None:
        events = generate_benign(profile, np.random.default_rng(4),
                                 start_timestamp=20 * DAY, end_timestamp=22 * DAY)
        expected = profile.events_per_second * 2 * DAY
        assert 0.5 * expected < len(events) < 1.6 * expected
        assert all(e.label_redteam == 0 for e in events)

    def test_stream_is_chronological_with_contiguous_ids_and_exact_truth(self, profile) -> None:
        rng = np.random.default_rng(5)
        specs = [
            plan_campaign(profile, rng, campaign_id="F1", family="fanout", hops=4,
                          interval_seconds=120, start_timestamp=20 * DAY + 3_600),
            plan_campaign(profile, rng, campaign_id="C1", family="chain", hops=3,
                          interval_seconds=45, start_timestamp=20 * DAY + 7_200),
        ]
        stream = generate_stream(profile, campaigns=specs, start_timestamp=20 * DAY,
                                 end_timestamp=21 * DAY, seed=7)
        ids = [e.event_id for e in stream.events]
        assert ids == list(range(1, len(ids) + 1))
        stamps = [e.timestamp for e in stream.events]
        assert stamps == sorted(stamps)
        assert stream.attack_count == 7
        assert stream.benign_count == len(stream.events) - 7
        labelled = {e.event_id for e in stream.events if e.label_redteam == 1}
        assert labelled == set(stream.truth)
        assert {t.campaign_id for t in stream.truth.values()} == {"F1", "C1"}

    def test_a_campaign_outside_the_window_is_rejected(self, profile) -> None:
        spec = plan_campaign(profile, np.random.default_rng(6), campaign_id="L",
                             family="chain", hops=3, interval_seconds=60, start_timestamp=5 * DAY)
        with pytest.raises(ValueError, match="outside"):
            generate_stream(profile, campaigns=[spec], start_timestamp=20 * DAY,
                            end_timestamp=21 * DAY, seed=1)


def _outcome(hop: int, *, alerted: bool, auto: bool, user: int = 1) -> EventOutcome:
    return EventOutcome(event_id=hop, timestamp=hop, user_id=user, risk=0.9 if alerted else 0.0,
                        alerted=alerted, technique_id="T1021", confidence="high",
                        auto_actioned=auto, recommended=(), campaign_id="C", hop_index=hop)


class TestCampaignAccounting:
    def test_the_loop_counts_what_escalation_buys_when_the_kill_fails(self) -> None:
        """Eight hops; the kill fires at hop 2 and again qualifies at hop 4.
        A kill that works stops the campaign at 2 (5 hops prevented); one
        that fails leaves the attacker moving until the escalation at 4
        (3 prevented) -- or, without escalation, nothing."""
        c = CampaignOutcome("C", "chain", 60, 8)
        c.hops = [_outcome(i, alerted=i >= 2, auto=i in (2, 4, 6)) for i in range(8)]
        assert c.hops_prevented("campaign") == 5
        assert c.hops_prevented_with_loop(kill_effectiveness=1.0, escalation=False) == 5
        assert c.hops_prevented_with_loop(kill_effectiveness=1.0, escalation=True) == 5
        assert c.hops_prevented_with_loop(kill_effectiveness=0.0, escalation=False) == 0
        assert c.hops_prevented_with_loop(kill_effectiveness=0.0, escalation=True) == 3
        # Outside the escalation window the second detection does not count.
        assert c.hops_prevented_with_loop(
            kill_effectiveness=0.0, escalation=True, escalation_window_seconds=1
        ) == 0
        # The draw is deterministic per campaign and seed.
        a = c.hops_prevented_with_loop(kill_effectiveness=0.5, escalation=True, seed=1)
        assert a == c.hops_prevented_with_loop(kill_effectiveness=0.5, escalation=True, seed=1)
        assert a in (3, 5)
        with pytest.raises(ValueError):
            c.hops_prevented_with_loop(kill_effectiveness=1.5, escalation=True)

    def test_latency_is_the_first_alerted_hop(self) -> None:
        c = CampaignOutcome("C", "chain", 60, 5)
        c.hops = [_outcome(0, alerted=False, auto=False), _outcome(1, alerted=False, auto=False),
                  _outcome(2, alerted=True, auto=False), _outcome(3, alerted=True, auto=True),
                  _outcome(4, alerted=True, auto=True)]
        assert c.detected and c.first_alert_hop == 2
        assert c.first_auto_action_hop == 3
        assert c.alerted_hops == 3

    def test_campaign_semantics_stop_everything_after_the_first_action(self) -> None:
        c = CampaignOutcome("C", "chain", 60, 6)
        c.hops = [_outcome(i, alerted=i >= 2, auto=i >= 2) for i in range(6)]
        assert c.hops_prevented("campaign") == 3          # hops 3, 4, 5

    def test_account_semantics_stop_only_the_actioned_credential(self) -> None:
        """A fan-out rotating two credentials: acting on one leaves the other."""
        c = CampaignOutcome("F", "fanout", 60, 6)
        c.hops = [_outcome(i, alerted=i >= 1, auto=i == 1, user=i % 2) for i in range(6)]
        # Action at hop 1 on user 1; user 1's later hops are 3 and 5.
        assert c.hops_prevented("account") == 2
        assert c.hops_prevented("campaign") == 4

    def test_an_undetected_campaign_prevents_nothing(self) -> None:
        c = CampaignOutcome("N", "chain", 60, 4)
        c.hops = [_outcome(i, alerted=False, auto=False) for i in range(4)]
        assert not c.detected
        assert c.first_alert_hop is None
        assert c.hops_prevented("campaign") == 0 == c.hops_prevented("account")

    def test_unknown_semantics_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="semantics"):
            CampaignOutcome("C", "chain", 60, 1).hops_prevented("hopeful")


class TestHarnessEndToEnd:
    """Real feature engine, real fusion, real rules; only the TGN is stubbed."""

    @pytest.fixture
    def scored_stream(self, profile):
        rng = np.random.default_rng(8)
        specs = [
            plan_campaign(profile, rng, campaign_id="C1", family="chain", hops=5,
                          interval_seconds=60, start_timestamp=20 * DAY + 3 * 3_600),
            plan_campaign(profile, rng, campaign_id="F1", family="fanout", hops=5,
                          interval_seconds=60, start_timestamp=20 * DAY + 5 * 3_600),
        ]
        stream = generate_stream(profile, campaigns=specs, start_timestamp=20 * DAY,
                                 end_timestamp=20 * DAY + 8 * 3_600, seed=9)
        records = list(CausalFeatureEngine().transform(stream.events))
        return stream, records

    def test_a_scorer_that_fires_from_hop_two_gives_latency_two(self, scored_stream) -> None:
        stream, records = scored_stream

        def scorer(group):
            return [1.0 if (t := stream.truth.get(r.event_id)) and t.hop_index >= 2 else 0.0
                    for r in group]

        report = measure_prevention(records, stream.truth, stream.campaigns, scorer=scorer,
                                    names=EntityNames.anonymous(), operating_point="tgn_only")
        for campaign in report.campaigns:
            assert campaign.detected
            assert campaign.first_alert_hop == 2
            assert campaign.alerted_hops == 3
        assert report.benign_alerted == 0
        assert report.benign_auto_actioned == 0

    def test_a_blind_scorer_leaves_only_the_chain_rule(self, scored_stream) -> None:
        """With the model contributing nothing, the deterministic chain rule
        (Finding 13) must still catch the same-account pivot, and the fan-out,
        which the rule does not describe, must go undetected. This is the
        harness proving it composes the rule floor, not just the model.

        The rule counts *pivot links* -- events whose source is a host the
        account already reached -- and the campaign's first event is an entry,
        not a link. Three links precede the fifth event, so the rule fires at
        hop index 4: the attacker's fifth move. That latency is itself a
        finding, and this pins it.
        """
        from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
        from graphsentinel.detection.policy import ALERT_ONLY, ChainRuleConfig

        stream, records = scored_stream
        shipped_until_finding_25 = ChainRuleConfig(prior_hops=3, window_seconds=300)
        report = measure_prevention(records, stream.truth, stream.campaigns,
                                    scorer=lambda group: [0.0] * len(group),
                                    names=EntityNames.anonymous(), operating_point="tgn_only",
                                    chain_rule=shipped_until_finding_25, policy=ALERT_ONLY)
        by_id = {c.campaign_id: c for c in report.campaigns}
        assert by_id["C1"].detected and by_id["C1"].first_alert_hop == 4
        assert by_id["C1"].max_risk == pytest.approx(0.60)       # the rule floor, exactly
        assert not by_id["F1"].detected
        assert report.benign_alerted == 0

        # The shipped configuration since Finding 25: four novel hops in
        # 1,800 s, allowed to trigger the unattended action -- the chain is
        # caught at the same move and raised to the execution gate.
        report = measure_prevention(records, stream.truth, stream.campaigns,
                                    scorer=lambda group: [0.0] * len(group),
                                    names=EntityNames.anonymous(), operating_point="tgn_only")
        by_id = {c.campaign_id: c for c in report.campaigns}
        assert by_id["C1"].detected and by_id["C1"].first_alert_hop == 4
        assert by_id["C1"].max_risk == pytest.approx(AUTO_EXECUTE_THRESHOLD)
        assert any(h.auto_actioned for h in by_id["C1"].hops)
        assert not by_id["F1"].detected
        assert report.benign_alerted == 0

    def test_benign_cost_is_counted_against_benign_events_only(self, scored_stream) -> None:
        stream, records = scored_stream
        report = measure_prevention(records, stream.truth, stream.campaigns,
                                    scorer=lambda group: [1.0] * len(group),
                                    names=EntityNames.anonymous(), operating_point="tgn_only")
        assert report.benign_events == stream.benign_count
        assert report.benign_alerted == stream.benign_count
        assert report.detection_rate() == 1.0
        assert all(c.first_alert_hop == 0 for c in report.campaigns)

    def test_truth_and_records_must_agree(self, scored_stream) -> None:
        stream, records = scored_stream
        truncated = [r for r in records if r.event_id not in stream.truth or
                     stream.truth[r.event_id].hop_index != 0]
        with pytest.raises(ValueError, match="disagree"):
            measure_prevention(truncated, stream.truth, stream.campaigns,
                               scorer=lambda g: [0.0] * len(g),
                               names=EntityNames.anonymous())

    def test_report_serialises_and_renders(self, scored_stream) -> None:
        stream, records = scored_stream
        report = measure_prevention(records, stream.truth, stream.campaigns,
                                    scorer=lambda group: [0.0] * len(group),
                                    names=EntityNames.anonymous())
        payload = report.to_dict()
        assert set(payload["by_family"]) == {"chain", "fanout"}
        assert "60" in payload["by_interval"]
        text = render_prevention(report)
        assert "Evasion curve" in text and "Benign cost" in text
