"""Each technique scenario must exhibit the behaviour its ATT&CK description names.

These are checks on the *injection*, not on any rule: a scenario that claims
to be password spraying but emits one account's failures is measuring the
wrong thing, and every recall number downstream would inherit the error.
The attribution accounting is checked separately with constructed outcomes.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.simulation.generator import generate_stream
from graphsentinel.simulation.prevention import (ATTRIBUTION_CONFIDENCE,
                                                 EntityNames, EventOutcome,
                                                 measure_prevention,
                                                 render_technique_validation,
                                                 technique_validation)
from graphsentinel.simulation.profile import CorpusProfile
from graphsentinel.simulation.techniques import (SCENARIOS, CategoryIds,
                                                 machine_account_misuse,
                                                 pass_the_hash, pass_the_ticket,
                                                 password_guessing,
                                                 password_spraying,
                                                 remote_system_discovery,
                                                 valid_account_abuse)

DAY = 86_400
IDS = CategoryIds(logon_network=1, logon_interactive=4, logon_remote_interactive=9,
                  auth_ntlm=1, auth_kerberos=3, orientation_logon=1, orientation_tgs=2,
                  orientation_tgt=4)
MACHINE_ACCOUNTS = list(range(30, 41))          # by convention in this fixture


@pytest.fixture(scope="module")
def profile() -> CorpusProfile:
    """Kerberos and NTLM users, TGT/TGS/LogOn orientations, 12 workstations."""
    rng = np.random.default_rng(1)
    rows, t = [], 0
    for event_id in range(8_000):
        t += int(rng.integers(5, 30))
        user = int(rng.integers(1, 41))
        kerberos = user % 3 != 0
        orientation = int(rng.choice([1, 2, 4])) if kerberos else 1
        rows.append({
            "event_id": event_id, "timestamp": t, "src_user_id": user, "dst_user_id": user,
            "src_host_id": 1 + user % 12, "dst_host_id": int(rng.integers(20, 320)),
            "auth_type_id": 3 if kerberos else 1, "logon_type_id": 1,
            "orientation_id": orientation, "success": 1, "label_redteam": 0,
        })
    return CorpusProfile.measure(pl.DataFrame(rows))


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(7)


def _host(profile: CorpusProfile) -> int:
    return profile.candidate_attacker_hosts()[0]


class TestScenarioBehaviour:
    def test_guessing_is_many_failures_on_one_account_then_a_success(self, profile, rng) -> None:
        s = password_guessing(profile, rng, IDS, scenario_id="g", start=5 * DAY,
                              attacker_host=_host(profile), failures=10)
        assert s.technique_id == "T1110"
        assert len({e.src_user_id for e in s.events}) == 1
        assert len({e.dst_host_id for e in s.events}) == 1
        assert [e.success for e in s.events] == [0] * 10 + [1]
        assert all(e.src_host_id == s.attacker_host_id for e in s.events)
        assert s.events[0].src_user_id not in profile.users_by_source_host.get(s.attacker_host_id, [])

    def test_spraying_touches_many_accounts_few_times_each(self, profile, rng) -> None:
        s = password_spraying(profile, rng, IDS, scenario_id="s", start=5 * DAY,
                              attacker_host=_host(profile), accounts=12)
        failures = [e for e in s.events if e.success == 0]
        per_account = {}
        for e in failures:
            per_account[e.src_user_id] = per_account.get(e.src_user_id, 0) + 1
        assert len(per_account) == 12
        assert max(per_account.values()) <= 2, "spraying stays under lockout"
        assert sum(e.success for e in s.events) == 1

    def test_discovery_reaches_many_novel_hosts_quickly(self, profile, rng) -> None:
        s = remote_system_discovery(profile, rng, IDS, scenario_id="d", start=5 * DAY,
                                    attacker_host=_host(profile), targets=20)
        assert s.technique_id == "T1087"
        assert len({e.dst_host_id for e in s.events}) == 20
        assert s.events[-1].timestamp - s.events[0].timestamp < 20 * 12
        user = s.events[0].src_user_id
        assert user in profile.users_by_source_host[s.attacker_host_id], "the foothold's own account"
        assert all(e.dst_host_id not in profile.user_destinations[user] for e in s.events)
        assert all(e.orientation_id == IDS.orientation_tgs for e in s.events)

    def test_valid_account_abuse_is_quiet_successful_and_off_hours(self, profile, rng) -> None:
        s = valid_account_abuse(profile, rng, IDS, scenario_id="v", start=5 * DAY + 40_000,
                                attacker_host=_host(profile), logons=3)
        assert s.technique_id == "T1078"
        assert all(e.success == 1 for e in s.events)
        assert all(2 <= e.hour <= 5 for e in s.events), "small hours"
        user = s.events[0].src_user_id
        assert user not in profile.users_by_source_host.get(s.attacker_host_id, [])
        assert all(e.dst_host_id not in profile.user_destinations[user] for e in s.events)

    def test_pass_the_ticket_is_service_tickets_without_authentication(self, profile, rng) -> None:
        s = pass_the_ticket(profile, rng, IDS, scenario_id="t", start=5 * DAY,
                            attacker_host=_host(profile))
        assert s.technique_id == "T1550.003"
        assert all(e.orientation_id == IDS.orientation_tgs for e in s.events)
        assert not any(e.orientation_id == IDS.orientation_tgt for e in s.events)
        user = s.events[0].src_user_id
        assert any(row[5] == IDS.orientation_tgt for row in profile.user_profiles[user]), (
            "a Kerberos account -- otherwise the missing TGT means nothing"
        )

    def test_pass_the_hash_is_ntlm_from_a_kerberos_account(self, profile, rng) -> None:
        s = pass_the_hash(profile, rng, IDS, scenario_id="h", start=5 * DAY,
                          attacker_host=_host(profile))
        assert s.technique_id == "T1550.002"
        assert all(e.auth_type_id == IDS.auth_ntlm and e.success == 1 for e in s.events)
        user = s.events[0].src_user_id
        assert any(row[3] == IDS.auth_kerberos for row in profile.user_profiles[user])

    def test_machine_account_misuse_is_an_interactive_machine_logon(self, profile, rng) -> None:
        s = machine_account_misuse(profile, rng, IDS, scenario_id="m", start=5 * DAY,
                                   attacker_host=_host(profile), machine_accounts=MACHINE_ACCOUNTS)
        assert s.technique_id == "T1078.002"
        assert s.events[0].src_user_id in MACHINE_ACCOUNTS
        assert all(e.logon_type_id in (IDS.logon_interactive, IDS.logon_remote_interactive)
                   for e in s.events)

    def test_every_scenario_is_labelled_chronological_and_from_the_foothold(self, profile) -> None:
        rng = np.random.default_rng(3)
        for technique, builders in SCENARIOS.items():
            for builder in builders:
                extra = {"machine_accounts": MACHINE_ACCOUNTS} if technique == "T1078.002" else {}
                s = builder(profile, rng, IDS, scenario_id=builder.__name__, start=6 * DAY,
                            attacker_host=_host(profile), **extra)
                assert s.technique_id == technique
                assert all(e.label_redteam == 1 for e in s.events)
                stamps = [e.timestamp for e in s.events]
                assert stamps == sorted(stamps)
                assert all(e.src_host_id == s.attacker_host_id for e in s.events)
                assert [t.technique_id for t in s.truths()] == [technique] * len(s.events)


def _outcome(event_id: int, *, expected: str | None, called: str | None, confidence: str = "high",
             alerted: bool = True) -> EventOutcome:
    return EventOutcome(event_id=event_id, timestamp=event_id, user_id=1, risk=0.5,
                        alerted=alerted, technique_id=called, confidence=confidence,
                        auto_actioned=False, recommended=(), campaign_id=None,
                        hop_index=None, expected_technique=expected)


class TestAttributionAccounting:
    def test_recall_precision_and_false_attributions(self) -> None:
        events = [
            _outcome(1, expected="T1110", called="T1110"),                 # correct
            _outcome(2, expected="T1110", called="T1021"),                 # wrong technique
            _outcome(3, expected="T1110", called=None, alerted=False),     # missed entirely
            _outcome(4, expected=None, called="T1110"),                    # benign called T1110
            _outcome(5, expected=None, called=None, alerted=False),        # benign, quiet
            _outcome(6, expected=None, called="T1110", confidence="low"),  # too weak to count
        ]
        result = technique_validation(events, ["T1110"])["T1110"]
        assert result.injected == 3
        assert result.alerted == 2
        assert result.attributed_correctly == 1
        assert result.attributed_other == 1
        assert result.false_attributions == 1, "the low-confidence call must not count"
        assert result.benign_events == 3
        assert result.precision == pytest.approx(0.5)
        assert result.attribution_recall == pytest.approx(1 / 3)
        assert result.detection_recall == pytest.approx(2 / 3)

    def test_low_confidence_attributions_are_ignored_everywhere(self) -> None:
        events = [_outcome(1, expected="T1078", called="T1078", confidence="low")]
        result = technique_validation(events, ["T1078"])["T1078"]
        assert result.attributed_correctly == 0
        assert "low" not in ATTRIBUTION_CONFIDENCE

    def test_a_technique_with_no_injections_has_zero_recall_not_an_error(self) -> None:
        result = technique_validation([_outcome(1, expected=None, called=None, alerted=False)],
                                      ["T1550.002"])["T1550.002"]
        assert result.injected == 0 and result.attribution_recall == 0.0

    def test_render_lists_every_technique(self) -> None:
        events = [_outcome(1, expected="T1110", called="T1110")]
        text = render_technique_validation(technique_validation(events, ["T1110", "T1087"]))
        assert "T1110" in text and "T1087" in text


class TestScenariosThroughTheHarness:
    def test_expected_technique_reaches_the_outcome(self, profile) -> None:
        rng = np.random.default_rng(11)
        host = _host(profile)
        scenario = password_guessing(profile, rng, IDS, scenario_id="G1", start=20 * DAY + 7_200,
                                     attacker_host=host, failures=6)
        extra = list(zip(scenario.events, scenario.truths()))
        stream = generate_stream(profile, campaigns=[], start_timestamp=20 * DAY,
                                 end_timestamp=20 * DAY + 4 * 3_600, seed=5, extra=extra)
        assert stream.attack_count == 7
        records = list(CausalFeatureEngine().transform(stream.events))
        report = measure_prevention(records, stream.truth, [], scorer=lambda g: [0.0] * len(g),
                                    names=EntityNames.anonymous())
        injected = [e for e in report.events if e.expected_technique == "T1110"]
        assert len(injected) == 7
        assert report.benign_events == stream.benign_count
