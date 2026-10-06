"""Tactic classification: each signature fires on its own pattern and stays quiet otherwise.

The discipline these tests enforce is separation. A signature that fires on
everything is worse than no signature, because it launders noise into an
ATT&CK technique id that looks authoritative in a report.
"""

from __future__ import annotations

import pytest

from graphsentinel.detection.signals import ExplicitSignals
from graphsentinel.detection.tactics import (AUTH_KERBEROS, AUTH_NTLM,
                                             LOGON_INTERACTIVE, LOGON_NETWORK,
                                             ORIENT_LOGON, ORIENT_TGS,
                                             ORIENT_TGT, SIGNATURES,
                                             TacticContext, TacticEngine,
                                             classify, describe_validation)
from graphsentinel.features.causal import FeatureRecord

BENIGN_DEFAULTS: dict[str, object] = {
    "event_id": 1,
    "timestamp": 1_000_000,
    "day": 11,
    "src_user_id": 42,
    "dst_user_id": 42,
    "src_host_id": 100,
    "dst_host_id": 200,
    "auth_type_id": AUTH_KERBEROS,
    "logon_type_id": LOGON_NETWORK,
    "orientation_id": ORIENT_LOGON,
    "success": 1,
    "label_redteam": 0,
    "hour_sin": 0.5,
    "hour_cos": 0.5,
    "delta_user_log": 3.0,
    "delta_pair_log": 3.0,
    "user_seen_before": 1,
    "pair_seen_before": 1,
    "is_new_pair": 0,
    "pair_frequency_1h": 12,
    "pair_rarity": 0.1,
    "user_unique_dst_5m": 1,
    "user_unique_dst_1h": 2,
    "user_unique_dst_24h": 20,
    "user_auth_rate_5m": 1,
    "user_failure_rate_15m": 0.0,
    "failures_before_success_15m": 0,
    "user_new_dst_ratio_1h": 0.0,
    "src_host_unique_dst_1h": 1,
    "dst_inbound_users_1h": 8,
    "destination_novelty": 0.1,
    "user_historical_degree": 30,
    "src_host_historical_degree": 25,
    "dst_historical_degree": 40,
    "rare_logon_score": 0.1,
}

QUIET_SIGNALS = ExplicitSignals(novelty=0.0, burst=0.05, pivot=0.0)


def record(**overrides: object) -> FeatureRecord:
    return FeatureRecord(**{**BENIGN_DEFAULTS, **overrides})


def context(
    *,
    signals: ExplicitSignals = QUIET_SIGNALS,
    user_name: str = "U42@DOM1",
    seconds_since_tgt: float | None = 600.0,
    kerberos_share: float = 0.9,
    tgt_coverage: float = 0.9,
    logon_type_name: str = "Network",
    auth_type_name: str = "Kerberos",
    orientation_name: str = "LogOn",
    **overrides: object,
) -> TacticContext:
    return TacticContext(
        record=record(**overrides),
        signals=signals,
        user_name=user_name,
        seconds_since_tgt=seconds_since_tgt,
        kerberos_share=kerberos_share,
        tgt_coverage=tgt_coverage,
        logon_type_name=logon_type_name,
        auth_type_name=auth_type_name,
        orientation_name=orientation_name,
    )


def score_for(result, technique_id: str) -> float:
    for item in result.scores:
        if item.technique_id == technique_id:
            return item.score
    return 0.0


def test_ordinary_traffic_triggers_nothing() -> None:
    """The baseline event must be silent, or every other test proves nothing."""
    result = classify(context())
    assert result.primary is None
    assert result.scores == ()
    assert result.confidence == "none"


def test_fanout_is_classified_as_lateral_movement() -> None:
    """Fan-out carries the signature; see _score_lateral_movement for why.

    Measured over the corpus, source-host fan-out separates attacks from
    benign traffic (benign p99 = 6 destinations/source-hour, attack median
    = 11) while pivot does not.
    """
    result = classify(
        context(
            signals=ExplicitSignals(novelty=1.0, burst=0.3, pivot=1.0),
            src_host_unique_dst_1h=14,
            is_new_pair=1,
            dst_historical_degree=2,
        )
    )
    assert result.primary is not None
    assert result.primary.technique_id == "T1021"
    assert result.confidence == "high"
    assert any("distinct destinations" in item for item in result.primary.evidence)


def test_pivot_alone_is_not_lateral_movement() -> None:
    """The regression this signature was rewritten to fix.

    A windowed pivot still fires on 47% of benign traffic and on none of the
    649 labelled attacks, so pivot without fan-out must not produce a
    classification -- it previously labelled a quarter of the estate.
    """
    result = classify(
        context(
            signals=ExplicitSignals(novelty=1.0, burst=0.3, pivot=1.0),
            src_host_unique_dst_1h=1,
            is_new_pair=1,
            dst_historical_degree=2,
        )
    )
    assert score_for(result, "T1021") == 0.0


def test_fanout_below_the_benign_ceiling_is_not_lateral_movement() -> None:
    """Benign traffic reaches 6 destinations per source-hour at p99."""
    assert score_for(classify(context(src_host_unique_dst_1h=3)), "T1021") == 0.0


def test_failures_then_success_is_brute_force_not_valid_account_abuse() -> None:
    """The two techniques share 'a success' and must be separated by what preceded it."""
    result = classify(
        context(
            is_new_pair=1,
            user_failure_rate_15m=2.5,
            failures_before_success_15m=6,
        )
    )
    assert result.primary is not None
    assert result.primary.technique_id == "T1110"
    # Guessing happened, so this is explicitly NOT valid-account abuse.
    assert score_for(result, "T1078") == 0.0


def test_first_try_success_on_new_pair_is_valid_account_abuse() -> None:
    result = classify(
        context(
            is_new_pair=1,
            failures_before_success_15m=0,
            user_failure_rate_15m=0.0,
            rare_logon_score=0.9,
            destination_novelty=0.9,
        )
    )
    assert score_for(result, "T1078") > 0.5
    assert score_for(result, "T1110") == 0.0


def test_wide_fanout_is_discovery() -> None:
    result = classify(
        context(
            user_unique_dst_5m=18,
            user_unique_dst_24h=20,
            user_new_dst_ratio_1h=0.9,
            user_auth_rate_5m=15,
        )
    )
    assert result.primary is not None
    assert result.primary.technique_id == "T1087"


def test_busy_admin_is_not_discovery() -> None:
    """A large 24h baseline must absorb a burst that would flag a quiet account.

    Without the ratio clause every administrator is a permanent false positive,
    which is the most common way a discovery rule gets switched off in practice.
    """
    busy = classify(context(user_unique_dst_5m=8, user_unique_dst_24h=400))
    quiet = classify(context(user_unique_dst_5m=8, user_unique_dst_24h=9))
    assert score_for(busy, "T1087") < score_for(quiet, "T1087")


def test_service_ticket_without_tgt_is_kerberos_abuse() -> None:
    """Only where TGTs are reliably logged -- hence the explicit coverage."""
    result = classify(
        context(
            orientation_name="TGS",
            seconds_since_tgt=None,
            is_new_pair=1,
            tgt_coverage=0.9,
        )
    )
    assert score_for(result, "T1550.003") > 0.5
    assert any("no prior TGT" in item for item in result.scores[0].evidence)


def test_missing_tgt_is_ignored_when_tgts_are_not_reliably_logged() -> None:
    """Absence of evidence is only evidence of absence when it would be visible.

    Measured on the corpus, 72.6% of the 16,334 accounts that request service
    tickets have no observed TGT at all -- issued before the capture window or
    simply not recorded. Firing on that measured a logging gap and accounted
    for 8.5% of benign traffic.
    """
    result = classify(
        context(
            orientation_name="TGS",
            seconds_since_tgt=None,
            is_new_pair=1,
            tgt_coverage=0.1,
        )
    )
    assert score_for(result, "T1550.003") == 0.0


def test_service_ticket_with_recent_tgt_is_clean() -> None:
    result = classify(context(orientation_name="TGS", seconds_since_tgt=300.0))
    assert score_for(result, "T1550.003") == 0.0


def test_machine_account_interactive_logon_is_misuse() -> None:
    result = classify(
        context(user_name="C1234$@DOM1", logon_type_name="Interactive")
    )
    assert score_for(result, "T1078.002") > 0.5


def test_human_account_interactive_logon_is_clean() -> None:
    result = classify(context(user_name="U42@DOM1", logon_type_name="Interactive"))
    assert score_for(result, "T1078.002") == 0.0


def test_ntlm_only_fires_in_a_kerberos_estate() -> None:
    """NTLM is unremarkable where NTLM is normal; the estate share must gate it."""
    kerberos_estate = classify(
        context(auth_type_name="NTLM", kerberos_share=0.95, is_new_pair=1)
    )
    ntlm_estate = classify(
        context(auth_type_name="NTLM", kerberos_share=0.2, is_new_pair=1)
    )
    assert score_for(kerberos_estate, "T1550.002") > 0.4
    assert score_for(ntlm_estate, "T1550.002") == 0.0


def test_scores_are_deterministic_and_ordered() -> None:
    ctx = context(
        signals=ExplicitSignals(novelty=1.0, burst=0.8, pivot=1.0),
        is_new_pair=1,
        user_unique_dst_5m=14,
        user_unique_dst_24h=16,
        user_new_dst_ratio_1h=0.8,
    )
    first, second = classify(ctx), classify(ctx)
    assert [s.to_dict() for s in first.scores] == [s.to_dict() for s in second.scores]
    assert all(
        first.scores[i].score >= first.scores[i + 1].score
        for i in range(len(first.scores) - 1)
    )


def test_ambiguous_evidence_is_not_reported_as_high_confidence() -> None:
    """Two techniques within the decisive margin must not yield 'high'."""
    result = classify(
        context(
            signals=ExplicitSignals(novelty=1.0, burst=0.6, pivot=1.0),
            is_new_pair=1,
            user_unique_dst_5m=16,
            user_unique_dst_24h=18,
            user_new_dst_ratio_1h=0.85,
            dst_historical_degree=2,
        )
    )
    assert result.primary is not None
    if len(result.scores) > 1:
        margin = result.scores[0].score - result.scores[1].score
        if margin < 0.15:
            assert result.confidence != "high"


def test_every_reported_score_carries_evidence() -> None:
    """A technique id with no stated reason is an unfalsifiable claim."""
    result = classify(
        context(
            signals=ExplicitSignals(novelty=1.0, burst=0.9, pivot=1.0),
            user_name="C99$@DOM1",
            auth_type_name="NTLM",
            logon_type_name="Interactive",
            is_new_pair=1,
            user_failure_rate_15m=2.0,
            failures_before_success_15m=4,
            user_unique_dst_5m=12,
            user_unique_dst_24h=14,
        )
    )
    assert result.scores
    for item in result.scores:
        assert item.evidence, f"{item.technique_id} reported a score with no evidence"


class TestTacticEngine:
    def test_tgt_is_tracked_per_user(self) -> None:
        engine = TacticEngine()
        engine.observe(record(orientation_id=ORIENT_TGT, timestamp=1_000, src_user_id=7))
        ctx = engine.context(
            record(orientation_id=ORIENT_TGS, timestamp=1_600, src_user_id=7),
            QUIET_SIGNALS,
        )
        assert ctx.seconds_since_tgt == 600.0
        # A different account has no TGT of its own, which is the anomaly.
        other = engine.context(
            record(orientation_id=ORIENT_TGS, timestamp=1_600, src_user_id=8),
            QUIET_SIGNALS,
        )
        assert other.seconds_since_tgt is None

    def test_kerberos_share_reflects_observed_traffic(self) -> None:
        engine = TacticEngine()
        assert engine.kerberos_share() == 0.0
        for _ in range(9):
            engine.observe(record(auth_type_id=AUTH_KERBEROS))
        engine.observe(record(auth_type_id=AUTH_NTLM))
        assert engine.kerberos_share() == pytest.approx(0.9)

    def test_rolling_window_evicts_old_observations(self) -> None:
        engine = TacticEngine(auth_window=10)
        for _ in range(10):
            engine.observe(record(auth_type_id=AUTH_KERBEROS))
        assert engine.kerberos_share() == pytest.approx(1.0)
        for _ in range(10):
            engine.observe(record(auth_type_id=AUTH_NTLM))
        assert engine.kerberos_share() == pytest.approx(0.0)

    def test_classify_event_does_not_mutate_state(self) -> None:
        """Classification must be side-effect free so a failed request cannot
        leave the engine half-updated."""
        engine = TacticEngine()
        engine.observe(record(auth_type_id=AUTH_KERBEROS))
        before = engine.kerberos_share()
        engine.classify_event(record(auth_type_id=AUTH_NTLM), QUIET_SIGNALS)
        assert engine.kerberos_share() == before

    def test_reset_clears_everything(self) -> None:
        engine = TacticEngine()
        engine.observe(record(orientation_id=ORIENT_TGT, src_user_id=3))
        engine.observe(record(auth_type_id=AUTH_KERBEROS))
        engine.reset()
        assert engine.kerberos_share() == 0.0
        ctx = engine.context(record(src_user_id=3), QUIET_SIGNALS)
        assert ctx.seconds_since_tgt is None


def test_validation_status_names_the_unvalidated_techniques() -> None:
    """The honest-reporting contract: only T1021 has real labels behind it."""
    status = describe_validation()
    assert status["validated_against_labels"] == ["T1021"]
    assert len(status["synthetic_validation_only"]) == len(SIGNATURES) - 1
    assert "no per-class precision" in status["note"].lower()


class TestDictionaryIndependence:
    """Rules must key on category NAMES, never on entity-dictionary indices.

    The frozen LANL dictionary puts "Interactive" at index 4; a dictionary
    built from a customer's own logs assigns ids in order of first appearance
    and lands on 2. Rules comparing ``record.logon_type_id`` to a module
    constant were therefore correct for exactly one deployment and silently
    inert everywhere else -- with every test written against the LANL
    constants still passing. Caught only by an end-to-end run against a
    dictionary that was not LANL's.
    """

    def test_machine_account_rule_ignores_the_id_field(self) -> None:
        """Deliberately contradictory: the NAME says Interactive, the id says
        Network. The name must win, because the id is dictionary-specific."""
        result = classify(
            context(
                user_name="C1234$@DOM1",
                logon_type_name="Interactive",
                logon_type_id=LOGON_NETWORK,       # a different dictionary's index
            )
        )
        assert score_for(result, "T1078.002") > 0.5

    def test_machine_account_rule_does_not_fire_on_the_id_alone(self) -> None:
        result = classify(
            context(
                user_name="C1234$@DOM1",
                logon_type_name="Network",
                logon_type_id=LOGON_INTERACTIVE,   # LANL's index for Interactive
            )
        )
        assert score_for(result, "T1078.002") == 0.0

    def test_kerberos_rule_keys_on_the_orientation_name(self) -> None:
        by_name = classify(
            context(orientation_name="TGS", seconds_since_tgt=None,
                    orientation_id=ORIENT_LOGON, tgt_coverage=0.9)
        )
        by_id_only = classify(
            context(orientation_name="LogOn", seconds_since_tgt=None,
                    orientation_id=ORIENT_TGS, tgt_coverage=0.9)
        )
        assert score_for(by_name, "T1550.003") > 0.5
        assert score_for(by_id_only, "T1550.003") == 0.0

    def test_an_unresolved_category_never_satisfies_a_rule(self) -> None:
        """Fail closed. An unknown category must not match by accident."""
        result = classify(
            context(user_name="C1234$@DOM1", logon_type_name="",
                    logon_type_id=LOGON_INTERACTIVE)
        )
        assert score_for(result, "T1078.002") == 0.0
