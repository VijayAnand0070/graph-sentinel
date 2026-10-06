"""The chain rule's shape and what a detected chain may do (Finding 25)."""

from __future__ import annotations

import pytest

from graphsentinel.detection.fusion import CHAIN_RULE_FLOOR, NoisyOrConfig
from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
from graphsentinel.detection.policy import (
    ALERT_ONLY,
    DEFAULT_CHAIN_RULE,
    DEFAULT_POLICY,
    UNATTENDED,
    ChainRuleConfig,
    chain_rule_from_environment,
    policy_from_environment,
)
from graphsentinel.detection.response import plan_for
from graphsentinel.detection.signals import ExplicitSignals
from graphsentinel.detection.tactics import TacticEngine
from graphsentinel.features.causal import CausalFeatureEngine
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


class TestChainRuleConfig:
    def test_names_round_trip(self) -> None:
        for text in ("4hops-300s-any", "3hops-1800s-novel", "2hops-60s-novel"):
            assert ChainRuleConfig.parse(text).name == text

    def test_rejects_nonsense(self) -> None:
        with pytest.raises(ValueError, match="look like"):
            ChainRuleConfig.parse("three hops please")
        with pytest.raises(ValueError, match="novelty"):
            ChainRuleConfig.parse("3hops-300s-sometimes")
        with pytest.raises(ValueError, match="prior hop"):
            ChainRuleConfig(prior_hops=0)

    def test_the_default_is_the_measured_choice(self) -> None:
        assert DEFAULT_CHAIN_RULE.name == "4hops-1800s-novel"
        assert DEFAULT_POLICY is UNATTENDED and DEFAULT_POLICY.unattended

    def test_environment_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GRAPHSENTINEL_CHAIN_RULE", "4hops-300s-any")
        monkeypatch.setenv("GRAPHSENTINEL_CHAIN_RULE_POLICY", "alert_only")
        assert chain_rule_from_environment().name == "4hops-300s-any"
        assert policy_from_environment() is ALERT_ONLY
        monkeypatch.setenv("GRAPHSENTINEL_CHAIN_RULE_POLICY", "armed_and_dangerous")
        with pytest.raises(ValueError, match="GRAPHSENTINEL_CHAIN_RULE_POLICY"):
            policy_from_environment()


class TestNovelHops:
    def test_only_never_reached_destinations_count(self) -> None:
        """An account retracing a known path is not a chain under the novel
        rule; the same walk into hosts it never touched is."""
        walk = [_event(i, 5_000 + i * 20, user=7, src=100 + i, dst=101 + i) for i in range(4)]
        # The same walk, hours earlier: those pairs are then known, and the
        # window has long expired by the time the walk repeats.
        history = [_event(50 + i, 100 + i * 5, user=7, src=100 + i, dst=101 + i) for i in range(4)]
        novel = ChainRuleConfig(prior_hops=2, window_seconds=1_800, novel_only=True)
        any_hop = ChainRuleConfig(prior_hops=2, window_seconds=1_800, novel_only=False)

        def fires(rule: ChainRuleConfig, events: list[NormalizedAuthEvent]) -> list[bool]:
            engine = CausalFeatureEngine()
            tracker = rule.tracker()
            out = []
            for record in engine.transform(events):
                _signals, chain = tracker.signals(record)
                out.append(chain)
                tracker.observe_group([record])
            return out

        assert fires(novel, walk)[-1] is True
        assert fires(any_hop, walk)[-1] is True
        # The same walk after the account already used those pairs: not novel.
        assert fires(novel, history + walk)[-1] is False
        assert fires(any_hop, history + walk)[-1] is True


class TestPolicyEffects:
    def test_the_rule_asserts_lateral_movement_at_high_confidence(self) -> None:
        engine = CausalFeatureEngine()
        record = next(iter(engine.transform([_event(1, 1_000, user=7, src=100, dst=101)])))
        signals = ExplicitSignals(novelty=1.0, burst=0.0, pivot=1.0)
        tactics = TacticEngine()
        plain = tactics.classify_event(record, signals)
        asserted = tactics.classify_event(record, signals, chain_detected=True)
        assert asserted.primary is not None
        assert asserted.primary.technique_id == "T1021"
        assert asserted.confidence == "high"
        assert any("chain rule" in line for line in asserted.primary.evidence)
        assert plain.confidence != "high" or plain.primary is None or plain.primary.score < 1.0

    def test_unattended_policy_reaches_the_unattended_action(self) -> None:
        plan = plan_for("T1021", "high", risk=UNATTENDED.floor)
        assert "force_reauth" in plan.auto_executable
        plan = plan_for("T1021", "medium", risk=ALERT_ONLY.floor)
        assert "force_reauth" not in plan.auto_executable
        assert ALERT_ONLY.floor == CHAIN_RULE_FLOOR < AUTO_EXECUTE_THRESHOLD == UNATTENDED.floor

    def test_policy_dicts_carry_the_gate(self) -> None:
        assert UNATTENDED.to_dict()["execution_gate"] == AUTO_EXECUTE_THRESHOLD
        assert ALERT_ONLY.to_dict()["unattended"] is False


class TestLiveWiring:
    def test_the_engine_builds_the_tracker_and_sets_the_service_floor(self) -> None:
        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.service import DetectionService

        service = DetectionService(threshold=0.5, fusion=NoisyOrConfig())
        live = LiveDetectionEngine(
            service,
            id_map_dir=None,
            policy=UNATTENDED,
            chain_rule=ChainRuleConfig.parse("2hops-600s-any"),
        )
        assert service.chain_rule_floor == AUTO_EXECUTE_THRESHOLD
        assert live._signals.chains.window_seconds == 600
        assert live._signals.chains.minimum_prior_hops == 1
        assert service.fusion_profile()["chain_rule_floor"] == AUTO_EXECUTE_THRESHOLD

    def test_a_live_chain_is_raised_to_the_gate_and_named(self) -> None:
        from graphsentinel.api.live import LiveDetectionEngine
        from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
        from graphsentinel.api.service import DetectionService

        service = DetectionService(threshold=0.5, fusion=NoisyOrConfig())
        live = LiveDetectionEngine(
            service,
            id_map_dir=None,
            policy=UNATTENDED,
            chain_rule=ChainRuleConfig.parse("2hops-600s-novel"),
        )
        hosts = ["C1", "C2", "C3", "C4"]
        results = []
        for i in range(3):
            batch = LiveAuthBatch(
                events=[
                    LiveAuthEvent(
                        timestamp=1_000 + i * 30,
                        user="U1@DOM1",
                        source_host=hosts[i],
                        destination_host=hosts[i + 1],
                        success=True,
                        source="test",
                    )
                ]
            )
            results.extend(live.detect(batch).results)
        last = results[-1]
        assert last.rule_floor == "chain_pivot"
        assert last.risk == pytest.approx(AUTO_EXECUTE_THRESHOLD)
        assert last.tactic is not None and last.tactic.technique_id == "T1021"
        assert last.tactic.confidence == "high"


class TestCorroboratedPolicy:
    def test_the_rule_only_raises_a_chain_the_model_also_flagged(self) -> None:
        from graphsentinel.api.schemas import (
            RiskComponentInput,
            ScoreBatchRequest,
            ScoreEventRequest,
        )
        from graphsentinel.api.service import DetectionService
        from graphsentinel.detection.policy import CORROBORATED

        service = DetectionService(threshold=0.5, fusion=NoisyOrConfig())
        service.chain_rule_floor = CORROBORATED.floor
        service.chain_rule_requires_alert = CORROBORATED.requires_model_alert

        def request(event_id: int, tgn: float) -> ScoreEventRequest:
            return ScoreEventRequest(
                event_id=event_id,
                timestamp=1_000 + event_id,
                user_id=1,
                source_host_id=1,
                destination_host_id=2 + event_id,
                user="U1@DOM1",
                source_host="C1",
                destination_host=f"C{2 + event_id}",
                is_new_pair=True,
                user_fanout_5m=1,
                recent_failures=0,
                evidence_support=0.0,
                components=RiskComponentInput(
                    tgn=tgn, novelty=0.2, burst=0.0, pivot=1.0, corroboration=0.0
                ),
                tactic=None,
                chain_detected=True,
            )

        quiet = service.score_batch(ScoreBatchRequest(events=(request(1, 0.05),))).results[0]
        loud = service.score_batch(ScoreBatchRequest(events=(request(2, 0.7),))).results[0]
        assert quiet.rule_floor is None and quiet.risk < 0.5
        assert loud.rule_floor == "chain_pivot" and loud.risk == pytest.approx(CORROBORATED.floor)
        assert CORROBORATED.unattended and CORROBORATED.to_dict()["requires_model_alert"] is True
