"""The live console must display what the detector did, not what it should have.

Found while building the prevention harness (Finding 17): the WebSocket
broadcast behind the console overrode the risk to at least 0.92 and forced
``alerted = True`` for any user named in the synthetic ground-truth manifest.
Stored alerts and HTTP responses were untouched, so every *count* in the
project stayed honest -- but the display a reviewer actually watches showed
critical detections regardless of whether the model had fired.

These tests pin the repaired contract: the payload carries the service's own
risk, alert flag and severity, and ground truth travels as a label beside them.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest

from graphsentinel.api import main as api_main
from graphsentinel.api.main import scored_event_payload
from graphsentinel.api.product import severity_for


def _raw(user: str = "U1234@DOM1") -> SimpleNamespace:
    return SimpleNamespace(
        timestamp=1_000, user=user, source_host="C1", destination_host="C2",
        auth_type="Kerberos", logon_type="Network", success=True, source="synthetic",
    )


def _scored(risk: float, alerted: bool) -> SimpleNamespace:
    return SimpleNamespace(alert_id="a-1" if alerted else None, risk=risk,
                           alerted=alerted, dominant_signals=("tgn",))


class TestGroundTruthDoesNotChangeTheScore:
    @pytest.mark.parametrize("risk, alerted", [(0.03, False), (0.41, True), (0.97, True)])
    def test_payload_carries_the_service_risk_for_a_known_attacker(
        self, risk: float, alerted: bool
    ) -> None:
        """The exact case the override targeted: a ground-truth attacker user.
        Whatever the model said is what the console must be told."""
        payload = scored_event_payload(
            _raw(), _scored(risk, alerted), threshold=0.329,
            ground_truth_chain_id="ATK-002", score_components=None,
        )
        assert payload["risk"] == risk
        assert payload["alerted"] is alerted
        assert payload["severity"] == severity_for(risk)

    def test_a_missed_attack_is_visible_as_a_miss(self) -> None:
        """The property the override destroyed. A known attacker the model
        scored at 0.03 must show up as a low-risk, un-alerted event *labelled*
        as ground truth -- that is how a reviewer sees a miss."""
        payload = scored_event_payload(
            _raw(), _scored(0.03, False), threshold=0.329,
            ground_truth_chain_id="ATK-001", score_components=None,
        )
        assert payload["is_ground_truth_attacker"] is True
        assert payload["chain_id"] == "ATK-001"
        assert payload["severity"] == "low"
        assert payload["alerted"] is False

    def test_an_unlabelled_user_carries_no_ground_truth(self) -> None:
        payload = scored_event_payload(
            _raw(), _scored(0.9, True), threshold=0.329,
            ground_truth_chain_id=None, score_components={"tgn": 0.9},
        )
        assert payload["is_ground_truth_attacker"] is False
        assert payload["chain_id"] is None
        assert payload["scores"] == {"tgn": 0.9}

    def test_severity_uses_the_shared_banding(self) -> None:
        """One set of cut points, published at /api/v1/threshold-config. The
        old block duplicated them inline, which is how bands drift."""
        for risk in (0.0, 0.49, 0.5, 0.69, 0.7, 0.84, 0.85, 1.0):
            payload = scored_event_payload(
                _raw(), _scored(risk, risk >= 0.329), threshold=0.329,
                ground_truth_chain_id=None, score_components=None,
            )
            assert payload["severity"] == severity_for(risk)


def test_no_score_override_survives_in_the_api_module() -> None:
    """Regression guard on the pattern itself.

    A future "demo aid" that clamps the displayed risk for known attackers
    would reintroduce fabricated detections. The source is checked for the
    shape of that edit rather than for its exact text.
    """
    source = inspect.getsource(api_main)
    forbidden = ("max(risk, 0.9", "risk = max(", "alerted_flag = True")
    hits = [pattern for pattern in forbidden if pattern in source]
    assert not hits, f"score override pattern present in api.main: {hits}"
