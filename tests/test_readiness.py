"""Readiness must name degradation rather than hide it.

The measured reason: a cold deployment scores at 46% of its achievable PR-AUC
while ROC-AUC moves only 0.9946 -> 0.9992. Nothing in ordinary monitoring
reveals that, so "serving but wrong" looks identical to "serving". Readiness
is where an operator looks, so it is where the fact belongs.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService


def client() -> TestClient:
    return TestClient(create_app(DetectionService(threshold=0.7)))


def test_ready_reports_cold_feature_state() -> None:
    body = client().get("/ready").json()
    assert body["status"] == "ok"
    reasons = " ".join(body["degraded"])
    assert "feature-state-cold" in reasons


def test_degradation_does_not_fail_the_probe() -> None:
    """A first deployment is legitimately cold. Failing readiness would stop
    it starting at all, which is worse than serving while degraded."""
    assert client().get("/ready").status_code == 200


def test_degraded_reasons_explain_the_consequence() -> None:
    """A bare flag tells an operator nothing actionable."""
    body = client().get("/ready").json()
    assert body["degraded"], "expected a cold instance to report degradation"
    for reason in body["degraded"]:
        assert ":" in reason, f"reason is not named: {reason!r}"
        assert len(reason) > 40, f"reason gives no consequence: {reason!r}"


def test_health_stays_a_simple_liveness_check() -> None:
    """/health answers 'is the process up', /ready answers 'should it serve'.
    Conflating them makes one of the two useless."""
    body = client().get("/health").json()
    assert body["status"] == "ok"
    assert "version" in body


def test_readiness_is_reachable_without_a_key() -> None:
    """An orchestrator probing readiness cannot be expected to hold the API
    key; a probe that 401s reads as a dead instance and triggers a restart
    loop."""
    body = client().get("/ready")
    assert body.status_code == 200
