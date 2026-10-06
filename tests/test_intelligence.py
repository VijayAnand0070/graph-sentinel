import pytest

from graphsentinel.detection.fusion import RiskComponents, fuse_risk
from graphsentinel.detection.intelligence import interpret_risk


def test_risk_intelligence_reports_severity_support_and_uncertainty() -> None:
    risk = fuse_risk(RiskComponents(0.95, 0.9, 0.8, 0.75, 0.7))

    intelligence = interpret_risk(risk)

    assert intelligence.severity == "high"
    assert intelligence.confidence > 0.8
    assert intelligence.uncertainty == pytest.approx(1 - intelligence.confidence)
    assert intelligence.dominant_signals == ("tgn", "novelty", "burst")
