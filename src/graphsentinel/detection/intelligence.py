"""Calibrated interpretation of ensemble risk without inventing certainty.

The detector probability remains the thresholding source of truth.  This module
measures agreement between independent signals so analysts can distinguish a
high score supported by several channels from a brittle single-signal spike.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

from graphsentinel.detection.fusion import FusedRisk

Severity = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class RiskIntelligence:
    severity: Severity
    confidence: float
    uncertainty: float
    dominant_signals: tuple[str, ...]


def interpret_risk(risk: FusedRisk) -> RiskIntelligence:
    """Describe ensemble agreement using bounded, deterministic statistics."""

    components = risk.components.to_dict()
    values = tuple(components.values())
    mean = sum(values) / len(values)
    variance = sum((value - mean) ** 2 for value in values) / len(values)
    disagreement = min(1.0, math.sqrt(variance) * 2.0)
    supporting_channels = sum(value >= 0.6 for value in values)
    support_factor = min(1.0, supporting_channels / 3)
    confidence = min(0.99, max(0.05, 0.55 * (1 - disagreement) + 0.45 * support_factor))
    severity: Severity
    if risk.score >= 0.9:
        severity = "critical"
    elif risk.score >= 0.75:
        severity = "high"
    elif risk.score >= 0.5:
        severity = "medium"
    else:
        severity = "low"
    ordered = sorted(components, key=lambda name: components[name], reverse=True)
    dominant = tuple(name for name in ordered[:3] if components[name] >= 0.5)
    return RiskIntelligence(
        severity=severity,
        confidence=confidence,
        uncertainty=1 - confidence,
        dominant_signals=dominant,
    )
