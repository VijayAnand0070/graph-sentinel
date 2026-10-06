import pytest
from pydantic import ValidationError

from graphsentinel.detection.fusion import RiskComponents, fuse_risk
from graphsentinel.explain.evidence import build_evidence_bundle
from graphsentinel.explain.schemas import CitedStatement, TriageReport
from graphsentinel.explain.triage import (
    DeterministicTriageProvider,
    validate_report_grounding,
)


def _bundle():
    return build_evidence_bundle(
        alert_id="GS-0001",
        timestamp=151648,
        user="U748",
        source_host="C17693",
        destination_host="C728",
        risk=fuse_risk(RiskComponents(0.9, 0.8, 0.7, 0.6, 0.0)),
        is_new_pair=True,
        user_fanout_5m=8,
        recent_failures=2,
    )


def test_evidence_bundle_avoids_unsupported_subtechnique() -> None:
    bundle = _bundle()

    assert bundle.attack_mapping.technique_id == "T1021"
    assert bundle.attack_mapping.subtechnique is None
    assert bundle.attack_mapping.confidence == "low"


def test_deterministic_triage_is_fully_cited() -> None:
    bundle = _bundle()

    report = DeterministicTriageProvider().generate(bundle)

    assert report.alert_id == bundle.alert_id
    assert report.attack_mapping == bundle.attack_mapping
    assert report.uncertainty


def test_grounding_rejects_unknown_evidence_reference() -> None:
    bundle = _bundle()
    report = DeterministicTriageProvider().generate(bundle)
    altered = report.model_copy(
        update={
            "executive_summary": (
                CitedStatement(text="Invented assertion", evidence_ids=("E-999",)),
            )
        }
    )

    with pytest.raises(ValueError, match="unknown evidence"):
        validate_report_grounding(bundle, altered)


def test_evidence_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        TriageReport.model_validate(
            {
                "schema_version": 1,
                "alert_id": "GS-1",
                "unexpected": "hallucinated",
            }
        )
