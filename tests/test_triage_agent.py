"""Contract tests for the LangGraph triage agent.

Every test injects a fake generator: the agent's correctness guarantees must
hold regardless of which model is behind it, and CI cannot depend on a local
Ollama host being up.
"""

from __future__ import annotations

import json

import pytest

from graphsentinel.explain.agent import (
    AgentConfig,
    LangGraphTriageProvider,
    OllamaError,
    build_prompt,
    parse_report,
)
from graphsentinel.explain.schemas import (
    AlertEvent,
    AttackMapping,
    EvidenceBundle,
    EvidenceItem,
    ScoreBundle,
)


def _bundle() -> EvidenceBundle:
    return EvidenceBundle(
        alert_id="GS-00000042",
        event=AlertEvent(
            timestamp=1559, user="grace", source_host="OPS-FILE", destination_host="OPS-DC01"
        ),
        scores=ScoreBundle(
            tgn=0.96, novelty=0.99, burst=0.77, pivot=0.86, corroboration=0.2, fused=0.899
        ),
        evidence=(
            EvidenceItem(
                evidence_id="E-001", category="observed", statement="Auth observed.", value=1559
            ),
            EvidenceItem(
                evidence_id="E-002", category="model", statement="TGN probability.", value=0.96
            ),
        ),
        attack_mapping=AttackMapping(
            tactic="Lateral Movement",
            technique_id="T1021",
            technique="Remote Services",
            confidence="high",
            justification_evidence_ids=("E-002",),
            limitation="Authentication telemetry alone cannot confirm execution.",
        ),
    )


GROUNDED = json.dumps(
    {
        "executive_summary": [{"text": "Authentication observed.", "evidence_ids": ["E-001"]}],
        "why_suspicious": [{"text": "Model scored the event highly.", "evidence_ids": ["E-002"]}],
        "timeline": [
            {"timestamp": 1559, "description": "Auth recorded.", "evidence_ids": ["E-001"]}
        ],
        "recommended_actions": ["Verify with the account owner."],
        "uncertainty": [{"text": "Execution unconfirmed.", "evidence_ids": ["E-002"]}],
    }
)

HALLUCINATED = json.dumps(
    {
        "executive_summary": [{"text": "Confirmed exfiltration.", "evidence_ids": ["E-999"]}],
        "why_suspicious": [{"text": "Malware found.", "evidence_ids": ["E-999"]}],
        "timeline": [{"timestamp": 1559, "description": "Beacon.", "evidence_ids": ["E-999"]}],
        "recommended_actions": ["Isolate host."],
        "uncertainty": [{"text": "None.", "evidence_ids": ["E-999"]}],
    }
)


def test_grounded_response_is_accepted_without_fallback() -> None:
    provider = LangGraphTriageProvider(generate=lambda _p: GROUNDED)

    report = provider.generate(_bundle())

    assert provider.used_fallback is False
    assert report.alert_id == "GS-00000042"
    assert report.executive_summary[0].evidence_ids == ("E-001",)
    assert provider.last_trace[-1] == "validate:accepted"


def test_fabricated_evidence_never_reaches_output() -> None:
    """The whole point of the gate: invented citations must not be emitted."""

    provider = LangGraphTriageProvider(
        config=AgentConfig(max_attempts=2), generate=lambda _p: HALLUCINATED
    )

    report = provider.generate(_bundle())

    assert provider.used_fallback is True
    rendered = " ".join(s.text for s in report.executive_summary + report.why_suspicious)
    assert "exfiltration" not in rendered.lower()
    assert "malware" not in rendered.lower()
    # Nothing in the emitted report may cite an ID absent from the bundle.
    allowed = {item.evidence_id for item in _bundle().evidence}
    cited = {
        eid
        for statement in (*report.executive_summary, *report.why_suspicious, *report.uncertainty)
        for eid in statement.evidence_ids
    }
    assert cited <= allowed


def test_agent_retries_then_accepts_a_corrected_response() -> None:
    calls = {"n": 0}

    def flaky(_prompt: str) -> str:
        calls["n"] += 1
        return HALLUCINATED if calls["n"] == 1 else GROUNDED

    provider = LangGraphTriageProvider(config=AgentConfig(max_attempts=3), generate=flaky)

    report = provider.generate(_bundle())

    assert calls["n"] == 2
    assert provider.used_fallback is False
    assert report.executive_summary[0].text == "Authentication observed."


def test_retries_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A model that never grounds must not spin forever."""

    calls = {"n": 0}

    def always_bad(_prompt: str) -> str:
        calls["n"] += 1
        return HALLUCINATED

    provider = LangGraphTriageProvider(config=AgentConfig(max_attempts=2), generate=always_bad)

    provider.generate(_bundle())

    assert calls["n"] == 2
    assert provider.used_fallback is True


def test_unreachable_model_falls_back_instead_of_raising() -> None:
    def unreachable(_prompt: str) -> str:
        raise OllamaError("connection refused")

    provider = LangGraphTriageProvider(config=AgentConfig(max_attempts=1), generate=unreachable)

    report = provider.generate(_bundle())

    assert provider.used_fallback is True
    assert report.alert_id == "GS-00000042"


def test_non_json_response_falls_back() -> None:
    provider = LangGraphTriageProvider(
        config=AgentConfig(max_attempts=1), generate=lambda _p: "just some prose"
    )

    report = provider.generate(_bundle())

    assert provider.used_fallback is True
    assert report.alert_id == "GS-00000042"


def test_model_cannot_rewrite_the_attack_mapping() -> None:
    """ATT&CK classification is a detector conclusion, not narrative."""

    payload = json.loads(GROUNDED)
    payload["attack_mapping"] = {
        "tactic": "Exfiltration",
        "technique_id": "T1048",
        "technique": "Exfiltration Over Alternative Protocol",
        "confidence": "high",
        "justification_evidence_ids": ["E-001"],
        "limitation": "none",
    }
    provider = LangGraphTriageProvider(generate=lambda _p: json.dumps(payload))

    report = provider.generate(_bundle())

    assert report.attack_mapping.technique_id == "T1021"
    assert report.attack_mapping.tactic == "Lateral Movement"


def test_json_is_extracted_from_surrounding_prose() -> None:
    wrapped = f"Sure! Here is the report:\n```json\n{GROUNDED}\n```\nHope that helps."

    report = parse_report(wrapped, _bundle())

    assert report.executive_summary[0].text == "Authentication observed."


def test_repair_prompt_names_the_actual_violation() -> None:
    prompt = build_prompt(_bundle(), ["triage report cites unknown evidence: ['E-999']"])

    assert "REJECTED" in prompt
    assert "E-999" in prompt


def test_prompt_exposes_only_bundle_evidence() -> None:
    prompt = build_prompt(_bundle())

    assert "E-001" in prompt and "E-002" in prompt
    assert "OPS-DC01" in prompt
    # The contract the model is held to must be stated in the prompt.
    assert "Never invent" in prompt
