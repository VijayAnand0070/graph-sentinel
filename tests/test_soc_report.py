"""Contract tests for the SOC incident report.

The report is the handover document: it says what happened to an account and
what the system already did about it. Every test injects a fake generator --
the guarantees must hold whatever model is behind it, and CI cannot depend on
a local Ollama host being up.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from graphsentinel.explain.schemas import (
    AlertEvent,
    AttackMapping,
    EvidenceBundle,
    EvidenceItem,
    ScoreBundle,
)
from graphsentinel.explain.soc_report import (
    DeterministicSocReportProvider,
    LangGraphSocReportProvider,
    build_soc_incident_bundle,
    build_soc_prompt,
    severity_for,
    validate_soc_report_grounding,
)

GATE = 0.846394


@dataclass
class _Alert:
    alert_id: str
    timestamp: int
    risk: float
    evidence: EvidenceBundle


@dataclass
class _Command:
    text: str


@dataclass
class _Execution:
    alert_id: str
    action: str
    outcome: str
    authority: str
    timestamp: int
    reversible: bool = True
    command: _Command | None = None


@dataclass
class _Escalation:
    reason: str
    at: int
    action: str = "lock_account"
    revert_at: int | None = None
    kept_by: str | None = None


def _evidence(alert_id: str, timestamp: int, src: str, dst: str, risk: float) -> EvidenceBundle:
    return EvidenceBundle(
        alert_id=alert_id,
        event=AlertEvent(
            timestamp=timestamp, user="U66@DOM1", source_host=src, destination_host=dst
        ),
        scores=ScoreBundle(
            tgn=risk, novelty=1.0, burst=0.0, pivot=0.5, corroboration=0.0, fused=risk
        ),
        evidence=(
            EvidenceItem(
                evidence_id="E-001", category="observed", statement="Auth observed.",
                value=timestamp,
            ),
        ),
        attack_mapping=AttackMapping(
            tactic="Lateral Movement",
            technique_id="T1021",
            technique="Remote Services",
            confidence="high",
            justification_evidence_ids=("E-001",),
            limitation="Authentication telemetry alone cannot confirm execution.",
        ),
    )


def _alerts() -> list[_Alert]:
    rows = [
        ("GS-00001000", 1_000, "WS05", "FS01", 0.95),
        ("GS-00001100", 1_060, "FS01", "DB01", 0.40),
        ("GS-00001200", 1_120, "FS01", "DC01", 0.90),
    ]
    return [_Alert(i, t, r, _evidence(i, t, s, d, r)) for i, t, s, d, r in rows]


def _bundle(*, with_actions: bool = True, escalated: bool = True) -> Any:
    executions = (
        [
            _Execution("GS-00001000", "notify_soc", "dry_run", "plan", 5_000),
            _Execution(
                "GS-00001000", "force_reauth", "dry_run", "plan", 5_000,
                command=_Command("Revoke-MgUserSignInSession -UserId 'U66@DOM1'"),
            ),
            _Execution(
                "GS-00001200", "lock_account", "dry_run", "escalation", 5_100,
                command=_Command("Disable-ADAccount -Identity 'U66@DOM1'"),
            ),
            _Execution(
                "GS-00001200", "reset_credentials", "pending_approval", "plan", 5_100,
                reversible=False,
            ),
        ]
        if with_actions
        else []
    )
    escalation = (
        _Escalation(reason="force_reauth did not hold; escalating", at=1_120, revert_at=12_300)
        if escalated
        else None
    )
    return build_soc_incident_bundle(
        "U66@DOM1", _alerts(), executions, escalation=escalation, gate=GATE
    )


def _response(bundle: Any, **overrides: Any) -> str:
    action_fact = next(f.fact_id for f in bundle.facts if f.kind == "action")
    payload: dict[str, Any] = {
        "headline": "U66@DOM1 moved across three hosts and was locked",
        "executive_summary": [{"text": "Three alerts in two minutes.", "evidence_ids": ["F-001"]}],
        "what_happened": [
            {"timestamp": 1_000, "description": "First hop.", "evidence_ids": ["F-001"]}
        ],
        "automated_response": [
            {"text": "The session kill ran, then the lock.", "evidence_ids": [action_fact]}
        ],
        "analyst_actions": ["Confirm with the account owner."],
        "uncertainty": [{"text": "Intent is not established.", "evidence_ids": ["F-001"]}],
    }
    payload.update(overrides)
    return json.dumps(payload)


class TestBundle:
    def test_every_alert_action_and_escalation_becomes_a_citable_fact(self) -> None:
        bundle = _bundle()
        kinds = {f.kind for f in bundle.facts}
        assert kinds == {"alert", "context", "action", "escalation"}
        assert bundle.account == "U66@DOM1"
        assert bundle.alert_ids == ("GS-00001000", "GS-00001100", "GS-00001200")
        assert bundle.hosts == ("WS05", "FS01", "DB01", "DC01")
        assert bundle.window_start == 1_000 and bundle.window_end == 1_120
        assert bundle.alerts_above_gate == 2 and bundle.escalated is True
        assert len(bundle.fact_ids) == len(bundle.facts)  # ids are unique

    def test_what_ran_and_what_waits_are_separated(self) -> None:
        bundle = _bundle()
        assert [a.action for a in bundle.actions_taken] == [
            "notify_soc", "force_reauth", "lock_account",
        ]
        assert [a.action for a in bundle.actions_pending] == ["reset_credentials"]
        assert bundle.actions_pending[0].reversible is False

    def test_severity_follows_the_measurement(self) -> None:
        assert severity_for(0.95, escalated=True, above_gate=0) == "critical"
        assert severity_for(0.95, escalated=False, above_gate=1) == "critical"
        assert severity_for(0.87, escalated=False, above_gate=1) == "high"
        assert severity_for(0.60, escalated=False, above_gate=0) == "medium"
        assert severity_for(0.35, escalated=False, above_gate=0) == "low"
        assert _bundle(with_actions=False, escalated=False).severity == "critical"

    def test_an_account_with_no_action_says_so_rather_than_saying_nothing(self) -> None:
        bundle = _bundle(with_actions=False, escalated=False)
        assert any("No disruptive action ran" in f.statement for f in bundle.facts)

    def test_an_account_with_no_alerts_is_refused(self) -> None:
        with pytest.raises(ValueError, match="nothing to report"):
            build_soc_incident_bundle("U66@DOM1", [])


class TestGrounding:
    def test_a_grounded_report_is_accepted_without_fallback(self) -> None:
        bundle = _bundle()
        provider = LangGraphSocReportProvider(generate=lambda _p: _response(bundle))

        report = provider.generate(bundle)

        assert provider.used_fallback is False
        assert provider.last_trace[-1] == "validate:accepted"
        assert report.account == "U66@DOM1" and report.severity == "critical"
        assert report.actions_taken == bundle.actions_taken

    def test_invented_facts_never_reach_the_report(self) -> None:
        bundle = _bundle()
        provider = LangGraphSocReportProvider(
            generate=lambda _p: _response(
                bundle,
                executive_summary=[
                    {"text": "Data was exfiltrated.", "evidence_ids": ["F-404"]}
                ],
            )
        )

        report = provider.generate(bundle)

        assert provider.used_fallback is True
        assert all("exfiltrat" not in s.text for s in report.executive_summary)
        assert any("unknown facts" in v for v in provider.last_violations)

    def test_a_response_claim_must_cite_an_action(self) -> None:
        # Otherwise "the system contained the account" is prose, not a record.
        bundle = _bundle()
        provider = LangGraphSocReportProvider(
            generate=lambda _p: _response(
                bundle,
                automated_response=[
                    {"text": "The host was isolated.", "evidence_ids": ["F-001"]}
                ],
            )
        )

        provider.generate(bundle)

        assert provider.used_fallback is True
        assert any("must cite an action" in v for v in provider.last_violations)

    def test_an_alert_id_that_does_not_exist_is_rejected(self) -> None:
        # A wrong id is an identifier an analyst pastes into a search box.
        bundle = _bundle()
        provider = LangGraphSocReportProvider(
            generate=lambda _p: _response(
                bundle,
                what_happened=[
                    {
                        "timestamp": 1_000,
                        "description": "See alert GS-99999999.",
                        "evidence_ids": ["F-001"],
                    }
                ],
            )
        )

        provider.generate(bundle)

        assert provider.used_fallback is True
        assert any("not in this incident" in v for v in provider.last_violations)

    def test_the_model_cannot_rewrite_what_the_system_did(self) -> None:
        bundle = _bundle()
        report = DeterministicSocReportProvider().generate(bundle)
        forged = report.model_copy(
            update={
                "actions_taken": tuple(
                    a.model_copy(update={"outcome": "executed"}) for a in report.actions_taken
                )
            }
        )
        with pytest.raises(ValueError, match="altered the detector's actions_taken"):
            validate_soc_report_grounding(bundle, forged)

    def test_the_model_cannot_raise_its_own_severity(self) -> None:
        bundle = _bundle(with_actions=True, escalated=False)
        report = DeterministicSocReportProvider().generate(bundle)
        with pytest.raises(ValueError, match="altered the detector's severity"):
            validate_soc_report_grounding(bundle, report.model_copy(update={"severity": "low"}))

    def test_an_unreachable_model_still_produces_a_report(self) -> None:
        from graphsentinel.explain.agent import OllamaError

        def unreachable(_prompt: str) -> str:
            raise OllamaError("connection refused")

        bundle = _bundle()
        provider = LangGraphSocReportProvider(generate=unreachable)

        report = provider.generate(bundle)

        assert provider.used_fallback is True
        assert report.incident_id == bundle.incident_id
        assert report.automated_response  # the handover still says what ran

    def test_retries_are_bounded(self) -> None:
        calls: list[str] = []

        def bad(prompt: str) -> str:
            calls.append(prompt)
            return "not json at all"

        bundle = _bundle()
        provider = LangGraphSocReportProvider(generate=bad)
        provider.generate(bundle)

        assert len(calls) == provider.config.max_attempts
        assert "REJECTED" in calls[-1]  # the repair prompt names the breach


class TestDeterministicProvider:
    def test_it_writes_the_same_shape_without_a_model(self) -> None:
        bundle = _bundle()
        report = DeterministicSocReportProvider().generate(bundle)
        assert report.severity == "critical"
        assert report.what_happened and report.automated_response and report.uncertainty
        assert "locked by the system" in report.headline

    def test_markdown_is_a_ticket_comment(self) -> None:
        report = DeterministicSocReportProvider().generate(_bundle())
        markdown = report.to_markdown()
        assert markdown.startswith("# ")
        for heading in (
            "## Summary",
            "## What happened",
            "## What the system did automatically",
            "## Waiting for a person",
            "## For the analyst",
            "## Uncertainty",
        ):
            assert heading in markdown
        assert "Disable-ADAccount" in markdown  # the literal command, not a paraphrase
        assert "reset_credentials" in markdown and "irreversible" in markdown


class TestPrompt:
    def test_the_prompt_exposes_only_bundle_facts(self) -> None:
        bundle = _bundle()
        prompt = build_soc_prompt(bundle)
        for fact in bundle.facts:
            assert fact.fact_id in prompt
        assert "cite these ids and no others" in prompt
        assert "SEVERITY (computed, do not change)" in prompt

    def test_the_repair_prompt_names_the_actual_violation(self) -> None:
        prompt = build_soc_prompt(_bundle(), ["SOC report cites unknown facts: ['F-404']"])
        assert "REJECTED" in prompt and "F-404" in prompt
