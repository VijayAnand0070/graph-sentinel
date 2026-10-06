"""Grounding contract for agent-generated attack-path explanations."""

from __future__ import annotations

import pytest

from graphsentinel.explain.path_agent import (
    PathFacts,
    build_path_prompt,
    deterministic_path_explanation,
    explain_path,
    humanize_duration,
    validate_path_explanation,
)


def _facts() -> PathFacts:
    return PathFacts(
        path_id="GS-P-1-2-3",
        hosts=("FIN-WS1", "FIN-SRV", "ENG-WS1", "OPS-DC01"),
        users=("alice", "dave"),
        timestamps=(1000, 1075, 1195, 3000),
        score=0.903,
        mean_edge_risk=0.896,
        new_edge_ratio=1.0,
        pivot_density=0.8,
        evidence_support=0.9,
        redteam_overlap=False,
    )


def test_explanation_naming_only_path_entities_is_accepted() -> None:
    text = "The path runs from FIN-WS1 through FIN-SRV to OPS-DC01 using alice."

    assert validate_path_explanation(text, _facts()) == text


def test_explanation_naming_an_unknown_host_is_rejected() -> None:
    """The model must not introduce hosts that are not on the path."""

    with pytest.raises(ValueError, match="absent from the path"):
        validate_path_explanation(
            "The attacker pivoted from FIN-WS1 to SECRET-DB99 and exfiltrated data.", _facts()
        )


def test_empty_explanation_is_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        validate_path_explanation("   ", _facts())


def test_overlong_explanation_is_rejected() -> None:
    with pytest.raises(ValueError, match="length budget"):
        validate_path_explanation("FIN-WS1 " * 400, _facts())


def test_ungrounded_model_falls_back_to_the_template() -> None:
    def invents(_prompt: str) -> str:
        return "Traffic reached SECRET-DB99 and C2-SERVER before exfiltration."

    text, used_fallback = explain_path(_facts(), generate=invents, max_attempts=2)

    assert used_fallback is True
    assert "SECRET-DB99" not in text
    assert "C2-SERVER" not in text


def test_grounded_model_output_is_used_directly() -> None:
    grounded = "This path moves from FIN-WS1 to OPS-DC01 across four hosts in about 33 minutes."

    text, used_fallback = explain_path(_facts(), generate=lambda _p: grounded)

    assert used_fallback is False
    assert text == grounded


def test_unavailable_model_falls_back_without_raising() -> None:
    def boom(_prompt: str) -> str:
        raise RuntimeError("ollama unreachable")

    text, used_fallback = explain_path(_facts(), generate=boom, max_attempts=2)

    assert used_fallback is True
    assert "FIN-WS1" in text


def test_no_generator_yields_the_deterministic_template() -> None:
    text, used_fallback = explain_path(_facts(), generate=None)

    assert used_fallback is True
    assert text == deterministic_path_explanation(_facts())


def test_deterministic_template_is_self_grounding() -> None:
    """The fallback must satisfy the same validator it backs up."""

    facts = _facts()

    assert validate_path_explanation(deterministic_path_explanation(facts), facts)


def test_prompt_carries_only_path_facts() -> None:
    prompt = build_path_prompt(_facts())

    assert "FIN-WS1 -> FIN-SRV" in prompt
    assert "Never invent a hostname" in prompt
    # Dwell between hops is a headline fact for a pivot chain.
    assert "DWELL BETWEEN HOPS" in prompt


def test_elapsed_and_hop_count_derive_from_timestamps() -> None:
    facts = _facts()

    assert facts.hop_count == 3
    assert facts.elapsed_seconds == 2000
    assert humanize_duration(facts.elapsed_seconds) == "33 minutes"
