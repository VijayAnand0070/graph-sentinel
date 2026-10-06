"""Grounded natural-language explanation of a ranked attack path.

Reuses the triage agent's central guarantee -- a model may only restate facts
it was given, and anything it cannot ground is rejected -- but applies it to a
path rather than a single alert. A path is the object an analyst actually
reasons about ("did someone walk from a workstation to the domain controller,
and how fast"), so it is worth explaining in prose; it is also exactly the
kind of object a model will happily invent detail about, which is why the
same reject-and-fall-back discipline applies here.

The grounding contract for paths differs from the alert bundle's evidence-ID
citations: the checkable facts are the hostnames, usernames, hop count and
elapsed time carried by the path record. So the validator here asserts that
every host and user named in the explanation actually appears in the path,
and rejects any explanation naming an entity that does not.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

MAX_SENTENCES = 4


@dataclass(frozen=True, slots=True)
class PathFacts:
    """The complete, bounded fact set a path explanation may draw on."""

    path_id: str
    hosts: tuple[str, ...]
    users: tuple[str, ...]
    timestamps: tuple[int, ...]
    score: float
    mean_edge_risk: float
    new_edge_ratio: float
    pivot_density: float
    evidence_support: float
    redteam_overlap: bool

    @property
    def elapsed_seconds(self) -> int:
        if len(self.timestamps) < 2:
            return 0
        return max(0, self.timestamps[-1] - self.timestamps[0])

    @property
    def hop_count(self) -> int:
        return max(0, len(self.hosts) - 1)


def humanize_duration(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds} seconds"
    if seconds < 3600:
        return f"{seconds // 60} minutes"
    if seconds < 86400:
        return f"{seconds // 3600} hours"
    return f"{seconds // 86400} days"


def build_path_prompt(facts: PathFacts) -> str:
    """Render the path as the ONLY facts the model may use."""

    dwell_lines = []
    for index in range(1, len(facts.timestamps)):
        gap = facts.timestamps[index] - facts.timestamps[index - 1]
        dwell_lines.append(f"  hop {index}: waited {humanize_duration(gap)} before this hop")

    return "\n".join(
        [
            "You are a SOC analyst describing one lateral-movement path.",
            "Use ONLY the facts below. You know nothing else about this network.",
            "",
            f"PATH_ID: {facts.path_id}",
            f"ROUTE: {' -> '.join(facts.hosts)}",
            f"ACCOUNTS USED: {', '.join(facts.users) if facts.users else 'unknown'}",
            f"HOPS: {facts.hop_count}",
            f"ELAPSED: {humanize_duration(facts.elapsed_seconds)}",
            f"PATH SCORE: {facts.score:.3f}",
            f"MEAN EDGE RISK: {facts.mean_edge_risk:.3f}",
            f"NEW-RELATIONSHIP RATIO: {facts.new_edge_ratio:.3f} "
            "(1.0 means every hop was between a pair never seen together before)",
            f"PIVOT DENSITY: {facts.pivot_density:.3f}",
            f"EVIDENCE SUPPORT: {facts.evidence_support:.3f}",
            f"RED-TEAM GROUND TRUTH OVERLAP: {facts.redteam_overlap}",
            *(["DWELL BETWEEN HOPS:", *dwell_lines] if dwell_lines else []),
            "",
            f"Write at most {MAX_SENTENCES} plain sentences explaining what this path shows",
            "and why it scored as it did. Rules:",
            "- Name only hosts and accounts listed above. Never invent a hostname or account.",
            "- Do not claim malware, data theft, or attacker intent; the data does not show it.",
            "- Do not recommend automated containment.",
            "- Return prose only. No JSON, no bullet points, no preamble.",
        ]
    )


# Hostnames/accounts are the checkable nouns in a path explanation. Matches
# the shapes this pipeline actually produces: LANL-style (C1234, U56@DOM1)
# and the readable synthetic names (OPS-DC01, FIN-WS1).
_ENTITY_PATTERN = re.compile(r"\b(?:[A-Z][A-Z0-9]*-[A-Z0-9]+|[CU]\d+\$?(?:@[A-Z0-9]+)?)\b")


def validate_path_explanation(text: str, facts: PathFacts) -> str:
    """Reject an explanation that names an entity outside the path.

    This is the path-level analogue of ``validate_report_grounding``: the
    model may rephrase, summarise and interpret, but the moment it names a
    host or account that is not in the path it has left the evidence behind
    and the output is discarded rather than shown to an analyst.
    """

    cleaned = " ".join(text.split()).strip()
    if not cleaned:
        raise ValueError("explanation was empty")
    if len(cleaned) > 1200:
        raise ValueError("explanation exceeded the length budget")

    known = {token.upper() for token in (*facts.hosts, *facts.users)}
    named = {match.group(0).upper() for match in _ENTITY_PATTERN.finditer(cleaned)}
    invented = named - known
    if invented:
        raise ValueError(f"explanation names entities absent from the path: {sorted(invented)}")

    sentences = [s for s in re.split(r"(?<=[.!?])\s+", cleaned) if s]
    if len(sentences) > MAX_SENTENCES + 2:
        raise ValueError("explanation was longer than the sentence budget")
    return cleaned


def deterministic_path_explanation(facts: PathFacts) -> str:
    """Template fallback. Always grounded, never unavailable."""

    route = " -> ".join(facts.hosts) if facts.hosts else "an unresolved route"
    parts = [
        f"This path traverses {facts.hop_count} hop(s) across {len(facts.hosts)} hosts ({route})."
    ]
    if facts.elapsed_seconds:
        parts.append(f"The traversal spans {humanize_duration(facts.elapsed_seconds)}.")
    if facts.new_edge_ratio >= 0.99:
        parts.append("Every hop was between a host pair not previously observed together.")
    elif facts.new_edge_ratio > 0:
        parts.append(
            f"{facts.new_edge_ratio * 100:.0f}% of hops were between previously unseen host pairs."
        )
    parts.append(
        f"It scored {facts.score:.3f} with mean edge risk {facts.mean_edge_risk:.3f}"
        f" and pivot density {facts.pivot_density:.3f}."
    )
    return " ".join(parts)


def explain_path(
    facts: PathFacts,
    *,
    generate: Callable[[str], str] | None = None,
    max_attempts: int = 2,
) -> tuple[str, bool]:
    """Return ``(explanation, used_fallback)``.

    Bounded retries then a deterministic template, mirroring the triage
    agent: an explanation panel must never block on, or be blocked by, a
    language model.
    """

    if generate is None:
        return deterministic_path_explanation(facts), True

    prompt = build_path_prompt(facts)
    for _ in range(max(1, max_attempts)):
        try:
            return validate_path_explanation(generate(prompt), facts), False
        except Exception:  # noqa: BLE001 - any failure is a rejection, then retry
            continue
    return deterministic_path_explanation(facts), True


def facts_from_payload(payload: dict, hosts: Sequence[str], users: Sequence[str]) -> PathFacts:
    """Build PathFacts from an API path record plus resolved entity names."""

    return PathFacts(
        path_id=str(payload.get("path_id", "")),
        hosts=tuple(hosts),
        users=tuple(users),
        timestamps=tuple(int(t) for t in payload.get("timestamps", [])),
        score=float(payload.get("score", 0.0)),
        mean_edge_risk=float(payload.get("mean_edge_risk", 0.0)),
        new_edge_ratio=float(payload.get("new_edge_ratio", 0.0)),
        pivot_density=float(payload.get("pivot_density", 0.0)),
        evidence_support=float(payload.get("evidence_support", 0.0)),
        redteam_overlap=bool(payload.get("redteam_overlap", False)),
    )
