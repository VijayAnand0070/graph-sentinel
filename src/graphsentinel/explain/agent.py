"""LangGraph triage agent backed by a locally-hosted Ollama model.

Why LangGraph rather than an autonomous multi-agent framework
------------------------------------------------------------
This codebase already enforces a hard output contract: every statement in a
:class:`TriageReport` must cite evidence IDs that exist in the originating
bundle, and the detector's ATT&CK mapping may not be altered (see
``validate_report_grounding``). That gate is non-negotiable, so the useful
question is not "can agents collaborate freely" but "can the control flow be
audited and bounded". LangGraph answers that directly: nodes and edges are
declared up front, so the sequence prepare -> draft -> validate -> repair is
explicit, reproducible, and inspectable, and the existing validator becomes a
conditional edge inside the graph instead of a hopeful post-check.

The model never sees raw telemetry -- only the already-bounded evidence
bundle -- and never authors the ATT&CK mapping; it is copied verbatim from the
detector. The agent's only job is to phrase an explanation over evidence the
detector already produced, and anything it cannot ground is rejected and
retried. On repeated failure the deterministic template provider is used, so
enabling the agent can degrade output quality but never correctness or
availability.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypedDict

from graphsentinel.explain.schemas import (
    CitedStatement,
    EvidenceBundle,
    TimelineItem,
    TriageReport,
)
from graphsentinel.explain.triage import (
    DeterministicTriageProvider,
    validate_report_grounding,
)

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
# qwen3.5:4b over llama3.2:3b, measured on this project's own triage prompt:
# it grounds three summary statements across E-001/E-002/E-005/E-006 instead
# of one, surfaces the failed-authentication evidence the smaller model drops,
# and produces specific recommendations ("investigate the 3 failed
# authentications") rather than generic ones. Costs roughly 2x latency
# (~24s vs ~13s), which is acceptable for per-alert triage. Requires
# think=False (set in ollama_generate) or its reasoning trace eats the
# entire token budget and the report comes back empty.
DEFAULT_MODEL = "qwen3.5:4b"


@dataclass(frozen=True, slots=True)
class AgentConfig:
    """Bounded runtime policy for the triage agent."""

    model: str = DEFAULT_MODEL
    host: str = DEFAULT_OLLAMA_HOST
    timeout_seconds: float = 120.0
    # Retries are strictly bounded: a model that cannot ground its output
    # after a couple of corrective passes is not going to, and an unbounded
    # repair loop would stall the alert pipeline.
    max_attempts: int = 3
    # Deterministic decoding by default -- an incident report that changes
    # wording between runs on identical evidence is not auditable.
    temperature: float = 0.0
    num_predict: int = 900

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be in [0, 2]")


class OllamaError(RuntimeError):
    """Raised when the local model host cannot satisfy a generation request."""


def ollama_generate(prompt: str, *, config: AgentConfig) -> str:
    """Call a local Ollama model over its HTTP API using only the stdlib.

    Deliberately avoids the LangChain provider stack: the sole requirement is
    "send a prompt, get text back", and pulling a provider abstraction for
    that would add a large dependency tree to a security tool for no gain.
    """

    payload = {
        "model": config.model,
        "prompt": prompt,
        "stream": False,
        # Reasoning-capable models (the qwen3.5 family here) default to
        # emitting a long chain-of-thought that consumes the entire
        # num_predict budget, leaving "response" empty. The report itself is
        # what gets validated and shown, so spend the budget on it.
        "think": False,
        "options": {
            "temperature": config.temperature,
            "num_predict": config.num_predict,
        },
    }
    request = urllib.request.Request(
        f"{config.host.rstrip('/')}/api/generate",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
            body = json.loads(response.read())
    except urllib.error.HTTPError as error:  # pragma: no cover - network dependent
        detail = error.read().decode(errors="replace")[:300]
        raise OllamaError(f"ollama returned HTTP {error.code}: {detail}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise OllamaError(f"ollama host unreachable at {config.host}: {error}") from error
    text = body.get("response")
    if not isinstance(text, str) or not text.strip():
        raise OllamaError("ollama returned an empty response")
    return text


# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------


class TriageState(TypedDict, total=False):
    """State threaded through the graph. Kept flat and JSON-ish so a run can
    be dumped verbatim into an audit record."""

    evidence: EvidenceBundle
    prompt: str
    raw_output: str
    report: TriageReport | None
    violations: list[str]
    attempts: int
    trace: list[str]


def _evidence_digest(bundle: EvidenceBundle) -> str:
    """Render the bundle as the ONLY factual context the model may use."""

    lines = [
        f"ALERT_ID: {bundle.alert_id}",
        f"EVENT: user={bundle.event.user} "
        f"source_host={bundle.event.source_host} "
        f"destination_host={bundle.event.destination_host} "
        f"timestamp={bundle.event.timestamp}",
        f"FUSED_RISK: {bundle.scores.fused:.4f} "
        f"(tgn={bundle.scores.tgn:.4f} novelty={bundle.scores.novelty:.4f} "
        f"burst={bundle.scores.burst:.4f} pivot={bundle.scores.pivot:.4f} "
        f"corroboration={bundle.scores.corroboration:.4f})",
        "",
        "EVIDENCE (cite these IDs and no others):",
    ]
    for item in bundle.evidence:
        lines.append(f"  {item.evidence_id} [{item.category}] {item.statement} -> {item.value}")
    if bundle.path_hosts:
        lines.append(f"PATH_HOSTS: {' -> '.join(bundle.path_hosts)}")
    return "\n".join(lines)


_SCHEMA_INSTRUCTIONS = """Return ONE JSON object and nothing else. Shape:

{
  "executive_summary": [{"text": "...", "evidence_ids": ["E-001"]}],
  "why_suspicious":    [{"text": "...", "evidence_ids": ["E-002"]}],
  "timeline":          [{"timestamp": 123, "description": "...", "evidence_ids": ["E-001"]}],
  "recommended_actions": ["..."],
  "uncertainty":       [{"text": "...", "evidence_ids": ["E-003"]}]
}

Hard rules:
- Every evidence_ids entry MUST be an ID listed in EVIDENCE above. Never invent one.
- Every statement must be supported by the evidence you cite.
- State only what the evidence shows. Do not speculate about attacker intent,
  malware, or data theft that the evidence does not establish.
- Do not recommend automated containment; recommendations are advisory only.
- executive_summary: at most 3 entries. All lists must be non-empty."""


def build_prompt(bundle: EvidenceBundle, violations: list[str] | None = None) -> str:
    parts = [
        "You are a SOC analyst writing a lateral-movement triage report.",
        "You may use ONLY the facts below. You have no other knowledge of this network.",
        "",
        _evidence_digest(bundle),
        "",
        _SCHEMA_INSTRUCTIONS,
    ]
    if violations:
        # Corrective pass: name the exact contract breach rather than asking
        # vaguely for "better" output, so the retry is targeted.
        parts += [
            "",
            "Your previous answer was REJECTED for these contract violations:",
            *(f"  - {v}" for v in violations),
            "Return corrected JSON that fixes them.",
        ]
    return "\n".join(parts)


def _extract_json(text: str) -> dict[str, Any]:
    """Pull the first balanced JSON object out of a model response.

    Small local models routinely wrap JSON in prose or code fences even when
    told not to, so locate the object by brace balance rather than trusting
    the whole response to parse.
    """

    start = text.find("{")
    if start == -1:
        raise ValueError("model response contained no JSON object")
    depth, in_string, escaped = 0, False, False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : index + 1])
    raise ValueError("model response contained an unterminated JSON object")


def _as_cited(raw: Any) -> tuple[CitedStatement, ...]:
    items = raw if isinstance(raw, list) else []
    out: list[CitedStatement] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text", "")).strip()
        ids = entry.get("evidence_ids") or []
        ids = [str(i) for i in ids] if isinstance(ids, list) else []
        if text and ids:
            out.append(CitedStatement(text=text[:800], evidence_ids=tuple(ids)))
    return tuple(out)


def parse_report(raw_output: str, bundle: EvidenceBundle) -> TriageReport:
    """Map a model response onto the strict report schema.

    The ATT&CK mapping and affected entities are taken from the detector's
    bundle, never from the model: those are detection conclusions, not
    narrative, and validate_report_grounding rejects any alteration anyway.
    """

    data = _extract_json(raw_output)
    timeline: list[TimelineItem] = []
    for entry in data.get("timeline") or []:
        if not isinstance(entry, dict):
            continue
        description = str(entry.get("description", "")).strip()
        ids = entry.get("evidence_ids") or []
        ids = [str(i) for i in ids] if isinstance(ids, list) else []
        if not description or not ids:
            continue
        try:
            timestamp = int(entry.get("timestamp", bundle.event.timestamp))
        except (TypeError, ValueError):
            timestamp = bundle.event.timestamp
        timeline.append(
            TimelineItem(
                timestamp=max(0, timestamp),
                description=description[:500],
                evidence_ids=tuple(ids),
            )
        )

    actions = [
        str(a).strip()[:500]
        for a in (data.get("recommended_actions") or [])
        if str(a).strip()
    ]

    return TriageReport(
        alert_id=bundle.alert_id,
        executive_summary=_as_cited(data.get("executive_summary"))[:3],
        why_suspicious=_as_cited(data.get("why_suspicious")),
        timeline=tuple(timeline),
        affected_entities=(
            bundle.event.user,
            bundle.event.source_host,
            bundle.event.destination_host,
        ),
        attack_mapping=bundle.attack_mapping,
        recommended_actions=tuple(actions),
        uncertainty=_as_cited(data.get("uncertainty")),
    )


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


def build_triage_graph(
    generate: Callable[[str], str],
    *,
    max_attempts: int = 3,
) -> Any:
    """Compile the prepare -> draft -> validate -> (repair) state machine."""

    from langgraph.graph import END, START, StateGraph

    def prepare(state: TriageState) -> TriageState:
        bundle = state["evidence"]
        return {
            "prompt": build_prompt(bundle, state.get("violations")),
            "attempts": state.get("attempts", 0),
            "trace": [*state.get("trace", []), "prepare"],
        }

    def draft(state: TriageState) -> TriageState:
        attempts = state.get("attempts", 0) + 1
        try:
            raw = generate(state["prompt"])
            return {
                "raw_output": raw,
                "attempts": attempts,
                "trace": [*state.get("trace", []), f"draft#{attempts}"],
            }
        except OllamaError as error:
            return {
                "raw_output": "",
                "attempts": attempts,
                "violations": [f"model unavailable: {error}"],
                "trace": [*state.get("trace", []), f"draft#{attempts}:error"],
            }

    def validate(state: TriageState) -> TriageState:
        bundle = state["evidence"]
        raw = state.get("raw_output") or ""
        if not raw:
            return {
                "report": None,
                "trace": [*state.get("trace", []), "validate:no-output"],
            }
        try:
            candidate = parse_report(raw, bundle)
            # The same gate the deterministic provider passes through. An
            # agent-authored report earns no exemption.
            grounded = validate_report_grounding(bundle, candidate)
        except Exception as error:  # noqa: BLE001 - any failure is a rejection
            return {
                "report": None,
                "violations": [str(error)[:300]],
                "trace": [*state.get("trace", []), "validate:rejected"],
            }
        return {
            "report": grounded,
            "violations": [],
            "trace": [*state.get("trace", []), "validate:accepted"],
        }

    def route(state: TriageState) -> str:
        if state.get("report") is not None:
            return "done"
        if state.get("attempts", 0) >= max_attempts:
            return "done"  # exhausted; caller falls back to the template
        return "repair"

    graph = StateGraph(TriageState)
    graph.add_node("prepare", prepare)
    graph.add_node("draft", draft)
    graph.add_node("validate", validate)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "draft")
    graph.add_edge("draft", "validate")
    graph.add_conditional_edges("validate", route, {"repair": "prepare", "done": END})
    return graph.compile()


class LangGraphTriageProvider:
    """TriageProvider backed by the agent, with a deterministic safety net."""

    name = "langgraph-ollama"
    version = "1"

    def __init__(
        self,
        *,
        config: AgentConfig | None = None,
        generate: Callable[[str], str] | None = None,
        fallback: Any | None = None,
    ) -> None:
        self.config = config or AgentConfig()
        # Injectable so tests exercise the graph without a live model host.
        self._generate = generate or (lambda prompt: ollama_generate(prompt, config=self.config))
        self._fallback = fallback or DeterministicTriageProvider()
        self._graph = build_triage_graph(self._generate, max_attempts=self.config.max_attempts)
        self.last_trace: list[str] = []
        self.last_violations: list[str] = []
        self.used_fallback = False

    def generate(self, evidence: EvidenceBundle) -> TriageReport:
        try:
            final: TriageState = self._graph.invoke(
                {"evidence": evidence, "attempts": 0, "trace": [], "violations": []}
            )
        except Exception as error:  # noqa: BLE001 - orchestration must never break triage
            self.last_trace = [f"graph-error: {str(error)[:200]}"]
            self.last_violations = [str(error)[:300]]
            self.used_fallback = True
            return self._fallback.generate(evidence)

        self.last_trace = list(final.get("trace", []))
        self.last_violations = list(final.get("violations", []))
        report = final.get("report")
        if report is None:
            # Never fail the alert: an ungroundable narrative degrades to the
            # deterministic template rather than blocking triage.
            self.used_fallback = True
            return self._fallback.generate(evidence)
        self.used_fallback = False
        return report


def build_default_provider() -> Any:
    """Return the agent when explicitly enabled, else the deterministic one.

    Opt-in by design: a security pipeline should not silently start routing
    analyst-facing output through a language model because a package happened
    to be installed.
    """

    if os.getenv("GRAPHSENTINEL_TRIAGE_AGENT", "").strip().lower() not in {"1", "true", "on"}:
        return DeterministicTriageProvider()
    return LangGraphTriageProvider(
        config=AgentConfig(
            model=os.getenv("GRAPHSENTINEL_OLLAMA_MODEL", DEFAULT_MODEL),
            host=os.getenv("GRAPHSENTINEL_OLLAMA_HOST", DEFAULT_OLLAMA_HOST),
        )
    )
