"""The SOC incident report: one account, everything that happened, one page.

``triage.py`` explains a single alert. That is the right unit for a queue and
the wrong one for a handover: by the time the prevention loop has contained
an account, escalated, and scheduled a revert, the analyst picking it up has
a dozen alerts and twice as many dispatch records to reconstruct, and the
question they actually have is "what happened to this account, what did the
system already do about it, and what is left for me".

This module answers that question as a written report, over exactly the same
discipline the per-alert triage uses:

* The report is built from a **fact bundle** -- alerts, dispatch records, the
  escalation and its evidence -- and every fact carries an ``F-nnn`` id.
* Any narrative statement must cite fact ids **from this bundle**. Nothing
  else is a valid citation, and an uncitable sentence is rejected.
* What the system *did* is copied verbatim from the dispatch records, never
  authored: a report that misstates which command ran is worse than no
  report. The model's job is the prose around those facts.
* The "what the system did" section must cite an action or escalation fact,
  so it cannot become a paragraph of plausible-sounding response theatre.

A language model writes the prose when one is enabled and reachable
(:class:`LangGraphSocReportProvider`); otherwise -- and whenever the model
cannot ground what it wrote -- the deterministic provider writes the same
report from the same facts, more plainly. The output contract is identical,
so downstream (the console, the Markdown export, a ticket) cannot tell which
engine produced it except by the provenance it is handed.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from typing import Any, Literal, Protocol, TypedDict

from pydantic import Field

from graphsentinel.detection.gates import AUTO_EXECUTE_GATE
from graphsentinel.explain.agent import (
    AgentConfig,
    OllamaError,
    _extract_json,
    ollama_generate,
)
from graphsentinel.explain.schemas import CitedStatement, StrictModel, TimelineItem

Severity = Literal["critical", "high", "medium", "low"]
FactKind = Literal["alert", "action", "escalation", "context"]


# ---------------------------------------------------------------------------
# the bundle: everything the report is allowed to say
# ---------------------------------------------------------------------------


class SocFact(StrictModel):
    """One citable fact. ``value`` keeps the number behind the sentence."""

    fact_id: str = Field(pattern=r"^F-[0-9]{3,}$")
    kind: FactKind
    statement: str = Field(min_length=1, max_length=500)
    at: int | None = None
    value: int | float | str | bool | None = None


class SocAction(StrictModel):
    """A dispatch record, reduced to what a report may state about it."""

    action: str = Field(min_length=1, max_length=64)
    outcome: str = Field(min_length=1, max_length=32)
    authority: str = Field(min_length=1, max_length=32)
    at: int = Field(ge=0)
    alert_id: str = Field(min_length=1, max_length=64)
    reversible: bool
    command: str | None = Field(default=None, max_length=1000)
    #: For an action waiting for a person: when its approval window closes,
    #: and what the system does then.
    decision_due: int | None = None
    on_timeout: str | None = Field(default=None, max_length=200)


class SocIncidentBundle(StrictModel):
    schema_version: Literal[1] = 1
    incident_id: str = Field(pattern=r"^INC-[A-Za-z0-9._$@-]+$")
    account: str = Field(min_length=1, max_length=128)
    window_start: int = Field(ge=0)
    window_end: int = Field(ge=0)
    severity: Severity
    alert_ids: tuple[str, ...] = Field(min_length=1)
    hosts: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()
    highest_risk: float = Field(ge=0, le=1)
    alerts_above_gate: int = Field(ge=0)
    actions_taken: tuple[SocAction, ...] = ()
    actions_pending: tuple[SocAction, ...] = ()
    escalated: bool = False
    lock_revert_at: int | None = None
    lock_kept_by: str | None = None
    facts: tuple[SocFact, ...] = Field(min_length=1)

    @property
    def fact_ids(self) -> set[str]:
        return {fact.fact_id for fact in self.facts}


class SocIncidentReport(StrictModel):
    schema_version: Literal[1] = 1
    incident_id: str
    account: str
    headline: str = Field(min_length=1, max_length=200)
    severity: Severity
    #: Copied from the bundle, never authored.
    window_start: int
    window_end: int
    alert_ids: tuple[str, ...]
    hosts: tuple[str, ...]
    actions_taken: tuple[SocAction, ...]
    actions_pending: tuple[SocAction, ...]
    #: Written, and cited.
    executive_summary: tuple[CitedStatement, ...] = Field(min_length=1, max_length=4)
    what_happened: tuple[TimelineItem, ...] = Field(min_length=1)
    automated_response: tuple[CitedStatement, ...] = Field(min_length=1)
    analyst_actions: tuple[str, ...] = Field(min_length=1, max_length=8)
    uncertainty: tuple[CitedStatement, ...] = Field(min_length=1)

    def to_markdown(self) -> str:
        """The report as a ticket comment."""
        lines = [
            f"# {self.headline}",
            "",
            f"**Incident** {self.incident_id} · **account** `{self.account}` · "
            f"**severity** {self.severity.upper()}",
            f"**Window** {self.window_start} to {self.window_end} "
            f"({self.window_end - self.window_start} s) · "
            f"**alerts** {len(self.alert_ids)} · **hosts** {', '.join(self.hosts) or '—'}",
            "",
            "## Summary",
            *(f"- {s.text} [{', '.join(s.evidence_ids)}]" for s in self.executive_summary),
            "",
            "## What happened",
            *(
                f"- `{item.timestamp}` {item.description} [{', '.join(item.evidence_ids)}]"
                for item in self.what_happened
            ),
            "",
            "## What the system did automatically",
            *(f"- {s.text} [{', '.join(s.evidence_ids)}]" for s in self.automated_response),
        ]
        if self.actions_taken:
            lines += [
                "",
                "| when | action | outcome | authority | command |",
                "|---|---|---|---|---|",
                *(
                    f"| {a.at} | `{a.action}` | {a.outcome} | {a.authority} | "
                    f"`{(a.command or '—')[:120]}` |"
                    for a in self.actions_taken
                ),
            ]
        if self.actions_pending:
            lines += [
                "",
                "## Waiting for a person",
                *(
                    f"- `{a.action}` on alert {a.alert_id}"
                    f"{'' if a.reversible else ' — irreversible'}"
                    + (f" — decide by t={a.decision_due}" if a.decision_due is not None else "")
                    + (f"; {a.on_timeout}" if a.on_timeout else "")
                    for a in self.actions_pending
                ),
            ]
        lines += [
            "",
            "## For the analyst",
            *(f"- [ ] {action}" for action in self.analyst_actions),
            "",
            "## Uncertainty",
            *(f"- {s.text} [{', '.join(s.evidence_ids)}]" for s in self.uncertainty),
            "",
        ]
        return "\n".join(lines)


class SocReportProvider(Protocol):
    name: str
    version: str

    def generate(self, bundle: SocIncidentBundle) -> SocIncidentReport: ...


# ---------------------------------------------------------------------------
# building the bundle
# ---------------------------------------------------------------------------


def _slug(account: str) -> str:
    return "".join(c if c.isalnum() or c in "._$@-" else "-" for c in account) or "account"


def severity_for(risk: float, *, escalated: bool, above_gate: int) -> Severity:
    """Severity as a function of what was measured, not of how it reads."""
    if escalated or (above_gate and risk >= 0.9):
        return "critical"
    if above_gate:
        return "high"
    if risk >= 0.5:
        return "medium"
    return "low"


def build_soc_incident_bundle(
    account: str,
    alerts: Sequence[Any],
    executions: Sequence[Any] = (),
    *,
    escalation: Any | None = None,
    gate: float = AUTO_EXECUTE_GATE.threshold,
    max_alert_facts: int = 12,
    approval_window: Any | None = None,
) -> SocIncidentBundle:
    """Assemble every fact a report about ``account`` may state.

    ``alerts`` and ``executions`` are duck-typed on purpose: this module sits
    under ``explain/`` and must not import the API's record types, and the
    same builder is used by the service, the CLI and the tests.
    """
    if not alerts:
        raise ValueError(f"no alerts for {account}: nothing to report")
    ordered = sorted(alerts, key=lambda a: int(a.timestamp))
    facts: list[SocFact] = []
    hosts: list[str] = []

    def add(kind: FactKind, statement: str, *, at: int | None = None, value: Any = None) -> str:
        fact_id = f"F-{len(facts) + 1:03d}"
        facts.append(
            SocFact(fact_id=fact_id, kind=kind, statement=statement[:500], at=at, value=value)
        )
        return fact_id

    highest = 0.0
    above_gate = 0
    techniques: list[str] = []
    alert_facts: dict[str, str] = {}
    for alert in ordered:
        event = alert.evidence.event
        risk = float(alert.risk)
        highest = max(highest, risk)
        if risk >= gate:
            above_gate += 1
        for host in (event.source_host, event.destination_host):
            if host not in hosts:
                hosts.append(host)
        mapping = getattr(alert.evidence, "attack_mapping", None)
        technique = getattr(mapping, "technique_id", None)
        if technique and technique not in techniques:
            techniques.append(str(technique))
        if len(alert_facts) < max_alert_facts:
            alert_facts[str(alert.alert_id)] = add(
                "alert",
                f"Alert {alert.alert_id}: {event.user} authenticated from {event.source_host} "
                f"to {event.destination_host} at fused risk {risk:.4f}"
                f"{' (at or above the execution gate)' if risk >= gate else ''}.",
                at=int(alert.timestamp),
                value=round(risk, 6),
            )

    if len(ordered) > len(alert_facts):
        add(
            "context",
            f"{len(ordered) - len(alert_facts)} further alerts on this account are not "
            f"listed individually; {len(ordered)} in total.",
            value=len(ordered),
        )
    add(
        "context",
        f"The account reached {len(hosts)} distinct hosts across the incident: "
        f"{', '.join(hosts[:12])}.",
        value=len(hosts),
    )
    add(
        "context",
        f"The highest fused risk on this account was {highest:.4f}; {above_gate} of "
        f"{len(ordered)} alerts were at or above the unattended execution gate ({gate:.4f}).",
        value=round(highest, 6),
    )

    taken: list[SocAction] = []
    pending: list[SocAction] = []
    # An action approved, rejected or expired after it waited is no longer
    # waiting: only the latest record per (alert, action) can be pending.
    latest_at: dict[tuple[str, str], int] = {}
    for record in executions:
        key = (str(record.alert_id), str(record.action))
        latest_at[key] = max(latest_at.get(key, -1), int(record.timestamp))
    deadlines: dict[tuple[str, str], tuple[int, str]] = {}
    for record in executions:
        command = getattr(record, "command", None)
        action = SocAction(
            action=str(record.action),
            outcome=str(record.outcome),
            authority=str(getattr(record, "authority", "plan")),
            at=int(record.timestamp),
            alert_id=str(record.alert_id),
            reversible=bool(getattr(record, "reversible", True)),
            command=(str(getattr(command, "text", "")) or None) if command else None,
        )
        if action.outcome == "pending_approval":
            if action.at >= latest_at[(action.alert_id, action.action)]:
                pending.append(action)
                if approval_window is not None:
                    deadlines[(action.alert_id, action.action)] = (
                        int(approval_window.deadline(record)),
                        str(approval_window.describe(action.action)),
                    )
                    pending[-1] = action.model_copy(
                        update={
                            "decision_due": deadlines[(action.alert_id, action.action)][0],
                            "on_timeout": deadlines[(action.alert_id, action.action)][1],
                        }
                    )
            continue
        taken.append(action)
        if action.action in {"notify_soc", "increase_monitoring"}:
            continue  # recorded, but not what a handover is about
        if action.outcome in {"rejected", "expired"}:
            add(
                "action",
                f"{action.action} on {account} (alert {action.alert_id}) was "
                + (
                    f"rejected by {getattr(record, 'approved_by', None) or 'an analyst'}"
                    if action.outcome == "rejected"
                    else "not decided within its approval window and expired unapplied"
                )
                + ".",
                at=action.at,
                value=action.action,
            )
            continue
        if action.authority == "timeout":
            add(
                "action",
                f"Nobody decided {action.action} on {account} within its approval window, so "
                f"the system applied it as a reversible block (outcome {action.outcome})"
                + (f". Command: {action.command}" if action.command else "."),
                at=action.at,
                value=action.action,
            )
            continue
        add(
            "action",
            f"The system ran {action.action} on {account} "
            f"(outcome {action.outcome}, authority {action.authority}"
            f"{', reversible' if action.reversible else ', IRREVERSIBLE'})"
            + (f". Command: {action.command}" if action.command else "."),
            at=action.at,
            value=action.action,
        )
    for action in pending:
        due = deadlines.get((action.alert_id, action.action))
        add(
            "action",
            f"{action.action} was planned for alert {action.alert_id} and is waiting for a "
            f"person{'' if action.reversible else ' (irreversible, never automatic)'}"
            + (f"; decision due by t={due[0]}: {due[1]}." if due else "."),
            at=action.at,
            value=action.action,
        )
    quiet = [a for a in taken if a.action in {"notify_soc", "increase_monitoring"}]
    if quiet:
        add(
            "action",
            f"{len(quiet)} non-disruptive actions (queueing and closer monitoring) were "
            "also dispatched.",
            value=len(quiet),
        )

    escalated = False
    revert_at: int | None = None
    kept_by: str | None = None
    if escalation is not None:
        escalated = True
        revert_at = getattr(escalation, "revert_at", None)
        kept_by = getattr(escalation, "kept_by", None)
        add(
            "escalation",
            str(getattr(escalation, "reason", "The containment did not hold; the account "
                        "was locked by the system.")),
            at=int(getattr(escalation, "at", ordered[-1].timestamp)),
            value=str(getattr(escalation, "action", "lock_account")),
        )
        if kept_by:
            add("escalation", f"The lock was kept by {kept_by}; it will not revert on its own.",
                value=kept_by)
        elif revert_at:
            add(
                "escalation",
                f"The lock reverts automatically at {revert_at} unless an analyst keeps it; "
                "an alert on the account restarts that clock.",
                at=int(revert_at),
                value=int(revert_at),
            )
    if not any(f.kind in {"action", "escalation"} for f in facts):
        add(
            "action",
            "No disruptive action ran on this account: nothing cleared the unattended bar, "
            "or the budget held it for a person.",
            value=False,
        )

    severity = severity_for(highest, escalated=escalated, above_gate=above_gate)
    return SocIncidentBundle(
        incident_id=f"INC-{_slug(account)}-{int(ordered[0].timestamp)}",
        account=account,
        window_start=int(ordered[0].timestamp),
        window_end=int(ordered[-1].timestamp),
        severity=severity,
        alert_ids=tuple(str(a.alert_id) for a in ordered),
        hosts=tuple(hosts),
        techniques=tuple(techniques),
        highest_risk=min(1.0, highest),
        alerts_above_gate=above_gate,
        actions_taken=tuple(taken),
        actions_pending=tuple(pending),
        escalated=escalated,
        lock_revert_at=int(revert_at) if revert_at else None,
        lock_kept_by=kept_by,
        facts=tuple(facts),
    )


# ---------------------------------------------------------------------------
# the contract
# ---------------------------------------------------------------------------


def validate_soc_report_grounding(
    bundle: SocIncidentBundle, report: SocIncidentReport
) -> SocIncidentReport:
    """Reject anything the bundle does not support. No exemptions by author."""
    if report.incident_id != bundle.incident_id or report.account != bundle.account:
        raise ValueError("SOC report does not belong to this incident")
    for name in ("severity", "window_start", "window_end", "alert_ids", "hosts",
                 "actions_taken", "actions_pending"):
        if getattr(report, name) != getattr(bundle, name):
            raise ValueError(f"SOC report altered the detector's {name}")
    allowed = bundle.fact_ids
    cited: set[str] = set()
    for statement in (*report.executive_summary, *report.automated_response, *report.uncertainty):
        cited.update(statement.evidence_ids)
    for item in report.what_happened:
        cited.update(item.evidence_ids)
    unknown = cited - allowed
    if unknown:
        raise ValueError(f"SOC report cites unknown facts: {sorted(unknown)}")
    # An alert id inside prose is an identifier an analyst will paste into a
    # search box. A citation check does not catch one that is merely wrong,
    # so every GS- token in the narrative must be an alert of this incident.
    narrative = " ".join(
        [report.headline, *(s.text for s in report.executive_summary),
         *(i.description for i in report.what_happened),
         *(s.text for s in report.automated_response),
         *(s.text for s in report.uncertainty), *report.analyst_actions]
    )
    invented = set(re.findall(r"GS-[A-Za-z0-9-]+", narrative)) - set(report.alert_ids)
    if invented:
        raise ValueError(
            f"SOC report names alerts that are not in this incident: {sorted(invented)}"
        )

    action_facts = {f.fact_id for f in bundle.facts if f.kind in {"action", "escalation"}}
    for statement in report.automated_response:
        if not action_facts & set(statement.evidence_ids):
            raise ValueError(
                "every statement about the automatic response must cite an action or "
                f"escalation fact; {statement.evidence_ids} are not"
            )
    return report


# ---------------------------------------------------------------------------
# deterministic provider
# ---------------------------------------------------------------------------


class DeterministicSocReportProvider:
    """The same report, written from the facts without a model."""

    name = "deterministic-soc-template"
    version = "1"

    def generate(self, bundle: SocIncidentBundle) -> SocIncidentReport:
        alert_facts = [f for f in bundle.facts if f.kind == "alert"]
        # What ran, then the escalation, then what is waiting: a handover
        # reads top-down and the first line should be the disruptive one.
        ran = [f for f in bundle.facts if f.kind == "action" and str(f.statement).startswith(
            "The system ran")]
        escalations = [f for f in bundle.facts if f.kind == "escalation"]
        waiting = [f for f in bundle.facts if f.kind == "action" and f not in ran]
        action_facts = [*ran, *escalations, *waiting]
        context_facts = [f for f in bundle.facts if f.kind == "context"]
        first, last = alert_facts[0], alert_facts[-1]
        span = bundle.window_end - bundle.window_start

        summary = [
            CitedStatement(
                text=(
                    f"{bundle.account} raised {len(bundle.alert_ids)} alerts over {span} s "
                    f"across {len(bundle.hosts)} hosts, peaking at fused risk "
                    f"{bundle.highest_risk:.4f}."
                ),
                evidence_ids=(first.fact_id, *(c.fact_id for c in context_facts[-1:])),
            )
        ]
        if bundle.escalated:
            summary.append(
                CitedStatement(
                    text=(
                        "The first containment did not hold and the system escalated to a "
                        "reversible account lock on its own authority."
                    ),
                    evidence_ids=tuple(
                        f.fact_id for f in bundle.facts if f.kind == "escalation"
                    )[:2],
                )
            )
        return validate_soc_report_grounding(
            bundle,
            SocIncidentReport(
                incident_id=bundle.incident_id,
                account=bundle.account,
                headline=(
                    f"{bundle.severity.upper()}: {bundle.account} — "
                    f"{len(bundle.alert_ids)} alerts across {len(bundle.hosts)} hosts"
                    + (", account locked by the system" if bundle.escalated else "")
                )[:200],
                severity=bundle.severity,
                window_start=bundle.window_start,
                window_end=bundle.window_end,
                alert_ids=bundle.alert_ids,
                hosts=bundle.hosts,
                actions_taken=bundle.actions_taken,
                actions_pending=bundle.actions_pending,
                executive_summary=tuple(summary[:4]),
                what_happened=tuple(
                    TimelineItem(
                        timestamp=fact.at or bundle.window_start,
                        description=fact.statement,
                        evidence_ids=(fact.fact_id,),
                    )
                    for fact in (alert_facts[:4] + ([last] if last not in alert_facts[:4] else []))
                ),
                automated_response=tuple(
                    CitedStatement(text=fact.statement, evidence_ids=(fact.fact_id,))
                    for fact in action_facts[:4]
                ),
                analyst_actions=(
                    f"Confirm with the owner of {bundle.account} whether this activity was theirs.",
                    f"Review authentication and process context on {', '.join(bundle.hosts[:3])}.",
                    (
                        "Decide whether to keep the automatic lock or lift it."
                        if bundle.escalated
                        else "Decide whether the actions waiting for approval should run."
                    ),
                ),
                uncertainty=(
                    CitedStatement(
                        text=(
                            "Authentication telemetry shows movement, not intent: it cannot "
                            "establish what was done on the hosts reached, and a session kill "
                            "does not invalidate Kerberos tickets already issued."
                        ),
                        evidence_ids=(
                            (context_facts[-1] if context_facts else first).fact_id,
                        ),
                    ),
                ),
            ),
        )


# ---------------------------------------------------------------------------
# the agent
# ---------------------------------------------------------------------------


_SOC_SCHEMA = """Return ONE JSON object and nothing else. Shape:

{
  "headline": "one line, under 160 characters, naming the account and what happened",
  "executive_summary":  [{"text": "...", "evidence_ids": ["F-001"]}],
  "what_happened":      [{"timestamp": 123, "description": "...", "evidence_ids": ["F-001"]}],
  "automated_response": [{"text": "...", "evidence_ids": ["F-004"]}],
  "analyst_actions":    ["..."],
  "uncertainty":        [{"text": "...", "evidence_ids": ["F-007"]}]
}

Hard rules:
- Cite ONLY fact ids listed under FACTS. Never invent one.
- Every statement in automated_response MUST cite at least one fact marked
  [action] or [escalation]. Describe only actions those facts record.
- Never state that an action was executed unless a fact says so; "dry_run"
  means it was planned and performed by nothing.
- State only what the facts show. No speculation about malware, data theft,
  or attacker identity.
- Copy alert ids (GS-...) character for character from the facts, or do not
  name them at all. A wrong id is worse than no id.
- analyst_actions are advisory steps for a person: at most 5, imperative. The
  FIRST one must be a verification step (confirm the activity with the account
  owner, or check what the reached hosts were used for). Never open with
  approving a disruptive action: a report that tells an analyst to isolate
  before they have checked is how a false positive becomes an outage.
- executive_summary: at most 3 entries. All lists must be non-empty."""


def _bundle_digest(bundle: SocIncidentBundle) -> str:
    lines = [
        f"INCIDENT: {bundle.incident_id}",
        f"ACCOUNT: {bundle.account}",
        f"WINDOW: {bundle.window_start} to {bundle.window_end} "
        f"({bundle.window_end - bundle.window_start} s)",
        f"ALERTS: {len(bundle.alert_ids)} (highest fused risk {bundle.highest_risk:.4f}; "
        f"{bundle.alerts_above_gate} at or above the unattended gate)",
        f"HOSTS: {' -> '.join(bundle.hosts)}",
        f"ATT&CK: {', '.join(bundle.techniques) or 'none asserted'}",
        f"SEVERITY (computed, do not change): {bundle.severity}",
        "",
        "FACTS (cite these ids and no others):",
    ]
    for fact in bundle.facts:
        when = f" at={fact.at}" if fact.at is not None else ""
        lines.append(f"  {fact.fact_id} [{fact.kind}]{when} {fact.statement}")
    return "\n".join(lines)


def build_soc_prompt(bundle: SocIncidentBundle, violations: Sequence[str] | None = None) -> str:
    parts = [
        "You are a SOC analyst writing the incident report that hands this account to "
        "the next shift.",
        "You may use ONLY the facts below. You have no other knowledge of this network.",
        "",
        _bundle_digest(bundle),
        "",
        _SOC_SCHEMA,
    ]
    if violations:
        parts += [
            "",
            "Your previous answer was REJECTED for these contract violations:",
            *(f"  - {v}" for v in violations),
            "Return corrected JSON that fixes them.",
        ]
    return "\n".join(parts)


def _cited(raw: Any) -> tuple[CitedStatement, ...]:
    out: list[CitedStatement] = []
    for entry in raw if isinstance(raw, list) else []:
        if not isinstance(entry, dict):
            continue
        text = str(entry.get("text", "")).strip()
        ids = entry.get("evidence_ids") or []
        ids = [str(i) for i in ids] if isinstance(ids, list) else []
        if text and ids:
            out.append(CitedStatement(text=text[:800], evidence_ids=tuple(ids)))
    return tuple(out)


def parse_soc_report(raw_output: str, bundle: SocIncidentBundle) -> SocIncidentReport:
    """Map a model response onto the report schema, copying the facts back in."""
    data = _extract_json(raw_output)
    timeline: list[TimelineItem] = []
    for entry in data.get("what_happened") or []:
        if not isinstance(entry, dict):
            continue
        description = str(entry.get("description", "")).strip()
        ids = entry.get("evidence_ids") or []
        ids = [str(i) for i in ids] if isinstance(ids, list) else []
        if not description or not ids:
            continue
        try:
            timestamp = int(entry.get("timestamp", bundle.window_start))
        except (TypeError, ValueError):
            timestamp = bundle.window_start
        timeline.append(
            TimelineItem(
                timestamp=max(0, timestamp),
                description=description[:500],
                evidence_ids=tuple(ids),
            )
        )
    actions = [
        str(a).strip()[:300] for a in (data.get("analyst_actions") or []) if str(a).strip()
    ]
    headline = str(data.get("headline", "")).strip()[:200] or (
        f"{bundle.severity.upper()}: {bundle.account}"
    )
    return SocIncidentReport(
        incident_id=bundle.incident_id,
        account=bundle.account,
        headline=headline,
        severity=bundle.severity,
        window_start=bundle.window_start,
        window_end=bundle.window_end,
        alert_ids=bundle.alert_ids,
        hosts=bundle.hosts,
        actions_taken=bundle.actions_taken,
        actions_pending=bundle.actions_pending,
        executive_summary=_cited(data.get("executive_summary"))[:3],
        what_happened=tuple(timeline),
        automated_response=_cited(data.get("automated_response")),
        analyst_actions=tuple(actions[:5]),
        uncertainty=_cited(data.get("uncertainty")),
    )


class SocReportState(TypedDict, total=False):
    """State threaded through the graph, flat enough to dump into an audit."""

    bundle: SocIncidentBundle
    prompt: str
    raw_output: str
    report: SocIncidentReport | None
    violations: list[str]
    attempts: int
    trace: list[str]


def build_soc_graph(generate: Callable[[str], str], *, max_attempts: int = 3) -> Any:
    """prepare -> draft -> validate -> (repair), the same shape as triage."""
    from langgraph.graph import END, START, StateGraph

    def prepare(state: SocReportState) -> SocReportState:
        return {
            "prompt": build_soc_prompt(state["bundle"], state.get("violations")),
            "attempts": state.get("attempts", 0),
            "trace": [*state.get("trace", []), "prepare"],
        }

    def draft(state: SocReportState) -> SocReportState:
        attempts = state.get("attempts", 0) + 1
        try:
            return {
                "raw_output": generate(state["prompt"]),
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

    def validate(state: SocReportState) -> SocReportState:
        raw = state.get("raw_output") or ""
        if not raw:
            return {"report": None, "trace": [*state.get("trace", []), "validate:no-output"]}
        try:
            candidate = parse_soc_report(raw, state["bundle"])
            grounded = validate_soc_report_grounding(state["bundle"], candidate)
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

    def route(state: SocReportState) -> str:
        if state.get("report") is not None or state.get("attempts", 0) >= max_attempts:
            return "done"
        return "repair"

    graph = StateGraph(SocReportState)
    graph.add_node("prepare", prepare)
    graph.add_node("draft", draft)
    graph.add_node("validate", validate)
    graph.add_edge(START, "prepare")
    graph.add_edge("prepare", "draft")
    graph.add_edge("draft", "validate")
    graph.add_conditional_edges("validate", route, {"repair": "prepare", "done": END})
    return graph.compile()


class LangGraphSocReportProvider:
    """SOC report written by the local model, with the template as a net."""

    name = "langgraph-ollama-soc"
    version = "1"

    def __init__(
        self,
        *,
        config: AgentConfig | None = None,
        generate: Callable[[str], str] | None = None,
        fallback: Any | None = None,
    ) -> None:
        # A whole incident is more to write than one alert, so the budget is
        # larger than triage's; everything else is deliberately identical.
        self.config = config or AgentConfig(num_predict=1_400)
        self._generate = generate or (lambda prompt: ollama_generate(prompt, config=self.config))
        self._fallback = fallback or DeterministicSocReportProvider()
        self._graph = build_soc_graph(self._generate, max_attempts=self.config.max_attempts)
        self.last_trace: list[str] = []
        self.last_violations: list[str] = []
        self.used_fallback = False

    def generate(self, bundle: SocIncidentBundle) -> SocIncidentReport:
        try:
            final: SocReportState = self._graph.invoke(
                {"bundle": bundle, "attempts": 0, "trace": [], "violations": []}
            )
        except Exception as error:  # noqa: BLE001 - orchestration must never break a handover
            self.last_trace = [f"graph-error: {str(error)[:200]}"]
            self.last_violations = [str(error)[:300]]
            self.used_fallback = True
            return self._fallback.generate(bundle)
        self.last_trace = list(final.get("trace", []))
        self.last_violations = list(final.get("violations", []))
        report = final.get("report")
        if report is None:
            self.used_fallback = True
            return self._fallback.generate(bundle)
        self.used_fallback = False
        return report


def build_default_soc_provider() -> SocReportProvider:
    """The agent when triage's own flag is on, else the deterministic writer."""
    import os

    if os.getenv("GRAPHSENTINEL_TRIAGE_AGENT", "").strip().lower() not in {"1", "true", "on"}:
        return DeterministicSocReportProvider()
    from graphsentinel.explain.agent import DEFAULT_MODEL, DEFAULT_OLLAMA_HOST

    return LangGraphSocReportProvider(
        config=AgentConfig(
            model=os.getenv("GRAPHSENTINEL_OLLAMA_MODEL", DEFAULT_MODEL),
            host=os.getenv("GRAPHSENTINEL_OLLAMA_HOST", DEFAULT_OLLAMA_HOST),
            num_predict=1_400,
        )
    )


def report_to_json(report: SocIncidentReport) -> str:
    return json.dumps(json.loads(report.model_dump_json()), indent=2)


__all__ = [
    "DeterministicSocReportProvider",
    "LangGraphSocReportProvider",
    "SocAction",
    "SocFact",
    "SocIncidentBundle",
    "SocIncidentReport",
    "SocReportProvider",
    "build_default_soc_provider",
    "build_soc_graph",
    "build_soc_incident_bundle",
    "build_soc_prompt",
    "parse_soc_report",
    "report_to_json",
    "severity_for",
    "validate_soc_report_grounding",
]
