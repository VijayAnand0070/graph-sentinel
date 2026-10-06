"""Simulated SOAR-style response playbooks: named, conditional action sequences.

A detection is only half of a SOC's job — the other half is "now what do we
do about it." This module models that second half as data: a playbook is an
ordered sequence of response actions, each gated by a minimum-risk condition,
so a low-severity trigger doesn't get the same heavy-handed response as a
confirmed critical one. Execution is entirely simulated (no real
infrastructure calls) but the audit trail — what ran, what was skipped and
why, when — is real and persisted, which is the actual point of a SOAR audit
log: an accountable record of the response decision, independent of whether
the actions themselves were simulated or real.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Iterable, Literal

ActionType = Literal[
    "isolate_host",
    "reset_credentials",
    "force_reauth",
    "block_network_path",
    "increase_monitoring",
    "notify_soc",
]
EntityKind = Literal["user", "host"]
#: What actually happened to a step. ``executed`` means a connector ran it
#: through an armed backend; ``dry_run`` means the command was planned and
#: recorded but nothing was performed (the default); ``pending_approval``
#: means the catalogue requires a person and none approved it. The earlier
#: version reported ``executed`` for any step whose risk bar was cleared,
#: including irreversible ones, with nothing behind it -- an audit record
#: asserting actions nobody took.
if TYPE_CHECKING:  # pragma: no cover - annotations only
    from graphsentinel.response.executor import Approval, ResponseExecutor

StepStatus = Literal[
    "executed", "dry_run", "pending_approval", "failed", "skipped_condition_not_met",
]


@dataclass(frozen=True, slots=True)
class PlaybookStep:
    """One templated action, gated by how risky the triggering entity must be."""

    action: ActionType
    minimum_risk: float = 0.0
    detail_template: str = "{action} on {entity}"

    def __post_init__(self) -> None:
        if not 0 <= self.minimum_risk <= 1:
            raise ValueError("minimum_risk must be in [0, 1]")


@dataclass(frozen=True, slots=True)
class PlaybookDefinition:
    name: str
    description: str
    steps: tuple[PlaybookStep, ...]

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must be non-empty")
        if not self.steps:
            raise ValueError("a playbook must have at least one step")


@dataclass(frozen=True, slots=True)
class PlaybookStepResult:
    action: ActionType
    status: StepStatus
    detail: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class PlaybookExecution:
    playbook_name: str
    entity: str
    entity_kind: EntityKind
    risk_at_trigger: float
    steps: tuple[PlaybookStepResult, ...]
    triggered_at: int

    def to_dict(self) -> dict[str, object]:
        return {
            "playbook_name": self.playbook_name,
            "entity": self.entity,
            "entity_kind": self.entity_kind,
            "risk_at_trigger": self.risk_at_trigger,
            "steps": [s.to_dict() for s in self.steps],
            "triggered_at": self.triggered_at,
        }


def execute_playbook(
    definition: PlaybookDefinition,
    *,
    entity: str,
    entity_kind: EntityKind,
    risk: float,
    now: int,
    executor: "ResponseExecutor | None" = None,
    approvals: Iterable["Approval"] = (),
    execution_id: str | None = None,
) -> PlaybookExecution:
    """Dispatch every step whose risk bar is cleared through the response executor.

    The risk bar decides which steps are *attempted*; the executor decides
    what becomes of each attempt, and its answer is the step's status. With
    the default executor nothing is performed and every attempted step reads
    ``dry_run`` with its planned command; steps the action catalogue reserves
    for a person read ``pending_approval`` unless an approval for this
    execution names them. Nothing in this function can mark a step
    ``executed`` on its own -- only an armed backend can, and only by running
    the command.
    """
    from graphsentinel.response.connectors import Target
    from graphsentinel.response.executor import ResponseExecutor

    if not entity:
        raise ValueError("entity must be non-empty")
    if not 0 <= risk <= 1:
        raise ValueError("risk must be in [0, 1]")

    executor = executor or ResponseExecutor()
    alert_id = execution_id or f"playbook:{definition.name}:{entity}:{now}"
    target = (Target(account=entity) if entity_kind == "user"
              else Target(host=entity, source_host=entity))
    granted = {a.action: a for a in approvals if a.alert_id == alert_id}

    results = []
    for step in definition.steps:
        if risk < step.minimum_risk:
            results.append(PlaybookStepResult(
                action=step.action, status="skipped_condition_not_met",
                detail=(f"requires risk >= {step.minimum_risk:.2f}, "
                        f"{entity} was at {risk:.3f} when triggered"),
            ))
            continue
        record = executor.execute_action(
            step.action, alert_id=alert_id, target=target, unattended=True,
            approval=granted.get(step.action),
        )
        intent = step.detail_template.format(action=step.action, entity=entity, risk=risk)
        if record.outcome == "executed":
            status: StepStatus = "executed"
            detail = intent
        elif record.outcome == "dry_run":
            status = "dry_run"
            command = record.command.text if record.command else ""
            detail = f"planned, not performed (no armed backend): {command}"
        elif record.outcome == "pending_approval":
            status = "pending_approval"
            detail = f"requires approval by a person: {intent}"
        else:
            status = "failed"
            detail = f"{record.outcome}: {record.error or intent}"
        results.append(PlaybookStepResult(action=step.action, status=status, detail=detail))

    return PlaybookExecution(
        playbook_name=definition.name,
        entity=entity,
        entity_kind=entity_kind,
        risk_at_trigger=risk,
        steps=tuple(results),
        triggered_at=now,
    )


CONTAINMENT_PLAYBOOK = PlaybookDefinition(
    name="containment",
    description="Full containment for a confirmed high-confidence compromise.",
    steps=(
        PlaybookStep("increase_monitoring", minimum_risk=0.0, detail_template="Elevated monitoring enabled for {entity}"),
        PlaybookStep("notify_soc", minimum_risk=0.5, detail_template="SOC paged for {entity} (risk {risk:.3f})"),
        PlaybookStep("force_reauth", minimum_risk=0.7, detail_template="Forced re-authentication issued for {entity}"),
        PlaybookStep("block_network_path", minimum_risk=0.8, detail_template="Blocked outbound authentication paths from {entity}"),
        PlaybookStep("isolate_host", minimum_risk=0.85, detail_template="Isolated {entity} from the network"),
        PlaybookStep("reset_credentials", minimum_risk=0.9, detail_template="Credentials reset for {entity}"),
    ),
)

INVESTIGATION_PLAYBOOK = PlaybookDefinition(
    name="investigation",
    description="Moderate response: gather evidence and tighten monitoring without disrupting the entity.",
    steps=(
        PlaybookStep("increase_monitoring", minimum_risk=0.0, detail_template="Elevated monitoring enabled for {entity}"),
        PlaybookStep("notify_soc", minimum_risk=0.4, detail_template="SOC notified for review of {entity} (risk {risk:.3f})"),
        PlaybookStep("force_reauth", minimum_risk=0.6, detail_template="Forced re-authentication issued for {entity}"),
    ),
)

MONITORING_PLAYBOOK = PlaybookDefinition(
    name="monitoring",
    description="Lightweight response for low-confidence signals: watch, don't act.",
    steps=(
        PlaybookStep("increase_monitoring", minimum_risk=0.0, detail_template="Elevated monitoring enabled for {entity}"),
        PlaybookStep("notify_soc", minimum_risk=0.3, detail_template="SOC informed of {entity} for awareness (risk {risk:.3f})"),
    ),
)

PLAYBOOK_CATALOG: dict[str, PlaybookDefinition] = {
    playbook.name: playbook
    for playbook in (CONTAINMENT_PLAYBOOK, INVESTIGATION_PLAYBOOK, MONITORING_PLAYBOOK)
}
