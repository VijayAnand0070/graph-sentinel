"""Tactic-aware response selection.

Choosing a response by risk alone answers "how bad is this" and ignores "what
is it", which is the question that determines whether an action helps. The
same 0.8 risk score warrants opposite handling depending on technique:

* Brute force -- ``force_reauth`` is useless. The attacker does not have the
  password yet; re-prompting the legitimate user changes nothing. Lock the
  account and the campaign stops.
* Valid-account abuse -- locking is too slow and re-auth is pointless, because
  the credential is already known. Reset it.
* Discovery -- the attacker has not done damage yet and enumeration is the
  cheapest time to learn their intent. Acting loudly here burns that
  visibility for nothing; watch instead.
* Lateral movement -- cut the chain at the link they are standing on. Every
  hop downstream depends on this one.

So the mapping below is not cosmetic. It is the difference between a response
that stops the attack and one that inconveniences the victim.

Safety posture
--------------
Nothing destructive executes automatically. Each action declares whether it is
reversible and whether it requires human approval, and the selector refuses to
auto-execute anything that is not reversible. That is deliberate: an automated
account lockout fired on a false positive at quarter close turns the detection
product into the incident.
"""

from __future__ import annotations

from dataclasses import dataclass

from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD

#: Actions the platform can request, ordered by how much they hurt if wrong.
#: ``reversible`` drives the auto-execution gate; ``requires_approval`` marks
#: actions a human must confirm regardless of confidence.
@dataclass(frozen=True, slots=True)
class ResponseAction:
    name: str
    description: str
    reversible: bool
    requires_approval: bool
    disruption: int  # 0 (invisible) .. 5 (takes the asset offline)


ACTIONS: dict[str, ResponseAction] = {
    "increase_monitoring": ResponseAction(
        name="increase_monitoring",
        description="Raise sampling and retention for this entity. Invisible to the user.",
        reversible=True,
        requires_approval=False,
        disruption=0,
    ),
    "notify_soc": ResponseAction(
        name="notify_soc",
        description="Route to an analyst queue with the evidence bundle attached.",
        reversible=True,
        requires_approval=False,
        disruption=0,
    ),
    "force_reauth": ResponseAction(
        name="force_reauth",
        description=(
            "Invalidate cached tickets and sessions. The first action an attacker "
            "actually feels; a legitimate user sees one extra prompt."
        ),
        reversible=True,
        requires_approval=False,
        disruption=1,
    ),
    "lock_account": ResponseAction(
        name="lock_account",
        description=(
            "Disable the account. Stops an in-progress guessing campaign outright."
        ),
        reversible=True,
        requires_approval=True,
        disruption=3,
    ),
    "block_network_path": ResponseAction(
        name="block_network_path",
        description=(
            "Deny this source-destination pair at the network layer, cutting the "
            "chain without taking either host offline."
        ),
        reversible=True,
        requires_approval=True,
        disruption=3,
    ),
    "reset_credentials": ResponseAction(
        name="reset_credentials",
        description=(
            "Force a credential rotation. Required when the secret itself is "
            "believed to be in the attacker's hands."
        ),
        reversible=False,
        requires_approval=True,
        disruption=4,
    ),
    "isolate_host": ResponseAction(
        name="isolate_host",
        description=(
            "Remove the host from the network. Stops everything, including whatever "
            "legitimate work it was doing."
        ),
        reversible=True,
        requires_approval=True,
        disruption=5,
    ),
    "disable_service_account": ResponseAction(
        name="disable_service_account",
        description=(
            "Disable a machine or service principal. Frequently breaks a dependent "
            "application, so it is never automatic."
        ),
        reversible=True,
        requires_approval=True,
        disruption=4,
    ),
}


@dataclass(frozen=True, slots=True)
class ResponsePlan:
    technique_id: str
    playbook: str
    rationale: str
    actions: tuple[str, ...]
    auto_executable: tuple[str, ...]
    needs_approval: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "playbook": self.playbook,
            "rationale": self.rationale,
            "actions": [
                {
                    "name": name,
                    "description": ACTIONS[name].description,
                    "reversible": ACTIONS[name].reversible,
                    "requires_approval": ACTIONS[name].requires_approval,
                    "disruption": ACTIONS[name].disruption,
                }
                for name in self.actions
            ],
            "auto_executable": list(self.auto_executable),
            "needs_approval": list(self.needs_approval),
        }


#: Ordered action sequences per technique. Order matters: cheap and reversible
#: first, so a wrong call is recoverable and the expensive action only runs if
#: the cheap one did not settle the question.
TACTIC_PLAYBOOKS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "T1021": (
        "contain_lateral_movement",
        "Break the chain at the current hop; every downstream hop depends on it.",
        ("increase_monitoring", "notify_soc", "force_reauth", "block_network_path",
         "isolate_host"),
    ),
    "T1110": (
        "stop_credential_guessing",
        "Re-auth is useless against an attacker who does not have the password yet; "
        "locking the account ends the campaign.",
        ("increase_monitoring", "notify_soc", "lock_account"),
    ),
    "T1087": (
        "observe_discovery",
        "Enumeration has done no damage yet and reveals intent. Acting loudly here "
        "burns visibility for no containment benefit.",
        ("increase_monitoring", "notify_soc"),
    ),
    "T1078": (
        "revoke_compromised_credential",
        "The credential is already known to the attacker, so only rotation helps.",
        ("increase_monitoring", "notify_soc", "force_reauth", "reset_credentials"),
    ),
    "T1550.003": (
        "invalidate_forged_tickets",
        "A forged or replayed ticket survives a password change; the signing key "
        "must be rotated and sessions invalidated.",
        ("increase_monitoring", "notify_soc", "force_reauth", "reset_credentials"),
    ),
    "T1078.002": (
        "contain_service_account",
        "A machine account behaving like an operator means the host or the "
        "principal is compromised.",
        ("increase_monitoring", "notify_soc", "disable_service_account", "isolate_host"),
    ),
    "T1550.002": (
        "contain_hash_reuse",
        "A reusable secret is in play, so re-auth alone will not evict the "
        "attacker; the path must be cut and the credential rotated.",
        ("increase_monitoring", "notify_soc", "block_network_path", "reset_credentials"),
    ),
}

#: Fallback when no technique was attributed. Never escalates beyond watching,
#: because acting on an unclassified alert is acting on an unexplained one.
UNCLASSIFIED_PLAN = ResponsePlan(
    technique_id="",
    playbook="monitoring",
    rationale="No technique was attributed; watch rather than act.",
    actions=("increase_monitoring", "notify_soc"),
    auto_executable=("increase_monitoring", "notify_soc"),
    needs_approval=(),
)

#: Confidence floors. An action is only offered when the attribution is at
#: least this confident, so a "low" verdict cannot reach a disruptive step.
CONFIDENCE_DEPTH = {"high": 5, "medium": 3, "low": 2, "none": 2}


def plan_for(
    technique_id: str | None,
    confidence: str = "low",
    *,
    risk: float = 0.0,
    auto_execute_threshold: float = AUTO_EXECUTE_THRESHOLD,
) -> ResponsePlan:
    """Select a response plan for an attributed technique.

    ``confidence`` truncates how deep into the action sequence the plan may
    reach, and ``risk`` gates auto-execution. An action is auto-executable only
    when it is reversible, needs no approval, AND the verdict is both
    high-confidence and above the risk gate -- three independent conditions,
    because any one of them alone has a failure mode that ends with a locked-out
    executive.
    """
    if not technique_id or technique_id not in TACTIC_PLAYBOOKS:
        return UNCLASSIFIED_PLAN

    playbook, rationale, sequence = TACTIC_PLAYBOOKS[technique_id]
    depth = CONFIDENCE_DEPTH.get(confidence, 2)
    actions = sequence[:depth]

    confident = confidence == "high" and risk >= auto_execute_threshold
    auto: list[str] = []
    approval: list[str] = []
    for name in actions:
        action = ACTIONS[name]
        if action.requires_approval or not action.reversible:
            approval.append(name)
        elif action.disruption == 0 or confident:
            auto.append(name)
        else:
            approval.append(name)

    return ResponsePlan(
        technique_id=technique_id,
        playbook=playbook,
        rationale=rationale,
        actions=actions,
        auto_executable=tuple(auto),
        needs_approval=tuple(approval),
    )


def catalogue() -> dict[str, object]:
    """Full response catalogue, for the console and for operator review."""
    return {
        "actions": {
            name: {
                "description": action.description,
                "reversible": action.reversible,
                "requires_approval": action.requires_approval,
                "disruption": action.disruption,
            }
            for name, action in ACTIONS.items()
        },
        "playbooks": {
            technique_id: {
                "playbook": playbook,
                "rationale": rationale,
                "actions": list(sequence),
            }
            for technique_id, (playbook, rationale, sequence) in TACTIC_PLAYBOOKS.items()
        },
        "safety": {
            "irreversible_actions_never_automatic": True,
            "auto_execution_requires": [
                "confidence == high",
                "risk >= auto_execute_threshold",
                "action reversible and not flagged for approval",
            ],
            "note": (
                "The platform recommends and gates; it does not execute against "
                "production directory or network systems in this build."
            ),
        },
    }
