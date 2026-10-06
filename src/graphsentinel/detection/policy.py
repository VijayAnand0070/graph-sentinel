"""What a rule-detected chain is allowed to do, and how the rule is shaped.

Two decisions that were hard-coded and are now measured choices:

``ChainRuleConfig`` -- the shape of the deterministic chain rule: how many
onward hops by the same account, inside what window, and whether only hops to
destinations the account has *never* reached count. Finding 13 measured the
first two on the labelled corpus; Finding 25 measures all three on the corpus
(false-positive cost) and on the prevention instrument (hops prevented).

``ChainRulePolicy`` -- what the rule may do once it fires. ``alert_only``
raises the fused risk to the alert floor (0.60), which is below the execution
gate, so a rule-caught chain is shown and never acted on unattended: this was
the shipped behaviour and it is why Finding 21 measured zero chain hops
prevented. ``unattended`` makes the rule a first-class trigger: the tactic
engine asserts T1021 at high confidence (a same-account multi-hop chain *is*
lateral movement, by definition, not by a fitted score) and the risk is raised
to the execution gate, so the unattended action -- a session kill -- follows
without a person. Its price is every benign chain the rule catches: those
users get one re-login prompt. Both sides are numbers in Finding 25.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from graphsentinel.detection.fusion import CHAIN_RULE_FLOOR
from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
from graphsentinel.detection.signals import (
    DEFAULT_CHAIN_WINDOW_SECONDS,
    DEFAULT_MINIMUM_PRIOR_HOPS,
    DEFAULT_REQUIRE_NOVEL,
    ChainPivotTracker,
    SignalTracker,
)

PolicyName = Literal["alert_only", "unattended", "corroborated"]


@dataclass(frozen=True, slots=True)
class ChainRuleConfig:
    """The shape of the chain rule. ``prior_hops`` onward moves by one account
    within ``window_seconds``; with ``novel_only`` only moves to a destination
    the account has never reached before count as hops."""

    prior_hops: int = DEFAULT_MINIMUM_PRIOR_HOPS
    window_seconds: int = DEFAULT_CHAIN_WINDOW_SECONDS
    novel_only: bool = DEFAULT_REQUIRE_NOVEL

    def __post_init__(self) -> None:
        if self.prior_hops < 1:
            raise ValueError("a chain needs at least one prior hop")
        if self.window_seconds <= 0:
            raise ValueError("chain window must be positive")

    @property
    def name(self) -> str:
        novelty = "novel" if self.novel_only else "any"
        return f"{self.prior_hops + 1}hops-{self.window_seconds}s-{novelty}"

    def tracker(self) -> SignalTracker:
        return SignalTracker(
            chains=ChainPivotTracker(
                window_seconds=self.window_seconds,
                minimum_prior_hops=self.prior_hops,
                require_novel=self.novel_only,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "prior_hops": self.prior_hops,
            "window_seconds": self.window_seconds,
            "novel_only": self.novel_only,
        }

    @classmethod
    def parse(cls, text: str) -> ChainRuleConfig:
        """``"4hops-300s-any"`` or ``"3hops-1800s-novel"`` -- the ``name`` form."""
        try:
            hops_part, window_part, novelty = text.strip().lower().split("-")
            hops = int(hops_part.removesuffix("hops"))
            window = int(window_part.removesuffix("s"))
        except ValueError as error:
            raise ValueError(
                f"chain rule must look like '4hops-300s-any' or '3hops-1800s-novel', not {text!r}"
            ) from error
        if novelty not in {"any", "novel"}:
            raise ValueError(f"chain rule novelty must be 'any' or 'novel', not {novelty!r}")
        return cls(prior_hops=hops - 1, window_seconds=window, novel_only=novelty == "novel")


@dataclass(frozen=True, slots=True)
class ChainRulePolicy:
    name: PolicyName
    #: The fused risk a rule-detected chain is raised to.
    floor: float
    #: Whether the tactic engine asserts T1021 at high confidence on a chain.
    asserts_technique: bool
    #: Whether the rule may only raise the risk when the model already put
    #: the event over the alert threshold: two independent signals before an
    #: automatic action, at the price of the chains the model scores low.
    requires_model_alert: bool = False

    @property
    def unattended(self) -> bool:
        """Can a rule-detected chain, on its own, trigger the unattended action?"""
        return self.asserts_technique and self.floor >= AUTO_EXECUTE_THRESHOLD

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "floor": self.floor,
            "asserts_technique": self.asserts_technique,
            "requires_model_alert": self.requires_model_alert,
            "unattended": self.unattended,
            "execution_gate": AUTO_EXECUTE_THRESHOLD,
        }


ALERT_ONLY = ChainRulePolicy(name="alert_only", floor=CHAIN_RULE_FLOOR, asserts_technique=False)
UNATTENDED = ChainRulePolicy(
    name="unattended", floor=AUTO_EXECUTE_THRESHOLD, asserts_technique=True
)
CORROBORATED = ChainRulePolicy(
    name="corroborated",
    floor=AUTO_EXECUTE_THRESHOLD,
    asserts_technique=True,
    requires_model_alert=True,
)
POLICIES: dict[str, ChainRulePolicy] = {
    p.name: p for p in (ALERT_ONLY, UNATTENDED, CORROBORATED)
}

#: The shipped defaults, chosen by the chain-rule study (Finding 25) rather
#: than by hand, and re-chosen once the same rules were priced at full rate.
#: Against 100 campaigns from ordinary workstations, the rule shipped until
#: now (4 hops in 300 s, any destination, alert only) detected 21 and
#: prevented 0.75% of hops -- and on an unsampled day flags 715-855 benign
#: events per 10,000, a cost the sampled corpus had hidden entirely. Four
#: *novel* hops in 1,800 s -- moves to hosts the account has never reached
#: -- detects 44 (36 of the 50 chains) at the fourth move and, allowed to
#: trigger the unattended action, prevents 13.9% of hops; on the instrument
#: it costs 6.15 benign session kills per 10,000 (5.46 without the rule),
#: and on the unsampled day its flag rate falls from 250 per 10,000 in the
#: first cold hour to 0-9 by the last hours, still falling as history
#: accumulates. Three novel hops in 1,800 s prevents 20.8% but sits at 21-55
#: per 10,000 after one day of history: an option for a deployment warmed
#: with weeks of history that has measured its own rate
#: (``scripts/chain_rule_hourly.py``), not a default. Whatever the rate, the
#: response coordinator's unattended budget bounds the worst hour.
DEFAULT_POLICY = UNATTENDED
#: The class defaults in ``detection/signals.py`` are the same rule, so a bare
#: ``SignalTracker()`` -- the scored-cache builder, the training pipeline --
#: computes the channel the product computes.
DEFAULT_CHAIN_RULE = ChainRuleConfig()


def policy_from_environment() -> ChainRulePolicy:
    name = os.getenv("GRAPHSENTINEL_CHAIN_RULE_POLICY", DEFAULT_POLICY.name).strip().lower()
    try:
        return POLICIES[name]
    except KeyError as error:
        raise ValueError(
            f"GRAPHSENTINEL_CHAIN_RULE_POLICY must be one of {sorted(POLICIES)}, not {name!r}"
        ) from error


def chain_rule_from_environment() -> ChainRuleConfig:
    text = os.getenv("GRAPHSENTINEL_CHAIN_RULE", "").strip()
    return ChainRuleConfig.parse(text) if text else DEFAULT_CHAIN_RULE


__all__ = [
    "ALERT_ONLY",
    "CORROBORATED",
    "DEFAULT_CHAIN_RULE",
    "DEFAULT_POLICY",
    "POLICIES",
    "UNATTENDED",
    "ChainRuleConfig",
    "ChainRulePolicy",
    "chain_rule_from_environment",
    "policy_from_environment",
]
