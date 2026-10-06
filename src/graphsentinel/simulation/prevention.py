"""The prevention instrument: what the shipped stack does to a known campaign.

Composition mirrors ``api/live.py`` step for step -- explicit signals, chain
tracker, tactic attribution, TGN probability, fusion, rule floor, threshold,
response plan -- because a harness that re-implements any of it measures the
re-implementation. The TGN is injected as a scorer so the logic can be tested
with a stub, and so a different checkpoint can be measured without touching
anything else.

Metrics, per campaign
---------------------
* **Detection latency in hops**: the index of the first hop that alerted.
  Hop 0 means the first move was caught; hop 3 means the attacker completed
  three moves first. This is the number that describes damage.
* **Hops prevented**: hops that would not have happened had the automated
  response taken effect. Reported under two semantics, because the honest
  answer depends on what the attacker holds:

  - ``campaign``: the first unattended disruptive action ends the campaign.
    Right for a chain under one account, or an attacker holding only session
    material.
  - ``account``: an action against one account stops only that account's
    later hops. Right for a fan-out rotating harvested credentials, where
    killing one session leaves the others intact.

  Nothing above ``force_reauth`` ever runs unattended (Finding 15), so
  "prevented" here always means "prevented by session invalidation", and
  everything requiring approval is counted as *recommended*, not done.

* **Benign cost**: benign events alerted, benign events that would have been
  auto-actioned, and distinct benign users hit -- the price of the policy in
  the same window.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import groupby
from typing import TYPE_CHECKING, cast

import numpy as np

from graphsentinel.detection.fusion import (
    RiskComponents,
    apply_rule_floor,
    fuse_risk,
    select_fusion,
)
from graphsentinel.detection.policy import (
    DEFAULT_CHAIN_RULE,
    DEFAULT_POLICY,
    ChainRuleConfig,
    ChainRulePolicy,
)
from graphsentinel.detection.response import plan_for
from graphsentinel.detection.signals import FanOutTracker
from graphsentinel.detection.tactics import TacticEngine
from graphsentinel.features.causal import MODEL_FEATURE_NAMES, FeatureRecord
from graphsentinel.simulation.campaigns import CampaignSpec
from graphsentinel.simulation.generator import Truth

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from graphsentinel.ingestion.id_map import AuthIdMaps, StableIdMap
    from graphsentinel.models.serving import TGNInferenceSession

#: One timestamp group of records in, one probability per record out.
Scorer = Callable[[Sequence[FeatureRecord]], Sequence[float]]

#: The only disruptive action the response layer may run unattended.
UNATTENDED_ACTION = "force_reauth"


@dataclass(frozen=True, slots=True)
class EntityNames:
    """Raw category names the tactic rules key on (never dictionary indices)."""

    users: Sequence[str]
    logon_types: Sequence[str]
    auth_types: Sequence[str]
    orientations: Sequence[str]

    @classmethod
    def from_id_maps(cls, maps: AuthIdMaps) -> EntityNames:
        def values(mapping: StableIdMap) -> list[str]:
            return list(cast("list[str]", mapping.to_dict()["values"]))

        return cls(
            values(maps.users),
            values(maps.logon_types),
            values(maps.auth_types),
            values(maps.orientations),
        )

    @classmethod
    def anonymous(cls) -> EntityNames:
        """For tests and stubbed runs: no names, so name-keyed rules stay quiet."""
        return cls((), (), (), ())

    def _at(self, table: Sequence[str], index: int) -> str:
        return table[index] if 0 <= index < len(table) else ""

    def user(self, index: int) -> str:
        return self._at(self.users, index)

    def logon_type(self, index: int) -> str:
        return self._at(self.logon_types, index)

    def auth_type(self, index: int) -> str:
        return self._at(self.auth_types, index)

    def orientation(self, index: int) -> str:
        return self._at(self.orientations, index)


def transfer_scorer(session, names: EntityNames, hosts: Sequence[str]) -> Scorer:  # type: ignore[no-untyped-def]
    """Score through a transfer-model session (calibrated risk), advancing its memory.

    Entities are passed by name, as onboarding and the live gateway pass them,
    so the memory warmed at onboarding is the memory read here."""
    from graphsentinel.models.serving import InferenceEvent
    from graphsentinel.models.transfer_serving import transfer_message

    def host(index: int) -> str | None:
        return hosts[index] if 0 <= index < len(hosts) else None

    def score(group: Sequence[FeatureRecord]) -> Sequence[float]:
        events = [
            InferenceEvent(
                event_id=r.event_id,
                timestamp=r.timestamp,
                user_id=r.src_user_id,
                source_host_id=r.src_host_id,
                destination_host_id=r.dst_host_id,
                message=transfer_message(
                    r,
                    auth_type=names.auth_type(r.auth_type_id),
                    logon_type=names.logon_type(r.logon_type_id),
                    orientation=names.orientation(r.orientation_id),
                ),
                user_name=names.user(r.src_user_id) or None,
                source_name=host(r.src_host_id),
                destination_name=host(r.dst_host_id),
            )
            for r in group
        ]
        preview = session.preview(events)
        session.commit(preview)
        return list(preview.probabilities)

    return score


def session_scorer(session: TGNInferenceSession) -> Scorer:
    """Score through a live InferenceSession, advancing its memory."""
    from graphsentinel.models.serving import InferenceEvent

    def score(group: Sequence[FeatureRecord]) -> Sequence[float]:
        events = [
            InferenceEvent(
                event_id=r.event_id,
                timestamp=r.timestamp,
                user_id=r.src_user_id,
                source_host_id=r.src_host_id,
                destination_host_id=r.dst_host_id,
                message=tuple(float(getattr(r, name)) for name in MODEL_FEATURE_NAMES),
            )
            for r in group
        ]
        preview = session.preview(events)
        session.commit(preview)
        return list(preview.probabilities)

    return score


@dataclass(frozen=True, slots=True)
class EventOutcome:
    event_id: int
    timestamp: int
    user_id: int
    risk: float
    alerted: bool
    technique_id: str | None
    confidence: str
    auto_actioned: bool
    recommended: tuple[str, ...]
    campaign_id: str | None
    hop_index: int | None
    #: What the truth table says this event is; None for benign traffic.
    expected_technique: str | None = None


@dataclass
class CampaignOutcome:
    campaign_id: str
    family: str
    interval_seconds: int
    length: int
    hops: list[EventOutcome] = field(default_factory=list)

    @property
    def first_alert_hop(self) -> int | None:
        alerted = [h.hop_index for h in self.hops if h.alerted and h.hop_index is not None]
        return min(alerted) if alerted else None

    @property
    def detected(self) -> bool:
        return self.first_alert_hop is not None

    @property
    def alerted_hops(self) -> int:
        return sum(1 for h in self.hops if h.alerted)

    @property
    def first_auto_action_hop(self) -> int | None:
        acted = [h.hop_index for h in self.hops if h.auto_actioned and h.hop_index is not None]
        return min(acted) if acted else None

    @property
    def max_risk(self) -> float:
        return max((h.risk for h in self.hops), default=0.0)

    @property
    def technique_at_first_alert(self) -> str | None:
        for h in sorted(self.hops, key=lambda x: x.hop_index or 0):
            if h.alerted:
                return h.technique_id
        return None

    def hops_prevented(self, semantics: str = "campaign") -> int:
        """Hops that would not have occurred, under the stated semantics."""
        if semantics == "campaign":
            first = self.first_auto_action_hop
            return 0 if first is None else self.length - first - 1
        if semantics == "account":
            stopped_accounts: dict[int, int] = {}
            for h in sorted(self.hops, key=lambda x: x.hop_index or 0):
                if h.auto_actioned and h.user_id not in stopped_accounts:
                    stopped_accounts[h.user_id] = h.hop_index or 0
            return sum(
                1
                for h in self.hops
                if h.user_id in stopped_accounts
                and (h.hop_index or 0) > stopped_accounts[h.user_id]
            )
        raise ValueError(f"unknown prevention semantics {semantics!r}")

    def hops_prevented_with_loop(
        self,
        *,
        kill_effectiveness: float,
        escalation: bool,
        escalation_window_seconds: int = 1_800,
        seed: int = 0,
    ) -> int:
        """Campaign semantics, with the response loop modelled.

        ``kill_effectiveness`` is the probability that the first unattended
        session kill actually stops the attacker (an issued Kerberos ticket
        survives a kill; a stolen session cookie may not). When it does not,
        the attacker keeps moving; with ``escalation`` on, the next hop that
        would itself qualify for an unattended action inside the window
        triggers the account lock, which stops the campaign for certain. The
        draw is deterministic per campaign so runs are reproducible.
        """
        if not 0.0 <= kill_effectiveness <= 1.0:
            raise ValueError("kill_effectiveness must be in [0, 1]")
        acted = sorted(
            (h for h in self.hops if h.auto_actioned and h.hop_index is not None),
            key=lambda h: h.hop_index or 0,
        )
        if not acted:
            return 0
        first = acted[0]
        # Deterministic uniform draw in [0, 1) from the campaign id and seed.
        digest = hashlib.sha256(f"{self.campaign_id}|{seed}".encode()).digest()
        draw = int.from_bytes(digest[:8], "big") / float(1 << 64)
        if draw < kill_effectiveness:
            return self.length - (first.hop_index or 0) - 1
        if not escalation:
            return 0
        for later in acted[1:]:
            if later.timestamp - first.timestamp <= escalation_window_seconds:
                return self.length - (later.hop_index or 0) - 1
        return 0

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "family": self.family,
            "interval_seconds": self.interval_seconds,
            "length": self.length,
            "detected": self.detected,
            "first_alert_hop": self.first_alert_hop,
            "alerted_hops": self.alerted_hops,
            "first_auto_action_hop": self.first_auto_action_hop,
            "hops_prevented_campaign": self.hops_prevented("campaign"),
            "hops_prevented_account": self.hops_prevented("account"),
            "max_risk": round(self.max_risk, 6),
            "technique_at_first_alert": self.technique_at_first_alert,
        }


@dataclass
class PreventionReport:
    operating_point: str
    threshold: float
    campaigns: list[CampaignOutcome]
    benign_events: int
    benign_alerted: int
    benign_auto_actioned: int
    benign_users_hit: int
    events: list[EventOutcome] = field(default_factory=list, repr=False)
    chain_rule: str = "4hops-1800s-novel"
    policy: str = "unattended"

    # ------------------------------------------------------------- aggregates
    def detection_rate(self, subset: Iterable[CampaignOutcome] | None = None) -> float:
        items = list(self.campaigns if subset is None else subset)
        return sum(c.detected for c in items) / len(items) if items else 0.0

    def latency_hops(self, subset: Iterable[CampaignOutcome] | None = None) -> list[int]:
        items = self.campaigns if subset is None else subset
        return [c.first_alert_hop for c in items if c.first_alert_hop is not None]

    def prevented_fraction(
        self, semantics: str, subset: Iterable[CampaignOutcome] | None = None
    ) -> float:
        items = list(self.campaigns if subset is None else subset)
        total = sum(c.length for c in items)
        return sum(c.hops_prevented(semantics) for c in items) / total if total else 0.0

    def prevented_fraction_with_loop(
        self,
        *,
        kill_effectiveness: float,
        escalation: bool,
        subset: Iterable[CampaignOutcome] | None = None,
    ) -> float:
        items = list(self.campaigns if subset is None else subset)
        total = sum(c.length for c in items)
        prevented = sum(
            c.hops_prevented_with_loop(
                kill_effectiveness=kill_effectiveness, escalation=escalation
            )
            for c in items
        )
        return prevented / total if total else 0.0

    def loop_table(self) -> list[dict[str, object]]:
        """What the escalation rung is worth as the session kill gets weaker."""
        rows: list[dict[str, object]] = []
        for effectiveness in (1.0, 0.75, 0.5, 0.25, 0.0):
            without = self.prevented_fraction_with_loop(
                kill_effectiveness=effectiveness, escalation=False
            )
            with_loop = self.prevented_fraction_with_loop(
                kill_effectiveness=effectiveness, escalation=True
            )
            rows.append(
                {
                    "kill_effectiveness": effectiveness,
                    "prevented_without_escalation": round(without, 4),
                    "prevented_with_escalation": round(with_loop, 4),
                    "campaigns_escalated": sum(
                        1
                        for c in self.campaigns
                        if c.hops_prevented_with_loop(
                            kill_effectiveness=effectiveness, escalation=True
                        )
                        > c.hops_prevented_with_loop(
                            kill_effectiveness=effectiveness, escalation=False
                        )
                    ),
                }
            )
        return rows

    def by_family(self) -> dict[str, dict[str, object]]:
        out: dict[str, dict[str, object]] = {}
        for family in sorted({c.family for c in self.campaigns}):
            subset = [c for c in self.campaigns if c.family == family]
            out[family] = self._summary(subset)
        return out

    def by_interval(self) -> dict[int, dict[str, object]]:
        """The evasion curve: how detection degrades as the attacker slows."""
        out: dict[int, dict[str, object]] = {}
        for interval in sorted({c.interval_seconds for c in self.campaigns}):
            subset = [c for c in self.campaigns if c.interval_seconds == interval]
            out[interval] = self._summary(subset)
        return out

    def _summary(self, subset: list[CampaignOutcome]) -> dict[str, object]:
        latencies = self.latency_hops(subset)
        return {
            "campaigns": len(subset),
            "detected": sum(c.detected for c in subset),
            "detection_rate": round(self.detection_rate(subset), 4),
            "median_latency_hops": (float(np.median(latencies)) if latencies else None),
            "mean_latency_hops": (round(float(np.mean(latencies)), 3) if latencies else None),
            "prevented_fraction_campaign": round(self.prevented_fraction("campaign", subset), 4),
            "prevented_fraction_account": round(self.prevented_fraction("account", subset), 4),
        }

    @property
    def benign_alert_rate_per_10k(self) -> float:
        return 10_000 * self.benign_alerted / self.benign_events if self.benign_events else 0.0

    @property
    def benign_auto_action_rate_per_10k(self) -> float:
        return (
            10_000 * self.benign_auto_actioned / self.benign_events if self.benign_events else 0.0
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "operating_point": self.operating_point,
            "threshold": self.threshold,
            "chain_rule": self.chain_rule,
            "policy": self.policy,
            "unattended_action": UNATTENDED_ACTION,
            "prevention_semantics": {
                "campaign": "first unattended action ends the campaign",
                "account": "an action stops only that account's later hops",
            },
            "overall": self._summary(self.campaigns),
            "by_family": self.by_family(),
            "by_interval": {str(k): v for k, v in self.by_interval().items()},
            "benign": {
                "events": self.benign_events,
                "alerted": self.benign_alerted,
                "alert_rate_per_10k": round(self.benign_alert_rate_per_10k, 3),
                "auto_actioned": self.benign_auto_actioned,
                "auto_action_rate_per_10k": round(self.benign_auto_action_rate_per_10k, 3),
                "users_hit": self.benign_users_hit,
            },
            "loop": self.loop_table(),
            "campaigns": [c.to_dict() for c in self.campaigns],
        }


def measure_prevention(
    records: Sequence[FeatureRecord],
    truth: Mapping[int, Truth],
    campaigns: Sequence[CampaignSpec],
    *,
    scorer: Scorer,
    names: EntityNames,
    operating_point: str = "noisy_or",
    corroboration: float = 0.0,
    chain_rule_floor: float | None = None,
    chain_rule: ChainRuleConfig | None = None,
    policy: ChainRulePolicy | None = None,
    fanout: FanOutTracker | None = None,
) -> PreventionReport:
    """Run the shipped detection stack over a scored stream and account for it.

    ``chain_rule`` is the shape of the deterministic chain rule and ``policy``
    what a detected chain may do, exactly as the live gateway composes them
    (``detection/policy.py``). The defaults are the shipped ones. ``fanout``,
    when given, adds the fan-out rule beside the chain rule, with the same
    floor and the same policy. A bare
    ``chain_rule_floor`` is kept for older callers: it sets the floor and lets
    the rule assert nothing, which is the ``alert_only`` policy at that floor.
    """
    fusion, threshold = select_fusion(operating_point)
    rule = chain_rule or DEFAULT_CHAIN_RULE
    if policy is None:
        policy = (
            DEFAULT_POLICY
            if chain_rule_floor is None
            else ChainRulePolicy(name="alert_only", floor=chain_rule_floor, asserts_technique=False)
        )
    tracker = rule.tracker()
    tactics = TacticEngine()
    by_campaign = {c.campaign_id: c for c in campaigns}
    outcomes: dict[str, CampaignOutcome] = {
        c.campaign_id: CampaignOutcome(c.campaign_id, c.family, c.interval_seconds, c.length)
        for c in campaigns
    }
    events: list[EventOutcome] = []
    benign_events = benign_alerted = benign_auto = 0
    benign_users: set[int] = set()

    ordered = sorted(records, key=lambda r: (r.timestamp, r.event_id))
    for _timestamp, grouped in groupby(ordered, key=lambda r: r.timestamp):
        group = list(grouped)
        staged = []
        for record in group:
            signals, chain_detected = tracker.signals(record)
            verdict = tactics.classify_event(
                record,
                signals,
                user_name=names.user(record.src_user_id),
                logon_type_name=names.logon_type(record.logon_type_id),
                auth_type_name=names.auth_type(record.auth_type_id),
                orientation_name=names.orientation(record.orientation_id),
                chain_detected=chain_detected and policy.asserts_technique,
            )
            tactics.observe(
                record,
                auth_type_name=names.auth_type(record.auth_type_id),
                orientation_name=names.orientation(record.orientation_id),
            )
            fanout_detected = False
            if fanout is not None:
                fanout.advance(record.timestamp)
                fanout_detected = fanout.is_fanout_hop(
                    record.src_host_id, record.dst_host_id, success=bool(record.success)
                )
            staged.append((record, signals, verdict, chain_detected or fanout_detected))

        probabilities = list(scorer(group))
        if len(probabilities) != len(group):
            raise ValueError("scorer returned the wrong number of probabilities")

        for (record, signals, verdict, chain_detected), probability in zip(
            staged, probabilities, strict=False
        ):
            components = RiskComponents(
                tgn=float(probability),
                novelty=signals.novelty,
                burst=signals.burst,
                pivot=signals.pivot,
                corroboration=corroboration,
            )
            raw = fuse_risk(components, fusion)
            fused = apply_rule_floor(
                raw,
                chain_detected=chain_detected
                and (not policy.requires_model_alert or raw.score >= threshold),
                floor=policy.floor,
            )
            risk = fused.score
            alerted = risk >= threshold
            technique = verdict.primary.technique_id if verdict.primary else None
            plan = plan_for(technique, verdict.confidence, risk=risk) if alerted else None
            auto = bool(plan and UNATTENDED_ACTION in plan.auto_executable)
            recommended = tuple(plan.needs_approval) if plan else ()

            membership = truth.get(record.event_id)
            outcome = EventOutcome(
                event_id=record.event_id,
                timestamp=record.timestamp,
                user_id=record.src_user_id,
                risk=risk,
                alerted=alerted,
                technique_id=technique,
                confidence=verdict.confidence,
                auto_actioned=auto,
                recommended=recommended,
                campaign_id=membership.campaign_id if membership else None,
                hop_index=membership.hop_index if membership else None,
                expected_technique=membership.technique_id if membership else None,
            )
            events.append(outcome)
            if membership is None:
                benign_events += 1
                benign_alerted += alerted
                benign_auto += auto
                if auto:
                    benign_users.add(record.src_user_id)
            elif membership.campaign_id in outcomes:
                outcomes[membership.campaign_id].hops.append(outcome)

        tracker.observe_group(group)
        if fanout is not None:
            for record in group:
                if record.success:
                    fanout.observe(record.src_user_id, record.src_host_id, record.dst_host_id, record.timestamp)

    for campaign_id, campaign_outcome in outcomes.items():
        if len(campaign_outcome.hops) != by_campaign[campaign_id].length:
            raise ValueError(
                f"{campaign_id}: expected {by_campaign[campaign_id].length} hops in the "
                f"stream, found {len(campaign_outcome.hops)} -- truth and records disagree"
            )

    return PreventionReport(
        operating_point=operating_point,
        threshold=threshold,
        chain_rule=rule.name,
        policy=policy.name,
        campaigns=[outcomes[c.campaign_id] for c in campaigns],
        benign_events=benign_events,
        benign_alerted=benign_alerted,
        benign_auto_actioned=benign_auto,
        benign_users_hit=len(benign_users),
        events=events,
    )


def render_prevention(report: PreventionReport) -> str:
    lines = [
        f"Operating point: {report.operating_point} (threshold {report.threshold:.4f}); "
        f"chain rule {report.chain_rule} under policy {report.policy}; "
        f"unattended action: {UNATTENDED_ACTION}",
        "",
        f"{'family':<9}{'campaigns':>10}{'detected':>9}{'rate':>7}{'median hop':>12}"
        f"{'prevented (campaign)':>22}{'prevented (account)':>21}",
        "-" * 90,
    ]
    for family, s in report.by_family().items():
        med = "-" if s["median_latency_hops"] is None else f"{s['median_latency_hops']:.1f}"
        lines.append(
            f"{family:<9}{s['campaigns']:>10}{s['detected']:>9}{s['detection_rate']:>7.0%}"
            f"{med:>12}{s['prevented_fraction_campaign']:>22.1%}"
            f"{s['prevented_fraction_account']:>21.1%}"
        )
    lines += [
        "",
        "Evasion curve (by inter-hop interval):",
        "",
        f"{'interval s':>11}{'campaigns':>10}{'detected':>9}{'rate':>7}{'median hop':>12}",
        "-" * 49,
    ]
    for interval, s in report.by_interval().items():
        med = "-" if s["median_latency_hops"] is None else f"{s['median_latency_hops']:.1f}"
        lines.append(
            f"{interval:>11}{s['campaigns']:>10}{s['detected']:>9}"
            f"{s['detection_rate']:>7.0%}{med:>12}"
        )
    lines += [
        "",
        "The loop (campaign semantics): prevented hops as the session kill gets weaker,",
        "without and with the one-rung escalation to an account lock:",
        "",
        f"{'kill works':>11}{'without':>10}{'with loop':>11}{'escalated':>11}",
        "-" * 43,
    ]
    for row in report.loop_table():
        lines.append(
            f"{row['kill_effectiveness']:>11.0%}{row['prevented_without_escalation']:>10.1%}"
            f"{row['prevented_with_escalation']:>11.1%}{row['campaigns_escalated']:>11}"
        )
    lines += [
        "",
        f"Benign cost: {report.benign_events:,} events, {report.benign_alerted} alerted "
        f"({report.benign_alert_rate_per_10k:.2f}/10k), {report.benign_auto_actioned} "
        f"auto-actioned ({report.benign_auto_action_rate_per_10k:.2f}/10k), "
        f"{report.benign_users_hit} distinct users hit",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Technique attribution: recall and precision per ATT&CK id
# ---------------------------------------------------------------------------
#: Attribution counts only when the engine was at least this confident.
#: "low" verdicts cannot reach a disruptive response step, so counting them as
#: attributions would credit the rule with calls the product never acts on.
ATTRIBUTION_CONFIDENCE = ("high", "medium")


@dataclass(frozen=True, slots=True)
class TechniqueValidation:
    technique_id: str
    injected: int
    alerted: int
    attributed_correctly: int
    attributed_other: int
    false_attributions: int
    benign_events: int

    @property
    def detection_recall(self) -> float:
        return self.alerted / self.injected if self.injected else 0.0

    @property
    def attribution_recall(self) -> float:
        return self.attributed_correctly / self.injected if self.injected else 0.0

    @property
    def precision(self) -> float:
        claimed = self.attributed_correctly + self.false_attributions
        return self.attributed_correctly / claimed if claimed else 0.0

    @property
    def false_attribution_rate_per_10k(self) -> float:
        return 10_000 * self.false_attributions / self.benign_events if self.benign_events else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "injected": self.injected,
            "alerted": self.alerted,
            "detection_recall": round(self.detection_recall, 4),
            "attributed_correctly": self.attributed_correctly,
            "attribution_recall": round(self.attribution_recall, 4),
            "attributed_to_another_technique": self.attributed_other,
            "false_attributions_on_benign": self.false_attributions,
            "false_attribution_rate_per_10k": round(self.false_attribution_rate_per_10k, 3),
            "precision": round(self.precision, 4),
        }


def technique_validation(
    events: Sequence[EventOutcome], technique_ids: Iterable[str]
) -> dict[str, TechniqueValidation]:
    """Per-technique recall (on injected events) and precision (against benign).

    *Detection recall* is the share of injected events that alerted at all --
    the product noticed something. *Attribution recall* is the share the
    engine named correctly at medium or high confidence -- the product knew
    what it was. *Precision* asks, of every event the engine called this
    technique, how many really were.
    """
    benign_events = sum(1 for e in events if e.expected_technique is None)
    results: dict[str, TechniqueValidation] = {}
    for technique in technique_ids:
        injected = [e for e in events if e.expected_technique == technique]
        confident = [
            e
            for e in events
            if e.technique_id == technique and e.confidence in ATTRIBUTION_CONFIDENCE
        ]
        correct = sum(1 for e in confident if e.expected_technique == technique)
        results[technique] = TechniqueValidation(
            technique_id=technique,
            injected=len(injected),
            alerted=sum(1 for e in injected if e.alerted),
            attributed_correctly=correct,
            attributed_other=sum(
                1
                for e in injected
                if e.technique_id not in (None, technique)
                and e.confidence in ATTRIBUTION_CONFIDENCE
            ),
            false_attributions=sum(1 for e in confident if e.expected_technique is None),
            benign_events=benign_events,
        )
    return results


def render_technique_validation(results: Mapping[str, TechniqueValidation]) -> str:
    lines = [
        f"{'technique':<11}{'injected':>9}{'alerted':>9}{'det. recall':>13}"
        f"{'attributed':>12}{'attr. recall':>14}{'benign FA/10k':>15}{'precision':>11}",
        "-" * 94,
    ]
    for technique, r in results.items():
        lines.append(
            f"{technique:<11}{r.injected:>9}{r.alerted:>9}{r.detection_recall:>13.1%}"
            f"{r.attributed_correctly:>12}{r.attribution_recall:>14.1%}"
            f"{r.false_attribution_rate_per_10k:>15.2f}{r.precision:>11.1%}"
        )
    return "\n".join(lines)
