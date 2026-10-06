"""Entity-disjoint evaluation: does the detector generalise, or has it memorised?

The problem this exists to catch
--------------------------------
Intrusion corpora label attacks by campaign, and a campaign runs from a small
number of compromised machines. If an entity appears as an attacker in training
and never appears benign, then its identity *is* the label, and any model with
the capacity to remember an entity — which a TGN, whose entire design is a
per-node memory, certainly has — can score well without representing attack
behaviour at all.

This is not hypothetical for GraphSentinel. Measured on the LANL corpus, one
source host supplies 121 of 126 test attacks and carries zero benign events in
training. Holding it out collapses test PR-AUC from 0.8210 to 0.0019: 99.8% of
the headline number was that one host. The full write-up is Finding 14 in
``docs/DETECTION_RESEARCH_FINDINGS.md``.

A time-based split does not protect against this, because it splits *when*, not
*who*. The entity is on both sides of the boundary by construction.

What is measured here
---------------------
Two things, deliberately separated, because one is a cause and the other is an
effect and they can be checked independently:

* :func:`attack_only_entities` inspects the **training** partition alone and
  reports which entities appear exclusively in attacks. This is the mechanism,
  and it is verifiable by counting rows -- no model involved, so it cannot be
  explained away as a quirk of one detector.
* :func:`contamination_report` removes each attacking entity from the **test**
  partition in turn and re-measures. This is the effect, in the units the
  project already reports.

A detector that has genuinely learned behaviour loses little when a single
entity is withdrawn. One that has memorised loses almost everything, and the
size of the loss is the size of the problem.

Interpreting a collapse
-----------------------
A collapse does not mean the detector is worthless, and the report does not say
so. It means the corpus cannot distinguish a detector that generalises from one
that memorises, so no absolute figure derived from it estimates field
performance. The held-out interval is reported alongside the base rate
precisely so a reader can see whether residual signal survives -- on this corpus
it does, at a 44.8x lift over base rate, which is real but far too weak to staff
an alert queue from.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np

from graphsentinel.evaluation.metrics import (
    DEFAULT_RESAMPLES,
    DEFAULT_SEED,
    average_precision,
    bootstrap_interval,
)

#: An entity supplying at least this share of all attacks is reported as
#: dominant. Set well below a majority because the concern starts long before
#: one entity owns most of the campaign -- at 30% a third of the metric is
#: already hostage to a single identity.
DOMINANCE_THRESHOLD = 0.30

#: Below this many remaining attacks, a held-out measurement is reported but
#: explicitly marked as too small to support a conclusion. Five positives give
#: an interval so wide that almost nothing is excluded by it.
MINIMUM_CREDIBLE_POSITIVES = 20


@dataclass(frozen=True, slots=True)
class EntityHoldout:
    """What removing one attacking entity does to the metric."""

    entity: int
    attacks_removed: int
    attacks_remaining: int
    events_remaining: int
    pr_auc_without: float
    interval_without: tuple[float, float]
    base_rate_without: float
    share_of_metric: float

    @property
    def credible(self) -> bool:
        """Enough positives left to say anything with?"""
        return self.attacks_remaining >= MINIMUM_CREDIBLE_POSITIVES

    @property
    def lift_without(self) -> float:
        """How far above chance the remainder still ranks.

        Reported because a collapsed PR-AUC at a collapsed base rate can still
        be far better than random, and calling that "no signal" would overstate
        the finding.
        """
        if self.base_rate_without <= 0:
            return 0.0
        return self.pr_auc_without / self.base_rate_without

    def to_dict(self) -> dict[str, object]:
        return {
            "entity": self.entity,
            "attacks_removed": self.attacks_removed,
            "attacks_remaining": self.attacks_remaining,
            "events_remaining": self.events_remaining,
            "pr_auc_without": round(self.pr_auc_without, 6),
            "ci95_without": [
                round(self.interval_without[0], 6),
                round(self.interval_without[1], 6),
            ],
            "base_rate_without": round(self.base_rate_without, 8),
            "lift_without": round(self.lift_without, 2),
            "share_of_metric": round(self.share_of_metric, 4),
            "credible": self.credible,
        }


@dataclass(frozen=True, slots=True)
class ContaminationReport:
    full_pr_auc: float
    attacking_entities: int
    dominant_entity: int | None
    dominant_share: float
    holdouts: tuple[EntityHoldout, ...]

    @property
    def worst(self) -> EntityHoldout | None:
        """The entity whose removal costs the most — the memorisation shortcut."""
        return max(self.holdouts, key=lambda h: h.share_of_metric, default=None)

    @property
    def total_capture(self) -> bool:
        """Does one entity supply *every* attack in the partition?

        This is the most severe case rather than an absent one, and it needs
        its own flag because it is the case where the holdout sweep produces
        nothing: withdrawing the entity leaves zero positives, PR-AUC is
        undefined, and an implementation that only inspects the sweep would
        find an empty list and conclude everything was fine.
        """
        return self.attacking_entities == 1 and self.dominant_entity is not None

    @property
    def contaminated(self) -> bool:
        """Does any single entity account for most of the measured performance?"""
        if self.total_capture:
            return True
        worst = self.worst
        return worst is not None and worst.share_of_metric >= 0.5

    def verdict(self) -> str:
        if self.total_capture:
            return (
                f"CONTAMINATED (total capture): every attack in this partition "
                f"originates from entity {self.dominant_entity}. No holdout is "
                f"possible, because withdrawing it leaves no positives to "
                f"measure -- so the reported PR-AUC of {self.full_pr_auc:.4f} "
                f"cannot be distinguished from a detector that has memorised "
                f"that one identity. This partition cannot support any "
                f"generalisation claim."
            )
        worst = self.worst
        if worst is None:
            if self.attacking_entities == 0:
                return "No attacking entities in this partition; nothing to measure."
            return (
                f"{self.attacking_entities} attacking entities, but no holdout "
                "left any positives to score. Treat this partition as unable to "
                "support a generalisation claim."
            )
        if not self.contaminated:
            return (
                f"No single entity dominates: removing the worst case "
                f"(entity {worst.entity}) costs "
                f"{worst.share_of_metric:.1%} of PR-AUC."
            )
        credibility = (
            ""
            if worst.credible
            else f" Only {worst.attacks_remaining} attacks remain after the holdout, "
            f"which is below the {MINIMUM_CREDIBLE_POSITIVES} needed to estimate "
            "the residual reliably -- the collapse is established, its exact "
            "magnitude is not."
        )
        return (
            f"CONTAMINATED: entity {worst.entity} accounts for "
            f"{worst.share_of_metric:.1%} of test PR-AUC "
            f"({self.full_pr_auc:.4f} -> {worst.pr_auc_without:.4f}). "
            f"Absolute figures from this partition are not estimates of "
            f"performance against an unseen attacker." + credibility
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "full_pr_auc": round(self.full_pr_auc, 6),
            "attacking_entities": self.attacking_entities,
            "dominant_entity": self.dominant_entity,
            "dominant_share": round(self.dominant_share, 4),
            "contaminated": self.contaminated,
            "total_capture": self.total_capture,
            "verdict": self.verdict(),
            "holdouts": [h.to_dict() for h in self.holdouts],
        }


def attack_only_entities(labels: Sequence[int], entities: Sequence[int]) -> dict[int, int]:
    """Entities that appear **only** in attacks, with their event counts.

    Run against the training partition. Any entity listed here is a perfect
    separator that a sufficiently expressive model can memorise instead of
    learning the behaviour the entity happened to exhibit.

    This is the diagnostic to run *before* trusting a headline metric, and it
    needs no model to compute -- which is what makes it hard to argue with.
    """
    label_array = np.asarray(list(labels), dtype=int)
    entity_array = np.asarray(list(entities))
    if label_array.shape != entity_array.shape:
        raise ValueError("labels and entities must have the same length")

    benign_entities = set(entity_array[label_array == 0].tolist())
    attack_counts = Counter(entity_array[label_array == 1].tolist())
    return {
        int(entity): int(count)
        for entity, count in sorted(attack_counts.items(), key=lambda item: -item[1])
        if entity not in benign_entities
    }


def contamination_report(
    labels: Sequence[int],
    scores: Sequence[float],
    entities: Sequence[int],
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
    max_entities: int = 10,
) -> ContaminationReport:
    """Re-measure PR-AUC with each attacking entity withdrawn in turn.

    ``max_entities`` caps the sweep at the largest contributors, since the tail
    of single-event entities cannot move the metric and each holdout costs a
    full bootstrap.
    """
    label_array = np.asarray(list(labels), dtype=int)
    score_array = np.asarray(list(scores), dtype=float)
    entity_array = np.asarray(list(entities))
    if not (label_array.shape == score_array.shape == entity_array.shape):
        raise ValueError("labels, scores and entities must have the same length")
    if label_array.size == 0:
        raise ValueError("cannot assess contamination over an empty partition")

    full = average_precision(label_array, score_array)
    attack_counts = Counter(entity_array[label_array == 1].tolist())
    total_attacks = int(label_array.sum())

    dominant_entity, dominant_share = None, 0.0
    if attack_counts:
        entity, count = attack_counts.most_common(1)[0]
        dominant_entity, dominant_share = int(entity), count / total_attacks

    holdouts: list[EntityHoldout] = []
    for entity, removed in attack_counts.most_common(max_entities):
        keep = entity_array != entity
        kept_labels, kept_scores = label_array[keep], score_array[keep]
        remaining = int(kept_labels.sum())
        if remaining == 0 or kept_labels.size == 0:
            # Removing this entity removes every positive; PR-AUC is undefined
            # rather than zero, so the entity is skipped instead of scored 0.
            continue
        without = average_precision(kept_labels, kept_scores)
        interval = bootstrap_interval(
            kept_labels,
            kept_scores,
            average_precision,
            resamples=resamples,
            seed=seed,
        )
        holdouts.append(
            EntityHoldout(
                entity=int(entity),
                attacks_removed=int(removed),
                attacks_remaining=remaining,
                events_remaining=int(kept_labels.size),
                pr_auc_without=without,
                interval_without=(interval.low, interval.high),
                base_rate_without=float(kept_labels.mean()),
                share_of_metric=(1.0 - without / full) if full > 0 else 0.0,
            )
        )

    return ContaminationReport(
        full_pr_auc=full,
        attacking_entities=len(attack_counts),
        dominant_entity=dominant_entity,
        dominant_share=dominant_share,
        holdouts=tuple(holdouts),
    )


def render_contamination(report: ContaminationReport) -> str:
    """Operator-readable rendering, for the evaluation report and the console."""
    lines = [
        f"Full-partition PR-AUC: {report.full_pr_auc:.4f}",
        f"Attacking entities: {report.attacking_entities}"
        + (
            f"; largest supplies {report.dominant_share:.1%} of attacks"
            if report.dominant_entity is not None
            else ""
        ),
        "",
        f"{'entity':>9}{'removed':>9}{'left':>7}{'PR-AUC':>10}{'95% CI':>22}{'lift':>8}{'cost':>8}",
        "-" * 73,
    ]
    for holdout in report.holdouts:
        interval = f"[{holdout.interval_without[0]:.4f}, {holdout.interval_without[1]:.4f}]"
        marker = "" if holdout.credible else "  (too few left)"
        lines.append(
            f"{holdout.entity:>9}{holdout.attacks_removed:>9}"
            f"{holdout.attacks_remaining:>7}{holdout.pr_auc_without:>10.4f}"
            f"{interval:>22}{holdout.lift_without:>8.1f}"
            f"{holdout.share_of_metric:>7.1%}{marker}"
        )
    lines.extend(["", report.verdict()])
    return "\n".join(lines)
