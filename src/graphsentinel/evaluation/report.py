"""Reproducible evaluation report.

One command regenerates every headline number in the project, with intervals,
from a single scored cache. The point is falsifiability: a reader who doubts a
figure should be able to re-derive it rather than take it on trust, and a
change that moves a number should show up as a diff rather than as a surprise
months later.

Protocol
--------
* Thresholds are derived on **validation only**, at a fixed false-positive
  budget. Deriving one on test would leak the partition it is meant to measure.
* Test is scored **once**, with everything already frozen.
* Every figure carries a 95% stratified bootstrap interval, and every
  comparison between detectors is **paired** on identical resampled events.
* The seed is fixed, so two runs of this report agree exactly.
"""

from __future__ import annotations

import json
import platform
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import numpy as np

from graphsentinel import __version__
from graphsentinel.detection.fusion import (CHANNELS, OPERATING_POINTS,
                                            FusionConfig, NoisyOrConfig)
from graphsentinel.evaluation.generalisation import (attack_only_entities,
                                                     contamination_report)
from graphsentinel.evaluation.metrics import (DEFAULT_RESAMPLES, DEFAULT_SEED,
                                              average_precision,
                                              bootstrap_interval, describe,
                                              operating_point,
                                              paired_comparison, recall_at_k,
                                              roc_auc, threshold_at_budget)

FP_BUDGET_PER_10K = 25.0

#: Detectors compared in every report. Each is a scoring rule over the same
#: cached channel matrix, so differences are attributable to the rule alone.
DETECTORS = ("linear", "noisy_or", "tgn_only")


@dataclass(frozen=True, slots=True)
class ScoredCache:
    """Per-event channel values and labels, split by partition."""

    labels: Mapping[str, np.ndarray]
    channels: Mapping[str, np.ndarray]
    #: Source host per event, when the cache carries it. Used for the
    #: entity-disjoint measurement; absent caches simply omit that section
    #: rather than failing, so older caches still produce a report.
    entities: Mapping[str, np.ndarray] | None = None

    @classmethod
    def from_parquet(cls, path: Path) -> ScoredCache:
        import polars as pl

        frame = pl.read_parquet(path)
        if "corroboration" not in frame.columns:
            # Not available offline; zero in the live path too, so holding it
            # at zero keeps the report faithful to deployment rather than
            # flattering any operator.
            frame = frame.with_columns(pl.lit(0.0).alias("corroboration"))
        has_entity = "src_host_id" in frame.columns
        labels, channels, entities = {}, {}, {}
        for partition in ("train", "validation", "test"):
            part = frame.filter(pl.col("partition") == partition)
            labels[partition] = part["label"].to_numpy().astype(int)
            channels[partition] = np.column_stack(
                [part[name].to_numpy().astype(float) for name in CHANNELS]
            )
            if has_entity:
                entities[partition] = part["src_host_id"].to_numpy()
        return cls(labels=labels, channels=channels,
                   entities=entities if has_entity else None)


def score(matrix: np.ndarray, detector: str) -> np.ndarray:
    """Apply one detector to the cached channel matrix."""
    if detector == "linear":
        weights = np.array([getattr(FusionConfig(), name) for name in CHANNELS])
        return np.clip(matrix @ weights, 0.0, 1.0)
    if detector in {"noisy_or", "tgn_only"}:
        config = (NoisyOrConfig() if detector == "noisy_or"
                  else NoisyOrConfig(tgn=1.0, novelty=0.0, burst=0.0, pivot=0.0,
                                     corroboration=0.0))
        reliabilities = np.array([getattr(config, name) for name in CHANNELS])
        return 1.0 - np.prod(1.0 - matrix * reliabilities[None, :], axis=1)
    raise ValueError(f"unknown detector {detector!r}")


def build_report(
    cache: ScoredCache,
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": 1,
        "generated_at": int(time.time()),
        "graphsentinel_version": __version__,
        "python": platform.python_version(),
        "protocol": {
            "threshold_derived_on": "validation",
            "test_scored_times": 1,
            "false_positive_budget_per_10k": FP_BUDGET_PER_10K,
            "bootstrap_resamples": resamples,
            "bootstrap_seed": seed,
            "bootstrap_stratified": True,
            "comparisons_paired": True,
            "tie_handling": "positives ranked last within equal scores",
        },
        "partitions": {
            name: describe(cache.labels[name])
            for name in ("train", "validation", "test")
        },
    }

    validation_y, test_y = cache.labels["validation"], cache.labels["test"]
    detector_scores = {
        name: (score(cache.channels["validation"], name), score(cache.channels["test"], name))
        for name in DETECTORS
    }

    results: dict[str, object] = {}
    for name, (val_scores, test_scores) in detector_scores.items():
        threshold = threshold_at_budget(validation_y, val_scores, FP_BUDGET_PER_10K)
        interval = bootstrap_interval(
            test_y, test_scores, average_precision, resamples=resamples, seed=seed
        )
        results[name] = {
            "threshold": round(threshold, 6),
            "published_threshold": OPERATING_POINTS.get(name, {}).get("threshold"),
            "validation_pr_auc": round(average_precision(validation_y, val_scores), 4),
            "test_pr_auc": interval.to_dict(),
            "test_roc_auc": round(roc_auc(test_y, test_scores), 4),
            "test_recall_at_100": round(recall_at_k(test_y, test_scores, 100), 4),
            "test_recall_at_1000": round(recall_at_k(test_y, test_scores, 1_000), 4),
            "test_operating_point": operating_point(
                test_y, test_scores, threshold
            ).to_dict(),
        }
    report["detectors"] = results

    # Paired comparisons in a fixed order, so the report reads the same way
    # every time and a regression is visible as a sign flip.
    comparisons = []
    for a, b in (("noisy_or", "linear"), ("tgn_only", "noisy_or"), ("tgn_only", "linear")):
        comparisons.append(
            paired_comparison(
                test_y, detector_scores[a][1], detector_scores[b][1],
                name_a=a, name_b=b, resamples=resamples, seed=seed,
            ).to_dict()
        )
    report["paired_comparisons"] = comparisons

    if cache.entities is not None:
        # The measurement behind ENTITY_CONTAMINATION_WARNING. Emitted as data
        # rather than prose so the caveat is re-derived on every run instead of
        # being a sentence someone has to remember to keep true.
        best = max(DETECTORS, key=lambda n: results[n]["test_pr_auc"]["point"])
        report["generalisation"] = {
            "detector": best,
            "entity": "src_host_id",
            "attack_only_entities_in_train": attack_only_entities(
                cache.labels["train"], cache.entities["train"]
            ),
            "test_contamination": contamination_report(
                test_y, detector_scores[best][1], cache.entities["test"],
                resamples=resamples, seed=seed,
            ).to_dict(),
        }

    report["headline"] = _headline(results, comparisons)
    return report


#: Every figure in this report is measured on the full test partition, and that
#: partition is dominated by one attacker host which is attack-only in training
#: (Finding 14). Removing it collapses test PR-AUC from 0.8210 to 0.0019 --
#: 99.8% of the metric. Detector-vs-detector comparisons stay meaningful because
#: all of them face the same shortcut, but the absolute values are not estimates
#: of field performance. The warning is emitted with the report so the caveat
#: cannot get separated from the numbers it applies to.
ENTITY_CONTAMINATION_WARNING = (
    "These are relative comparisons, not field-performance estimates. The test "
    "partition's attacks originate almost entirely from one source host that "
    "carries zero benign events in training: one host, one campaign, one "
    "pattern. Holding it out collapses test PR-AUC from 0.8210 to 0.0019 "
    "[0.0017, 0.0038]. Ablation shows the shipped model did not memorise the "
    "host (Finding 20) -- it learned that campaign's behaviour and has no second "
    "example -- but the evaluation cannot tell the two apart, which is the "
    "point. Detector-vs-detector differences remain valid; no absolute number "
    "here should be quoted as expected performance against an unseen attacker. "
    "See docs/DETECTION_RESEARCH_FINDINGS.md, Findings 14 and 20."
)


def _headline(results: Mapping[str, object], comparisons: list[dict]) -> dict[str, object]:
    """The conclusions a reader should take, stated with their caveats."""
    best = max(DETECTORS, key=lambda n: results[n]["test_pr_auc"]["point"])
    significant = [c for c in comparisons if c["significant"]]
    return {
        "best_test_pr_auc": best,
        "best_test_pr_auc_value": results[best]["test_pr_auc"],
        "significant_comparisons": [c["comparison"] for c in significant],
        "caveat": (
            "The test partition holds few attacks, so intervals are wide and "
            "point estimates must not be quoted alone. ROC-AUC is reported for "
            "comparability only: detectors differing by ~0.23 PR-AUC differ by "
            "~0.03 ROC-AUC on this data."
        ),
        "entity_contamination": ENTITY_CONTAMINATION_WARNING,
    }


def render_markdown(report: Mapping[str, object]) -> str:
    """Human-readable rendering of the same numbers, for review."""
    lines: list[str] = []
    add = lines.append
    add("# GraphSentinel — Evaluation Report")
    add("")
    add(f"Generated from GraphSentinel {report['graphsentinel_version']} "
        f"on Python {report['python']}.")
    add("")

    protocol = report["protocol"]
    add("## Protocol")
    add("")
    add(f"- Threshold derived on **{protocol['threshold_derived_on']}** only, at a "
        f"{protocol['false_positive_budget_per_10k']} per 10,000 false-positive budget")
    add(f"- Test partition scored **once**, with everything frozen")
    add(f"- {protocol['bootstrap_resamples']:,} stratified bootstrap resamples, "
        f"seed {protocol['bootstrap_seed']}")
    add(f"- Comparisons **paired** on identical resampled events")
    add(f"- Ties: {protocol['tie_handling']}")
    add("")

    add("## Partitions")
    add("")
    add("| Partition | Events | Attacks | Prevalence |")
    add("|---|---|---|---|")
    for name, shape in report["partitions"].items():
        add(f"| {name} | {shape['events']:,} | {shape['attacks']} | "
            f"{shape['prevalence']:.4%} |")
    add("")

    add("## Detectors")
    add("")
    add("| Detector | Threshold | Val PR-AUC | **Test PR-AUC (95% CI)** | Test ROC-AUC | FP/10k | Recall |")
    add("|---|---|---|---|---|---|---|")
    for name, result in report["detectors"].items():
        interval = result["test_pr_auc"]
        point = result["test_operating_point"]
        add(f"| `{name}` | {result['threshold']:.4f} | {result['validation_pr_auc']:.4f} "
            f"| **{interval['point']:.4f}** [{interval['ci95'][0]:.4f}, "
            f"{interval['ci95'][1]:.4f}] | {result['test_roc_auc']:.4f} "
            f"| {point['false_positives_per_10k']:.1f} | {point['recall']:.4f} |")
    add("")

    add("## Paired comparisons")
    add("")
    add("| Comparison | Difference (95% CI) | Wins | Significant |")
    add("|---|---|---|---|")
    for comparison in report["paired_comparisons"]:
        diff = comparison["difference"]
        add(f"| {comparison['comparison']} | {diff['point']:+.4f} "
            f"[{diff['ci95'][0]:+.4f}, {diff['ci95'][1]:+.4f}] | "
            f"{comparison['fraction_a_wins']:.1%} | "
            f"{'**yes**' if comparison['significant'] else 'no'} |")
    add("")

    generalisation = report.get("generalisation")
    if generalisation:
        contamination = generalisation["test_contamination"]
        add("## Entity-disjoint evaluation")
        add("")
        add(f"Attacking entity: `{generalisation['entity']}`. Scored on "
            f"**`{generalisation['detector']}`**, the best detector above.")
        add("")
        attack_only = generalisation["attack_only_entities_in_train"]
        if attack_only:
            listed = ", ".join(f"`{entity}` ({count} events)"
                               for entity, count in list(attack_only.items())[:5])
            add(f"**Attack-only entities in training:** {listed}. An entity that "
                "never appears benign in training is a perfect separator, so a "
                "model with per-entity memory can score well on it without "
                "representing attack behaviour.")
        else:
            add("**Attack-only entities in training:** none. Every attacking "
                "entity also appears in benign traffic, so identity alone does "
                "not determine the label.")
        add("")
        if contamination["holdouts"]:
            add("| Entity held out | Attacks removed | Attacks left | PR-AUC without "
                "| 95% CI | Lift | Cost |")
            add("|---|---|---|---|---|---|---|")
            for holdout in contamination["holdouts"]:
                interval = (f"[{holdout['ci95_without'][0]:.4f}, "
                            f"{holdout['ci95_without'][1]:.4f}]")
                note = "" if holdout["credible"] else " *"
                add(f"| `{holdout['entity']}` | {holdout['attacks_removed']} "
                    f"| {holdout['attacks_remaining']}{note} "
                    f"| {holdout['pr_auc_without']:.4f} | {interval} "
                    f"| {holdout['lift_without']:.1f}x "
                    f"| {holdout['share_of_metric']:.1%} |")
            add("")
            add("`*` too few attacks remain to estimate the residual reliably.")
            add("")
        add(f"> {contamination['verdict']}")
        add("")

    headline = report["headline"]
    add("## Reading this")
    add("")
    add(f"Best test PR-AUC: **`{headline['best_test_pr_auc']}`** at "
        f"{headline['best_test_pr_auc_value']['point']:.4f}.")
    add("")
    add(f"> {headline['caveat']}")
    add("")
    add("### Entity contamination — read before quoting any number above")
    add("")
    add(f"> {headline['entity_contamination']}")
    add("")
    return "\n".join(lines)


def write_report(
    cache_path: Path,
    output_dir: Path,
    *,
    resamples: int = DEFAULT_RESAMPLES,
    seed: int = DEFAULT_SEED,
) -> dict[str, Path]:
    cache = ScoredCache.from_parquet(cache_path)
    report = build_report(cache, resamples=resamples, seed=seed)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "evaluation_report.json"
    markdown_path = output_dir / "EVALUATION_REPORT.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return {"json": json_path, "markdown": markdown_path}


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Regenerate the evaluation report")
    parser.add_argument("--cache", type=Path, required=True,
                        help="Parquet of per-event channel values and labels")
    parser.add_argument("--output", type=Path, default=Path("docs"))
    parser.add_argument("--resamples", type=int, default=DEFAULT_RESAMPLES)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args(argv)

    written = write_report(args.cache, args.output,
                           resamples=args.resamples, seed=args.seed)
    for kind, path in written.items():
        print(f"wrote {kind}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
