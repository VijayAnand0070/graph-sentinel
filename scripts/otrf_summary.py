"""Summarise the OTRF evaluation honestly: against chance, and without a threshold.

Reads ``artifacts/otrf/otrf_events.json`` (every scored event, written by
``otrf_evaluate.py``) and reports, over the recordings whose ground truth names
the attack and whose logs contain it:

* recall at the shipped alert threshold (0.3292, calibrated on LANL);
* how often the attacker's event is the most suspicious event in its recording,
  against the rate a random ordering would give (``n_attack / n_events`` per
  recording) -- "rank 1 of 3" is a one-in-three coin, not a detection;
* threshold-free separability: ROC-AUC of risk, attack vs benign, pooled over
  the recordings, with a bootstrap interval that resamples *recordings* (the
  unit that is independent), and the mean within-recording AUC.
"""

from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


def auc(positives: list[float], negatives: list[float]) -> float | None:
    """Mann-Whitney AUC with ties counted as half."""
    if not positives or not negatives:
        return None
    wins = 0.0
    for p in positives:
        for n in negatives:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(positives) * len(negatives))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--events", type=Path, default=Path("artifacts/otrf/otrf_events.json")
    )
    parser.add_argument("--out", type=Path, default=Path("artifacts/otrf/otrf_summary.json"))
    parser.add_argument("--threshold", type=float, default=0.3292)
    parser.add_argument("--resamples", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=20260924)
    args = parser.parse_args()

    events: list[dict[str, Any]] = json.loads(args.events.read_text(encoding="utf-8"))
    by_recording: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["label"] != "excluded":
            by_recording[event["dataset"]].append(event)
    scored = {name: evs for name, evs in by_recording.items() if any(e["attack"] for e in evs)}

    def caught(evs: list[dict[str, Any]]) -> bool:
        return any(e["attack"] and e["risk"] >= args.threshold for e in evs)

    detected = sum(1 for evs in scored.values() if caught(evs))
    top1_observed = 0
    top1_expected = 0.0
    informative = 0  # recordings with at least one benign event: ranking can mean something
    within_aucs: list[float] = []
    for evs in scored.values():
        attack = [e["risk"] for e in evs if e["attack"]]
        benign = [e["risk"] for e in evs if not e["attack"]]
        top = max(evs, key=lambda e: e["risk"])
        if benign:
            informative += 1
            top1_observed += int(top["attack"])
            top1_expected += len(attack) / len(evs)
            value = auc(attack, benign)
            if value is not None:
                within_aucs.append(value)

    def pooled(names: list[str]) -> float | None:
        pos = [e["risk"] for n in names for e in scored[n] if e["attack"]]
        neg = [e["risk"] for n in names for e in scored[n] if not e["attack"]]
        return auc(pos, neg)

    names = sorted(scored)
    point = pooled(names)
    rng = random.Random(args.seed)
    boots = []
    for _ in range(args.resamples):
        sample = [rng.choice(names) for _ in names]
        value = pooled(sample)
        if value is not None:
            boots.append(value)
    boots.sort()
    interval = (
        (boots[int(0.025 * len(boots))], boots[int(0.975 * len(boots)) - 1]) if boots else None
    )

    benign_alerts = sum(
        1 for evs in scored.values() for e in evs if not e["attack"] and e["risk"] >= args.threshold
    )
    benign_total = sum(1 for evs in scored.values() for e in evs if not e["attack"])
    summary = {
        "recordings_scored": len(scored),
        "attack_events": sum(1 for evs in scored.values() for e in evs if e["attack"]),
        "benign_events": benign_total,
        "detected_at_shipped_threshold": detected,
        "threshold": args.threshold,
        "benign_alerts_at_shipped_threshold": benign_alerts,
        "recordings_with_benign_events": informative,
        "attack_ranked_first": top1_observed,
        "attack_ranked_first_by_chance": round(top1_expected, 2),
        "pooled_roc_auc": round(point, 4) if point is not None else None,
        "pooled_roc_auc_95ci_over_recordings": (
            [round(v, 4) for v in interval] if interval else None
        ),
        "mean_within_recording_roc_auc": round(sum(within_aucs) / len(within_aucs), 4)
        if within_aucs else None,
        "within_recording_auc_count": len(within_aucs),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
