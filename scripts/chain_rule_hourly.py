"""How a chain rule's benign cost falls as the history behind it grows.

On an unsampled day the engine starts cold: every account-host pair is new
the first time it is seen, so a rule that counts *novel* hops flags far more
in the first hours than it ever would with weeks of history behind it. This
replays a rule over a full-rate day and reports benign flags per 10,000 per
hour, so the cold-start inflation is visible and the trend, not the day's
average, is what gets quoted. Finding 25 reads the curve.

    python scripts/chain_rule_hourly.py --data artifacts/e2e/fullrate_day1/features \
        --rules 3hops-1800s-novel,3hops-600s-novel --out artifacts/prevention/chain_rule_hourly.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from itertools import groupby
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from chain_rule_study import records_from_frame  # noqa: E402
from measure_prevention import load_frame  # noqa: E402

from graphsentinel.detection.policy import ChainRuleConfig  # noqa: E402


def hourly(frame, rule: ChainRuleConfig) -> list[dict[str, float]]:  # type: ignore[no-untyped-def]
    tracker = rule.tracker()
    buckets: dict[int, list[int]] = {}
    users: dict[int, set[int]] = {}
    for _timestamp, grouped in groupby(records_from_frame(frame), key=lambda r: r.timestamp):
        group = list(grouped)
        hour = group[0].timestamp // 3_600
        bucket = buckets.setdefault(hour, [0, 0, 0])  # benign, flagged, novel
        seen = users.setdefault(hour, set())
        for record in group:
            _signals, chain = tracker.signals(record)
            if record.label_redteam:
                continue
            bucket[0] += 1
            bucket[1] += chain
            bucket[2] += int(record.is_new_pair)
            if chain:
                seen.add(record.src_user_id)
        tracker.observe_group(group)
    return [
        {
            "hour": hour,
            "benign": benign,
            "flagged": flagged,
            "flagged_per_10k": round(1e4 * flagged / max(1, benign), 2),
            "new_pair_share": round(novel / max(1, benign), 4),
            "users_flagged": len(users[hour]),
        }
        for hour, (benign, flagged, novel) in sorted(buckets.items())
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--rules", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    frame = load_frame(args.data)
    results: dict[str, object] = {"data": str(args.data), "events": frame.height, "rules": {}}
    for name in [n.strip() for n in args.rules.split(",") if n.strip()]:
        started = time.perf_counter()
        curve = hourly(frame, ChainRuleConfig.parse(name))
        results["rules"][name] = curve  # type: ignore[index]
        print(f"{name}  ({time.perf_counter() - started:.0f}s)", flush=True)
        for row in curve:
            print(
                f"  hour {row['hour']:>3}  benign {row['benign']:>8,}  flagged {row['flagged']:>7,} "
                f"({row['flagged_per_10k']:>8.2f}/10k)  new-pair share {row['new_pair_share']:.3f}  "
                f"users {row['users_flagged']:>5}",
                flush=True,
            )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
