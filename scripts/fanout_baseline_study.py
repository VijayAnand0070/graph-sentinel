"""Fan-out rule relative to each host's own baseline, costed on unlabelled training days.

A fixed "many accounts from one host" rule is dominated by infrastructure: on
LANL a few hub hosts use thousands of distinct accounts an hour and reach new
hosts all day, so even 100 accounts and 100 novel moves an hour flag ~210 of
every million events. A beachhead is different: an ordinary workstation that
normally uses one or two accounts suddenly reaches new hosts with several.

The rule therefore compares a host with itself: it fires only when the host's
*baseline* -- the median, over its previous days (up to seven), of its daily
maximum of distinct accounts per hour -- is at most ``L``. Thresholds are chosen
on the training days by benign cost alone (labels are not read): the most
sensitive (accounts, novel moves, baseline) whose flag rate stays within the
budget.

    python scripts/fanout_baseline_study.py --days-dir artifacts/fullrate/days \\
        --rules-dir artifacts/fullrate/rules --out artifacts/fullrate/fanout_baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402

LOOKBACK_DAYS = 7


def baselines(days_dir: Path, rules_dir: Path, days: list[int], out_dir: Path) -> None:
    """Per event: the source host's baseline from strictly earlier days."""
    daily_max: dict[int, dict[int, int]] = {}
    out_dir.mkdir(parents=True, exist_ok=True)
    for day in days:
        src = pl.read_parquet(days_dir / f"day{day:02d}.parquet", columns=["src"])["src"].to_numpy()
        rules = pl.read_parquet(rules_dir / f"day{day:02d}.parquet")
        acc = rules["fo_accounts"].to_numpy()
        # baseline for today's events from previous days only
        history = [daily_max[d] for d in range(max(0, day - LOOKBACK_DAYS), day) if d in daily_max]
        hosts = np.unique(src)
        base = {}
        for h in hosts.tolist():
            values = [m[h] for m in history if h in m]
            base[h] = float(np.median(values)) if values else 0.0
        lookup = np.vectorize(base.get, otypes=[np.float64])(src) if len(src) else np.empty(0)
        pl.DataFrame({"event_id": rules["event_id"], "fo_baseline": lookup.astype(np.float32)}).write_parquet(
            out_dir / f"day{day:02d}.parquet"
        )
        frame = pl.DataFrame({"src": src, "acc": acc}).group_by("src").agg(pl.col("acc").max())
        daily_max[day] = dict(zip(frame["src"].to_list(), frame["acc"].to_list(), strict=True))
        print(f"day {day:02d}: baselines for {len(hosts):,} hosts", flush=True)


def flags(rules: pl.DataFrame, base: np.ndarray, accounts: int, novel: int, limit: float) -> np.ndarray:
    return (
        (rules["fo_novel_now"].to_numpy() == 1)
        & (rules["fo_accounts"].to_numpy() >= accounts)
        & (rules["fo_novel"].to_numpy() >= novel)
        & (base <= limit)
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--rules-dir", type=Path, required=True)
    ap.add_argument("--days", default="0-15")
    ap.add_argument("--train-days", default="1-6", help="costing days (day 0 has no baseline history)")
    ap.add_argument("--budget", type=float, default=1e-6)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    base_dir = args.rules_dir.parent / "fanout_baseline"
    baselines(args.days_dir, args.rules_dir, sorted(_days(args.days)), base_dir)
    train = sorted(_days(args.train_days))
    rules = pl.concat([pl.read_parquet(args.rules_dir / f"day{d:02d}.parquet") for d in train])
    base = pl.concat([pl.read_parquet(base_dir / f"day{d:02d}.parquet") for d in train])["fo_baseline"].to_numpy()
    n = rules.height
    table = []
    for limit in (1, 2, 3, 5, 10):
        for accounts in (2, 3, 4, 5, 8):
            for novel in (1, 2, 3, 5, 8):
                rate = float(flags(rules, base, accounts, novel, limit).sum()) / n
                table.append({"baseline_limit": limit, "accounts": accounts, "novel_moves": novel,
                              "flags_per_million": 1e6 * rate})
    within = [r for r in table if r["flags_per_million"] <= 1e6 * args.budget]
    # most sensitive within budget: highest flag rate, then the loosest thresholds
    best = max(within, key=lambda r: (r["flags_per_million"], r["baseline_limit"], -r["accounts"], -r["novel_moves"])) if within else None
    for r in sorted(table, key=lambda r: r["flags_per_million"])[:40]:
        print(r, flush=True)
    print("chosen:", best, flush=True)
    args.out.write_text(json.dumps({"budget": args.budget, "train_days": train, "chosen": best, "table": table},
                                   indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
