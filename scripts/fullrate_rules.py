"""Stream the full-rate days through the behavioural rules (label-free).

For every event it records the shipped chain rule's decision and the fan-out
rule's inputs -- distinct accounts the source host used and novel hosts it
reached in the window before the event, and whether this destination is novel
for it -- so the fan-out thresholds can be chosen afterwards on unlabelled
training days by their cost, without re-streaming.

    python scripts/fullrate_rules.py --days-dir artifacts/fullrate/days --days 0-15 \\
        --out artifacts/fullrate/rules
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402

from graphsentinel.detection.signals import ChainPivotTracker, FanOutTracker  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--days", default="0-15")
    ap.add_argument("--fanout-window", type=int, default=3_600)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    chains = ChainPivotTracker()
    fan = FanOutTracker(window_seconds=args.fanout_window, minimum_accounts=1, minimum_novel_moves=0)
    for day in sorted(_days(args.days)):
        started = time.perf_counter()
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet", columns=["event_id", "timestamp", "user", "src", "dst", "success"])
        t = f["timestamp"].to_numpy().tolist()
        u = f["user"].to_numpy().tolist()
        s = f["src"].to_numpy().tolist()
        d = f["dst"].to_numpy().tolist()
        ok = f["success"].to_numpy().tolist()
        n = len(t)
        chain = np.zeros(n, dtype=np.int8)
        fo_acc = np.zeros(n, dtype=np.int32)
        fo_nov = np.zeros(n, dtype=np.int32)
        fo_now = np.zeros(n, dtype=np.int8)
        accounts, novel, reached = fan._accounts, fan._novel, fan._reached_ever
        i = 0
        while i < n:
            ts = t[i]
            j = i
            while j < n and t[j] == ts:
                j += 1
            chains.advance(ts)
            fan.advance(ts)
            for k in range(i, j):
                if ok[k]:
                    chain[k] = chains.is_chain_hop(u[k], s[k], d[k], success=True)
                    fo_now[k] = d[k] not in reached.get(s[k], ())
                fo_acc[k] = len(accounts.get(s[k], ()))
                fo_nov[k] = novel.get(s[k], 0)
            for k in range(i, j):
                if ok[k]:
                    chains.observe(u[k], s[k], d[k], ts)
                    fan.observe(u[k], s[k], d[k], ts)
            i = j
        pl.DataFrame(
            {"event_id": f["event_id"], "chain_hop": chain, "fo_accounts": fo_acc, "fo_novel": fo_nov, "fo_novel_now": fo_now}
        ).write_parquet(args.out / f"day{day:02d}.parquet")
        print(f"day {day:02d}: {n:,} events, {int(chain.sum())} chain hops, {time.perf_counter() - started:.0f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
