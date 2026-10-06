"""Process-novelty features for every authentication event (label-free).

A process is *new on a host* the first time that process name starts there, and
*new for an account* the first time that account starts it anywhere. Remote
execution (PsExec-style services, WMI, scheduled tasks) makes processes appear
on the destination that it never ran before; credential tools make them appear
on the attacker's own host. For each authentication event (account u, source s,
destination d, time t):

* ``dst_new_5m`` / ``dst_new_30m``: processes new on d started in (t, t+300] / (t, t+1800];
* ``src_new_1h``: processes new on s started in (t-3600, t];
* ``user_new_1h``: processes new for u started in (t-3600, t+300].

The ``after`` windows look ahead: a score using them is decided up to five (or
thirty) minutes after the logon, which the evaluation states. Days are processed
in order and "new" is judged against every earlier day, so day 0 is a warm-up.

    python scripts/proc_features.py --proc-days artifacts/proc/days --auth-days artifacts/fullrate/days \\
        --days 0-29 --out artifacts/proc/features
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402

SHIFT = np.int64(1) << 32


def keys(entity: np.ndarray, t: np.ndarray) -> np.ndarray:
    return entity.astype(np.int64) * SHIFT + t.astype(np.int64)


def count(sorted_keys: np.ndarray, entity: np.ndarray, lo: np.ndarray, hi: np.ndarray) -> np.ndarray:
    """Events of ``entity`` with time in (lo, hi]."""
    base = entity.astype(np.int64) * SHIFT
    return (np.searchsorted(sorted_keys, base + hi, "right") - np.searchsorted(sorted_keys, base + lo, "right")).astype(
        np.int32)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--proc-days", type=Path, required=True)
    ap.add_argument("--auth-days", type=Path, required=True)
    ap.add_argument("--days", default="0-29")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    days = sorted(_days(args.days))

    # 1. novel (host, process) and (user, process) first starts, day by day
    seen_hp = pl.DataFrame(schema={"host": pl.Int32, "proc": pl.Int64})
    seen_up = pl.DataFrame(schema={"user": pl.Int32, "proc": pl.Int64})
    novel_host: dict[int, np.ndarray] = {}
    novel_user: dict[int, np.ndarray] = {}
    stats = {}
    for d in days:
        t0 = time.perf_counter()
        p = pl.read_parquet(args.proc_days / f"proc{d:02d}.parquet")
        hp = p.filter(pl.col("host") >= 0).group_by(["host", "proc"]).agg(pl.col("t").min())
        new_hp = hp.join(seen_hp, on=["host", "proc"], how="anti")
        up = p.filter(pl.col("user") >= 0).group_by(["user", "proc"]).agg(pl.col("t").min())
        new_up = up.join(seen_up, on=["user", "proc"], how="anti")
        seen_hp = pl.concat([seen_hp, new_hp.select(["host", "proc"])])
        seen_up = pl.concat([seen_up, new_up.select(["user", "proc"])])
        novel_host[d] = np.sort(keys(new_hp["host"].to_numpy(), new_hp["t"].to_numpy()))
        novel_user[d] = np.sort(keys(new_up["user"].to_numpy(), new_up["t"].to_numpy()))
        stats[d] = {"starts": p.height, "new_host_process": new_hp.height, "new_user_process": new_up.height}
        print(f"day {d:02d}: {p.height:,} starts, {new_hp.height:,} new host-process, "
              f"{new_up.height:,} new account-process ({time.perf_counter() - t0:.0f}s)", flush=True)
        del p, hp, up, new_hp, new_up
        gc.collect()

    # 2. features for every authentication event (windows may cross midnight)
    for d in days:
        t0 = time.perf_counter()
        a = pl.read_parquet(args.auth_days / f"day{d:02d}.parquet", columns=["event_id", "timestamp", "user", "src", "dst"])
        near = [x for x in (d - 1, d, d + 1) if x in novel_host]
        kh = np.sort(np.concatenate([novel_host[x] for x in near]))
        ku = np.sort(np.concatenate([novel_user[x] for x in near]))
        t = a["timestamp"].to_numpy().astype(np.int64)
        src, dst, user = a["src"].to_numpy(), a["dst"].to_numpy(), a["user"].to_numpy()
        out = pl.DataFrame({
            "event_id": a["event_id"],
            "dst_new_5m": count(kh, dst, t, t + 300),
            "dst_new_30m": count(kh, dst, t, t + 1_800),
            "src_new_1h": count(kh, src, t - 3_600, t),
            "user_new_1h": count(ku, user, t - 3_600, t + 300),
        })
        out.write_parquet(args.out / f"day{d:02d}.parquet")
        nz = {c: float((out[c] > 0).mean()) for c in out.columns if c != "event_id"}
        print(f"features day {d:02d}: {out.height:,} events, share non-zero {nz} ({time.perf_counter() - t0:.0f}s)",
              flush=True)
        del a, out
        gc.collect()
    (args.out / "summary.json").write_text(json.dumps({"days": days, "per_day": stats}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
