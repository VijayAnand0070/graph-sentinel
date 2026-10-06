"""Full-rate LANL corpus: exact causal features for every event, day by day.

The stride-sampled corpora behind the first model kept every red-team event and
one benign event in several hundred, and computed features on that thinned
stream: an attacker kept its whole history while a benign account kept a
fraction of its own, so windowed counts and novelty differed between the classes
partly because of the sampling (docs/JOURNAL_PLAN.md, E1). Here nothing is
dropped before features are computed: every authentication of every day is
featurised against the complete history before it, with the vectorised engine
(identical to the streaming one, tested event by event).

For the self-supervised model it also writes counterfactual negatives for a
sample of real events in the training days: the same account, time and event
type with another destination (drawn by popularity, or uniformly from hosts
seen so far) or another source host, featurised against the same history.

    python scripts/fullrate_build.py --interim artifacts/fullrate/interim \\
        --id-maps artifacts/fullrate/id_maps --out artifacts/fullrate/days --neg-days 0-7
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
sys.path.insert(0, str(ROOT / "src"))

from graphsentinel.features.vectorized import QueryEvents, VectorizedFeatureEngine  # noqa: E402
from graphsentinel.models.transfer import NUMERIC_FEATURES  # noqa: E402

COLUMNS = [
    "event_id", "timestamp", "src_user_id", "src_host_id", "dst_host_id", "auth_type_id",
    "logon_type_id", "orientation_id", "success", "label_redteam",
]
SLICE = 2_000_000
#: negatives per sampled positive: (kind, how many)
NEGATIVE_PLAN = (("dst_popular", 2), ("dst_uniform", 1), ("src_popular", 2))


def _days(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.update(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out


def _query(engine: VectorizedFeatureEngine, q: QueryEvents) -> dict[str, np.ndarray]:
    parts: list[dict[str, np.ndarray]] = []
    for lo in range(0, len(q.t), SLICE):
        sl = slice(lo, lo + SLICE)
        f = engine.query(QueryEvents(q.t[sl], q.user[sl], q.src[sl], q.dst[sl], q.logon[sl], q.success[sl]))
        parts.append({k: f[k].astype(np.float32) for k in NUMERIC_FEATURES})
        del f
    return {k: np.concatenate([p[k] for p in parts]) for k in NUMERIC_FEATURES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--interim", type=Path, required=True)
    parser.add_argument("--id-maps", type=Path, help="unused; kept for command compatibility")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", default="0-15")
    parser.add_argument("--neg-days", default="0-7")
    parser.add_argument("--neg-rate", type=float, default=0.02)
    parser.add_argument("--seed", type=int, default=1729)
    parser.add_argument("--wait-for", type=Path, help="ingest report whose appearance means every day is written")
    parser.add_argument("--keep-existing", action="store_true",
                        help="replay days whose file exists (to rebuild state) without rewriting them")
    args = parser.parse_args(argv)

    rng = np.random.default_rng(args.seed)
    engine = VectorizedFeatureEngine()
    neg_days = _days(args.neg_days)
    args.out.mkdir(parents=True, exist_ok=True)
    hosts_seen = np.zeros(1 << 16, dtype=bool)
    summary: dict[str, object] = {"days": {}, "numeric_features": list(NUMERIC_FEATURES)}

    for day in sorted(_days(args.days)):
        if args.wait_for:
            # the ingest writes chronologically: a day is complete once the day
            # after next has appeared, or once the ingest has written its report
            while not (args.interim / f"auth_day={day + 2:02d}").exists() and not args.wait_for.exists():
                time.sleep(20)
        started = time.perf_counter()
        part = args.interim / f"auth_day={day:02d}"
        ev = pl.read_parquet(str(part / "*.parquet"), columns=COLUMNS).sort(["timestamp", "event_id"])
        arr = {c: ev[c].to_numpy() for c in COLUMNS}
        del ev
        gc.collect()
        n = len(arr["timestamp"])
        engine.begin_chunk(
            {
                "t": arr["timestamp"], "user": arr["src_user_id"], "src": arr["src_host_id"],
                "dst": arr["dst_host_id"], "logon": arr["logon_type_id"], "success": arr["success"],
            }
        )
        q = QueryEvents(
            arr["timestamp"], arr["src_user_id"], arr["src_host_id"], arr["dst_host_id"],
            arr["logon_type_id"], arr["success"],
        )
        feats = _query(engine, q)
        frame = pl.DataFrame(
            {
                "event_id": arr["event_id"].astype(np.int64),
                "timestamp": arr["timestamp"].astype(np.int32),
                "user": arr["src_user_id"].astype(np.int32),
                "src": arr["src_host_id"].astype(np.int32),
                "dst": arr["dst_host_id"].astype(np.int32),
                # raw ingest ids; canonical categories are applied at load time,
                # because the id maps are only final once the ingest has finished
                "auth_id": arr["auth_type_id"].astype(np.int16),
                "logon_id": arr["logon_type_id"].astype(np.int16),
                "orient_id": arr["orientation_id"].astype(np.int16),
                "success": arr["success"].astype(np.int8),
                "label": arr["label_redteam"].astype(np.int8),
                **feats,
            }
        )
        target = args.out / f"day{day:02d}.parquet"
        if not (args.keep_existing and target.is_file()):
            frame.write_parquet(target, compression="zstd", compression_level=3)
        del frame, feats
        gc.collect()

        top = int(max(arr["src_host_id"].max(), arr["dst_host_id"].max()))
        if top >= len(hosts_seen):
            grown = np.zeros(max(top + 1, 2 * len(hosts_seen)), dtype=bool)
            grown[: len(hosts_seen)] = hosts_seen
            hosts_seen = grown
        hosts_seen[arr["src_host_id"]] = True
        hosts_seen[arr["dst_host_id"]] = True

        negatives = 0
        if day in neg_days and not (args.keep_existing and (args.out / f"neg{day:02d}.parquet").is_file()):
            pos = np.flatnonzero(rng.random(n) < args.neg_rate)
            pool_hosts = np.flatnonzero(hosts_seen)
            rows: dict[str, list[np.ndarray]] = {k: [] for k in ("pos_event_id", "kind", "t", "user", "src", "dst", "logon", "success")}
            for kind_id, (kind, count) in enumerate(NEGATIVE_PLAN):
                for _ in range(count):
                    user = arr["src_user_id"][pos]
                    src = arr["src_host_id"][pos].copy()
                    dst = arr["dst_host_id"][pos].copy()
                    if kind == "dst_popular":
                        dst = arr["dst_host_id"][rng.integers(0, n, len(pos))]
                    elif kind == "dst_uniform":
                        dst = pool_hosts[rng.integers(0, len(pool_hosts), len(pos))]
                    else:
                        src = arr["src_host_id"][rng.integers(0, n, len(pos))]
                    # a counterfactual must differ from the real event and not be a local logon;
                    # redraw the corrupted end only, from the uniform pool
                    real_src, real_dst = arr["src_host_id"][pos], arr["dst_host_id"][pos]
                    bad = (src == dst) | ((src == real_src) & (dst == real_dst))
                    while bad.any():
                        redraw = pool_hosts[rng.integers(0, len(pool_hosts), int(bad.sum()))]
                        if kind == "src_popular":
                            src[bad] = redraw
                        else:
                            dst[bad] = redraw
                        bad = (src == dst) | ((src == real_src) & (dst == real_dst))
                    rows["pos_event_id"].append(arr["event_id"][pos])
                    rows["kind"].append(np.full(len(pos), kind_id, dtype=np.int8))
                    rows["t"].append(arr["timestamp"][pos])
                    rows["user"].append(user)
                    rows["src"].append(src)
                    rows["dst"].append(dst)
                    rows["logon"].append(arr["logon_type_id"][pos])
                    rows["success"].append(arr["success"][pos])
            neg = {k: np.concatenate(v) for k, v in rows.items()}
            order = np.argsort(neg["t"], kind="stable")
            neg = {k: v[order] for k, v in neg.items()}
            nf = _query(engine, QueryEvents(neg["t"], neg["user"], neg["src"], neg["dst"], neg["logon"], neg["success"]))
            pl.DataFrame(
                {
                    "pos_event_id": neg["pos_event_id"].astype(np.int64),
                    "kind": neg["kind"],
                    "timestamp": neg["t"].astype(np.int32),
                    "user": neg["user"].astype(np.int32),
                    "src": neg["src"].astype(np.int32),
                    "dst": neg["dst"].astype(np.int32),
                    **nf,
                }
            ).write_parquet(args.out / f"neg{day:02d}.parquet", compression="zstd", compression_level=3)
            negatives = len(neg["t"])
            del nf, neg
        engine.end_chunk()
        attacks = int(arr["label_redteam"].sum())
        elapsed = time.perf_counter() - started
        summary["days"][day] = {"events": n, "attacks": attacks, "negatives": negatives, "seconds": round(elapsed, 1)}  # type: ignore[index]
        print(f"day {day:02d}: {n:,} events, {attacks} attacks, {negatives:,} negatives, {elapsed:.0f}s", flush=True)
        del arr
        gc.collect()
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
