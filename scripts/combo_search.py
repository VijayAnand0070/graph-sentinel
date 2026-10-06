"""Search label-free score combinations on a development window (no labels used to score).

Every base detector is turned into its percentile among the calibration day's
events (no labels). A combination is the mean (or max) of the percentiles of a
set of base detectors, optionally with a bonus for the behavioural rules. Each
combination is judged on the development window by:

* HD@K -- campaign-days whose attacker host has an event in the day's top K;
* campaign-days detected at budgets alpha (thresholds from the calibration day);
* event-level ROC-AUC and average precision.

The search runs one day at a time and keeps only counts, so memory stays bounded.
Choose on the development window; score the chosen combination once on the final
window with ``--only``.

    python scripts/combo_search.py --days-dir artifacts/fullrate/days \\
        --tgn artifacts/transfer/scores_s1729 --supervised artifacts/transfer/supervised.joblib \\
        --rules-dir artifacts/fullrate/rules --calib-day 7 --test-days 8-15 \\
        --out artifacts/transfer/improve/combos_dev.json
"""

from __future__ import annotations

import argparse
import gc
import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from fullrate_eval import FEATURE_DETECTORS, SLICE, _matrix, fanout_flags  # noqa: E402
from improve_eval import Histo, log  # noqa: E402
from transfer_common import category_maps  # noqa: E402

BUDGETS = (1e-6, 1e-5, 1e-4, 1e-3)
KS = (10, 30, 100, 300)
FANOUT = (8, 5, 2.0)

#: label-free base detectors read from the event's causal features
RAW = {
    "user_src_new": (["user_src_seen_before"], lambda f: 1.0 - f["user_src_seen_before"]),
    "host_pair_new": (["src_dst_seen_before"], lambda f: 1.0 - f["src_dst_seen_before"]),
    "src_fanout": (["src_host_unique_users_1h"], lambda f: f["src_host_unique_users_1h"]),
    "new_dst_ratio": (["user_new_dst_ratio_1h"], lambda f: f["user_new_dst_ratio_1h"]),
}
CORE = ["tgn", "rarity", "iforest", "user_src_new", "host_pair_new", "src_fanout"]
#: process-novelty detectors (scripts/proc_features.py), used with --proc-dir
PROC = {
    "proc_dst5": lambda f: f["dst_new_5m"],
    "proc_dst30": lambda f: f["dst_new_30m"],
    "proc_src": lambda f: f["src_new_1h"],
    "proc_user": lambda f: f["user_new_1h"],
    "proc_sum": lambda f: f["dst_new_5m"] + f["src_new_1h"] + f["user_new_1h"],
}


def proc_combos() -> dict[str, tuple[str, tuple[str, ...], float]]:
    base = ("tgn", "rarity", "iforest")
    out: dict[str, tuple[str, tuple[str, ...], float]] = {m: ("mean", (m,), 0.0) for m in (*base, *PROC)}
    out["mean(tgn+rarity+iforest)"] = ("mean", base, 0.0)
    for m in PROC:
        out[f"mean(tgn+rarity+iforest+{m})"] = ("mean", (*base, m), 0.0)
        out[f"max(mean3,{m})"] = ("max3", (*base, m), 0.0)
    out["mean(tgn+rarity+iforest+proc_dst5+proc_src)"] = ("mean", (*base, "proc_dst5", "proc_src"), 0.0)
    out["mean(tgn+rarity+iforest+proc_dst30+proc_user)"] = ("mean", (*base, "proc_dst30", "proc_user"), 0.0)
    return out


def combos() -> dict[str, tuple[str, tuple[str, ...], float]]:
    """name -> (operator, members, rule bonus)."""
    out: dict[str, tuple[str, tuple[str, ...], float]] = {}
    for m in [*CORE, "new_dst_ratio", "edgebank"]:
        out[m] = ("mean", (m,), 0.0)
    for size in (2, 3, 4):
        for members in itertools.combinations(CORE, size):
            out["mean(" + "+".join(members) + ")"] = ("mean", members, 0.0)
    for members in itertools.combinations(CORE, 3):
        out["max(" + "+".join(members) + ")"] = ("max", members, 0.0)
    base = ("tgn", "rarity", "iforest")
    out["mean(tgn+rarity+iforest)+rules"] = ("mean", base, 0.5)
    out["mean(tgn+rarity+iforest+new_dst_ratio)"] = ("mean", (*base, "new_dst_ratio"), 0.0)
    out["mean(tgn+rarity+iforest+edgebank)"] = ("mean", (*base, "edgebank"), 0.0)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, default=Path("artifacts/fullrate/id_maps_0_29"))
    ap.add_argument("--tgn", type=Path, required=True)
    ap.add_argument("--supervised", type=Path, required=True, help="bundle holding the isolation forest and scaler")
    ap.add_argument("--rules-dir", type=Path, required=True)
    ap.add_argument("--calib-day", type=int, default=7)
    ap.add_argument("--test-days", default="8-15")
    ap.add_argument("--proc-dir", type=Path, default=None, help="process features: search process combinations")
    ap.add_argument("--only", default="", help="comma-separated combination names to score (final run)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    import joblib

    bundle = joblib.load(args.supervised)
    iforest, scaler = bundle["models"]["isolation_forest"], bundle["scaler"]
    maps = category_maps(args.id_maps)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    table = proc_combos() if args.proc_dir else combos()
    if args.only:
        wanted = [w.strip() for w in args.only.split(";") if w.strip()]
        table = {k: v for k, v in table.items() if k in wanted}
        missing = set(wanted) - set(table)
        if missing:
            raise SystemExit(f"unknown combinations: {sorted(missing)}")
    needed = sorted({m for _, members, _ in table.values() for m in members})
    test_days = sorted(_days(args.test_days))

    def base(day: int) -> tuple[dict[str, np.ndarray], np.ndarray, pl.DataFrame]:
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        out: dict[str, np.ndarray] = {}
        if "tgn" in needed:
            s = pl.read_parquet(args.tgn / f"day{day:02d}.parquet")
            assert (s["event_id"].to_numpy() == f["event_id"].to_numpy()).all()
            out["tgn"] = (-s["logit"].to_numpy()).astype(np.float32)
        for name, (cols, fn) in {**RAW, "rarity": FEATURE_DETECTORS["rarity"],
                                 "edgebank": FEATURE_DETECTORS["edgebank"]}.items():
            if name in needed:
                out[name] = fn({c: f[c].to_numpy().astype(np.float64) for c in cols}).astype(np.float32)
        if "iforest" in needed:
            out["iforest"] = np.empty(f.height, dtype=np.float32)
            for lo in range(0, f.height, SLICE):
                x = _matrix(f[lo: lo + SLICE], scaler, maps)
                out["iforest"][lo: lo + len(x)] = -iforest.score_samples(x)
                del x
        if args.proc_dir is not None:
            pf = pl.read_parquet(args.proc_dir / f"day{day:02d}.parquet")
            assert (pf["event_id"].to_numpy() == f["event_id"].to_numpy()).all()
            cols = {c: pf[c].to_numpy().astype(np.float64) for c in pf.columns if c != "event_id"}
            for name, fn in PROC.items():
                if name in needed:
                    out[name] = fn(cols).astype(np.float32)
            del pf, cols
        r = pl.read_parquet(args.rules_dir / f"day{day:02d}.parquet")
        bfile = args.rules_dir.parent / "fanout_baseline" / f"day{day:02d}.parquet"
        b = pl.read_parquet(bfile)["fo_baseline"].to_numpy() if bfile.is_file() else None
        rules = (r["chain_hop"].to_numpy().astype(bool) | fanout_flags(r, FANOUT, b)).astype(np.float32)
        meta = f.select(["label", "src"])
        del f, r
        gc.collect()
        return out, rules, meta

    def score(name: str, pct: dict[str, np.ndarray], rules: np.ndarray) -> np.ndarray:
        op, members, bonus = table[name]
        stack = np.stack([pct[m] for m in members])
        if op == "max3":  # the served mean of the first three, or the last member if higher
            s = np.maximum(stack[:3].mean(axis=0), stack[3])
        else:
            s = stack.mean(axis=0) if op == "mean" else stack.max(axis=0)
        if bonus:
            s = s + bonus * rules
        return s.astype(np.float32)

    log(f"calibration day {args.calib_day}; {len(table)} combinations over {needed}")
    raw_c, rules_c, _ = base(args.calib_day)
    ref = {k: np.sort(v) for k, v in raw_c.items()}

    def to_pct(raw: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
        return {k: (np.searchsorted(ref[k], v, "right") / len(ref[k])).astype(np.float32) for k, v in raw.items()}

    pct_c = to_pct(raw_c)
    thresholds: dict[str, dict[float, float]] = {}
    for name in table:
        s = score(name, pct_c, rules_c)
        thresholds[name] = {a: float(np.quantile(s, 1 - a, method="higher")) for a in BUDGETS}
    del raw_c, pct_c, rules_c
    gc.collect()

    histos = {n: Histo() for n in table}
    stats: dict[str, dict[str, object]] = {n: {"hd": {k: 0 for k in KS}, "best_rank": {},
                                              "camp": {a: 0 for a in BUDGETS},
                                              "alerts": {a: [] for a in BUDGETS}} for n in table}
    n_campaigns = 0
    for day in test_days:
        t0 = time.perf_counter()
        raw, rules, meta = base(day)
        pct = to_pct(raw)
        del raw
        labels = meta["label"].to_numpy()
        src = meta["src"].to_numpy()
        attackers = sorted({int(h) for h in src[labels == 1]})
        n_campaigns += len(attackers)
        masks = {h: src == h for h in attackers}
        for name in table:
            s = score(name, pct, rules)
            # bounded to [0, 1] for the histogram (rule bonus can exceed 1)
            histos[name].add(np.minimum(s / (1.0 + table[name][2]), 1.0), labels)
            st = stats[name]
            for a in BUDGETS:
                flag = s > thresholds[name][a]
                st["alerts"][a].append(int(flag.sum()))  # type: ignore[index]
                for h in attackers:
                    if (flag & masks[h] & (labels == 1)).any():
                        st["camp"][a] += 1  # type: ignore[index]
            if attackers:
                for h in attackers:
                    best = float(s[masks[h]].max())
                    # ties are broken at random: the expected rank sits in the middle of the tie
                    greater = int((s > best).sum())
                    equal = int((s == best).sum())
                    rank = greater + (equal + 1) / 2
                    st["best_rank"][f"{hosts[h]}/day{day}"] = float(rank)  # type: ignore[index]
                    for k in KS:
                        if rank <= k:
                            st["hd"][k] += 1  # type: ignore[index]
        log(f"day {day}: {len(labels):,} events, {len(attackers)} campaign(s), {time.perf_counter() - t0:.0f}s")
        del pct, rules, meta, labels, src
        gc.collect()

    rows = []
    for name in table:
        st = stats[name]
        m = histos[name].metrics()
        rows.append({
            "name": name,
            "roc_auc": m["roc_auc"], "ap": m["ap"],
            "hd": {str(k): v for k, v in st["hd"].items()},  # type: ignore[union-attr]
            "campaigns": {str(a): v for a, v in st["camp"].items()},  # type: ignore[union-attr]
            "alerts_per_day_median": {str(a): float(np.median(v)) for a, v in st["alerts"].items()},  # type: ignore[union-attr]
            "best_rank": st["best_rank"],
        })
    rows.sort(key=lambda r: (r["hd"]["300"], r["campaigns"]["1e-05"], r["hd"]["100"], r["ap"]), reverse=True)
    out = {"calibration_day": args.calib_day, "test_days": test_days, "campaign_days": n_campaigns, "rows": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    for r in rows[:15]:
        log(f"{r['name']:>50}: HD@300 {r['hd']['300']} HD@100 {r['hd']['100']} camp@1e-5 {r['campaigns']['1e-05']} "
            f"camp@1e-4 {r['campaigns']['0.0001']} AUC {r['roc_auc']:.3f} AP {r['ap']:.2e}")
    log(f"written {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
