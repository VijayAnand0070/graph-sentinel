"""Campaign view: is the attacking host among a day's top alerts?

LANL's red-team file labels the attacker's *compromise* authentications; the
attacker host's other authentications on the same days are unlabelled (on day
8, C17693 made 527 authentications, 261 labelled). Per-event metrics then count
attacker activity as false positives. What a SOC acts on is the host: if any
authentication from the attacking host is among the day's top-K alerts, the
intrusion is in front of an analyst that day.

For each detector and each (attacker host, attack day): the best rank of any of
the host's events among all of the day's events, whether that is within the top
K for K in {10, 30, 100, 300} alerts a day, and the minutes from the day's first
labelled attack event to the first of the host's events that is within the top K.

    python scripts/host_day_detection.py --days-dir artifacts/fullrate/days \\
        --id-maps artifacts/fullrate/id_maps --model tgn=artifacts/transfer/scores_s1729 \\
        --supervised artifacts/transfer/supervised.joblib --out artifacts/transfer/host_day.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from fullrate_eval import FEATURE_DETECTORS, _matrix  # noqa: E402
from transfer_common import category_maps  # noqa: E402

KS = (10, 30, 100, 300)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--test-days", default="8-15")
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--supervised", type=Path, default=None)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    maps = category_maps(args.id_maps)
    bundle = None
    if args.supervised and args.supervised.exists():
        import joblib

        bundle = joblib.load(args.supervised)
    names = list(FEATURE_DETECTORS) + [m.split("=", 1)[0] for m in args.model]
    if bundle:
        names += [n for n in bundle["models"] if n != "isolation_forest"]
    results: dict[str, dict] = {n: {} for n in names}
    for day in sorted(_days(args.test_days)):
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        label = f["label"].to_numpy()
        if label.sum() == 0:
            continue
        src = f["src"].to_numpy()
        t = f["timestamp"].to_numpy()
        attackers = sorted({int(s) for s in src[label == 1]})
        for name in names:
            if name in FEATURE_DETECTORS:
                cols, fn = FEATURE_DETECTORS[name]
                scores = fn({c: f[c].to_numpy().astype(np.float64) for c in cols})
            elif bundle and name in bundle["models"]:
                scores = np.empty(f.height)
                for lo in range(0, f.height, 2_000_000):
                    x = _matrix(f[lo: lo + 2_000_000], bundle["scaler"], maps)
                    scores[lo: lo + len(x)] = bundle["models"][name].predict_proba(x)[:, 1]
            else:
                path = dict(m.split("=", 1) for m in args.model)[name]
                s = pl.read_parquet(Path(path) / f"day{day:02d}.parquet")
                assert (s["event_id"].to_numpy() == f["event_id"].to_numpy()).all()
                scores = -s["logit"].to_numpy()
            order = np.argsort(-scores, kind="stable")
            rank = np.empty(len(scores), dtype=np.int64)
            rank[order] = np.arange(1, len(scores) + 1)
            for h in attackers:
                mine = src == h
                first_attack = int(t[mine & (label == 1)].min())
                entry = {"events": int(mine.sum()), "labelled": int((mine & (label == 1)).sum()),
                         "best_rank": int(rank[mine].min())}
                for k in KS:
                    hit = mine & (rank <= k)
                    entry[f"top{k}"] = bool(hit.any())
                    entry[f"top{k}_minutes"] = round((int(t[hit].min()) - first_attack) / 60, 1) if hit.any() else None
                results[name][f"{hosts[h]}/day{day}"] = entry
        print(f"day {day}: attackers {[hosts[h] for h in attackers]}", flush=True)
        del f
    summary = {}
    for name, per in results.items():
        summary[name] = {f"top{k}": sum(v[f"top{k}"] for v in per.values()) for k in KS}
        summary[name]["campaign_days"] = len(per)
        summary[name]["median_best_rank"] = float(np.median([v["best_rank"] for v in per.values()])) if per else None
        print(f"{name:>22}: {summary[name]}", flush=True)
    args.out.write_text(json.dumps({"summary": summary, "per_host_day": results}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
