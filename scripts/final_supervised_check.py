"""Score the chosen supervised set-up once on the final window, attacker seen and unseen.

The set-up (feature set and model) is the one the leave-one-attacker-out study on
the training days chose. It is trained on days 0-15 three times -- with every
attacker host, and with each final-window attacker host removed -- and every
event of the final window is scored. Thresholds come from the calibration day.

    python scripts/final_supervised_check.py --days-dir artifacts/fullrate/days \\
        --feature-set no_identity --model gbdt_reg --out artifacts/transfer/improve/final_supervised.json
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
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from fullrate_eval import SLICE, _matrix  # noqa: E402
from improve_eval import Histo, log  # noqa: E402
from loho_study import columns, full_matrix, make_models, with_proc  # noqa: E402
from transfer_common import category_maps  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402

BUDGETS = (1e-5, 1e-4, 1e-3)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, default=Path("artifacts/fullrate/id_maps_0_29"))
    ap.add_argument("--train-days", default="0-15")
    ap.add_argument("--calib-day", type=int, default=15)
    ap.add_argument("--test-days", default="16-29")
    ap.add_argument("--feature-set", default="no_identity")
    ap.add_argument("--model", default="gbdt_reg")
    ap.add_argument("--benign-train", type=int, default=1_000_000)
    ap.add_argument("--proc-dir", type=Path, default=None)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    maps = category_maps(args.id_maps)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    train_days, test_days = sorted(_days(args.train_days)), sorted(_days(args.test_days))
    cols = columns(args.feature_set)

    # attacker hosts of the final window
    campaigns: set[tuple[int, int]] = set()
    for d in test_days:
        f = pl.read_parquet(args.days_dir / f"day{d:02d}.parquet", columns=["label", "src"])
        campaigns |= {(int(h), d) for h in f.filter(pl.col("label") == 1)["src"].unique().to_list()}
    final_attackers = sorted({h for h, _ in campaigns})

    attacks, benign = [], []
    for d in train_days:
        f = with_proc(pl.read_parquet(args.days_dir / f"day{d:02d}.parquet"), args.proc_dir, d)
        attacks.append(f.filter(pl.col("label") == 1))
        b = f.filter(pl.col("label") == 0)
        take = rng.choice(b.height, size=min(args.benign_train // len(train_days), b.height), replace=False)
        benign.append(b[np.sort(take)])
        del f, b
        gc.collect()
    a_df, b_df = pl.concat(attacks), pl.concat(benign)
    scaler = FeatureScaler.fit({c: b_df[c].to_numpy() for c in NUMERIC_FEATURES})
    xa, xb = full_matrix(a_df, scaler, maps)[:, cols], full_matrix(b_df, scaler, maps)[:, cols]
    sa, sb = a_df["src"].to_numpy(), b_df["src"].to_numpy()
    variants: dict[str, object] = {}
    for name, excluded in [("seen", None), *((f"without_{hosts[h]}", h) for h in final_attackers)]:
        ka = np.ones(len(xa), bool) if excluded is None else sa != excluded
        kb = np.ones(len(xb), bool) if excluded is None else sb != excluded
        x = np.concatenate([xa[ka], xb[kb]])
        y = np.concatenate([np.ones(int(ka.sum())), np.zeros(int(kb.sum()))])
        w = np.where(y == 1, (y == 0).sum() / y.sum(), 1.0)
        model = make_models(args.seed)[args.model]
        if args.model == "logistic":
            model.fit(x, y)  # type: ignore[attr-defined]
        else:
            model.fit(x, y, sample_weight=w)  # type: ignore[attr-defined]
        variants[name] = model
        log(f"{name}: {int(ka.sum())} training attacks")
        del x, y, w
    del xa, xb
    gc.collect()

    def score(day: int) -> tuple[dict[str, np.ndarray], np.ndarray, np.ndarray]:
        f = with_proc(pl.read_parquet(args.days_dir / f"day{day:02d}.parquet"), args.proc_dir, day)
        out = {n: np.empty(f.height, dtype=np.float32) for n in variants}
        for lo in range(0, f.height, SLICE):
            x = full_matrix(f[lo: lo + SLICE], scaler, maps)[:, cols]
            for n, m in variants.items():
                out[n][lo: lo + len(x)] = m.predict_proba(x)[:, 1]  # type: ignore[attr-defined]
            del x
        labels, src = f["label"].to_numpy(), f["src"].to_numpy()
        del f
        gc.collect()
        return out, labels, src

    calib, _, _ = score(args.calib_day)
    ref = {n: np.sort(v) for n, v in calib.items()}
    taus = {n: {a: float(np.quantile(v, 1 - a, method="higher")) for a in BUDGETS} for n, v in calib.items()}
    del calib
    histos = {n: Histo() for n in variants}
    best: dict[str, dict[str, float]] = {n: {} for n in variants}
    caught: dict[str, dict[float, set[str]]] = {n: {a: set() for a in BUDGETS} for n in variants}
    alerts: dict[str, dict[float, list[int]]] = {n: {a: [] for a in BUDGETS} for n in variants}
    for day in test_days:
        t0 = time.perf_counter()
        sc, labels, src = score(day)
        for n, s in sc.items():
            histos[n].add((np.searchsorted(ref[n], s, "right") / len(ref[n])).astype(np.float32), labels)
            for a in BUDGETS:
                flag = s > taus[n][a]
                alerts[n][a].append(int(flag.sum()))
                for h, d in campaigns:
                    if d == day and (flag & (src == h) & (labels == 1)).any():
                        caught[n][a].add(f"{hosts[h]}/day{d}")
            for h, d in campaigns:
                if d == day:
                    b = float(s[(src == h) & (labels == 1)].max())
                    best[n][f"{hosts[h]}/day{d}"] = float((s > b).sum() + ((s == b).sum() + 1) / 2)
        log(f"day {day}: {time.perf_counter() - t0:.0f}s")
        del sc, labels, src
        gc.collect()
    result: dict[str, object] = {"feature_set": args.feature_set, "model": args.model,
                                 "campaign_days": sorted(f"{hosts[h]}/day{d}" for h, d in campaigns), "variants": {}}
    for n in variants:
        m = histos[n].metrics()
        own = None if n == "seen" else n.split("_", 1)[1]
        ranks = best[n]
        entry = {
            **m,
            "hd300": int(sum(r <= 300 for r in ranks.values())),
            "best_rank": ranks,
            "caught": {str(a): sorted(v) for a, v in caught[n].items()},
            "alerts_per_day_median": {str(a): float(np.median(v)) for a, v in alerts[n].items()},
        }
        if own:
            mine = {k: v for k, v in ranks.items() if k.startswith(own + "/")}
            entry["unseen_host"] = own
            entry["unseen_hd300"] = int(sum(r <= 300 for r in mine.values()))
            entry["unseen_campaign_days"] = len(mine)
            entry["unseen_caught"] = {str(a): sorted(c for c in v if c.startswith(own + "/"))
                                      for a, v in caught[n].items()}
        result["variants"][n] = entry  # type: ignore[index]
        log(f"{n:>22}: AUC {m['roc_auc']:.3f} AP {m['ap']:.2e} HD@300 {entry['hd300']}/{len(campaigns)}"
            + (f" | unseen {own}: HD@300 {entry['unseen_hd300']}/{entry['unseen_campaign_days']}, caught@1e-4 "
               f"{len(entry['unseen_caught']['0.0001'])}" if own else "")
            + f" | caught@1e-4 {len(caught[n][1e-4])}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
