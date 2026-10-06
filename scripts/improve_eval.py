"""Improvement and validation study on one evaluation window, one day at a time.

Four questions, answered with every event of the window and nothing tuned on it:

1. Do label-free detectors combine better than any one of them? Scores are turned
   into percentiles of the calibration day (no labels), then averaged or maxed.
2. Does ranking *machines* per day (what a SOC investigates) find the attacker
   host earlier than ranking single events?
3. How many ordinary accounts would the immediate two-hour lock hit per day, with
   the product's action budget, hourly cap and per-account hold?
4. Does a supervised detector find an attacker host it has never seen? It is
   retrained with every event of that host removed from the training days.
5. Does learning from analyst decisions work? A simulated analyst reviews only
   the alerts a label-free detector raised on the training days (the top
   ``--feedback-budget`` share of each day by rarity) and labels them correctly;
   a model is retrained from those decisions with ``retrain_from_feedback.py``.

Memory stays bounded: event-level AUC / AP are read from per-variant histograms of
benign percentile scores, and everything else is computed per day.

    python scripts/improve_eval.py --days-dir artifacts/fullrate/days \\
        --id-maps artifacts/fullrate/id_maps_0_29 --tgn artifacts/transfer/scores_final_s1729 \\
        --supervised artifacts/transfer/final/supervised.joblib --train-days 0-15 --calib-day 15 \\
        --test-days 16-29 --out artifacts/transfer/improve/improve_final.json
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
from fullrate_eval import FEATURE_DETECTORS, SLICE, _matrix  # noqa: E402
from retrain_from_feedback import build_training_set, fit  # noqa: E402
from transfer_common import category_maps  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402

BUDGETS = (1e-6, 1e-5, 1e-4, 1e-3)
EVENT_KS = (10, 30, 100, 300)
HOST_KS = (1, 5, 10, 20, 50)
BINS = 1 << 22
LOCK_HOLD_SECONDS = 7_200
LOCK_PER_HOUR = 20


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Histo:
    """Benign scores in [0, 1] as a histogram; attack scores kept exactly."""

    def __init__(self) -> None:
        self.benign = np.zeros(BINS + 1, dtype=np.int64)
        self.attacks: list[float] = []

    def add(self, scores: np.ndarray, labels: np.ndarray) -> None:
        b = scores[labels == 0]
        idx = np.minimum((b * BINS).astype(np.int64), BINS)
        self.benign += np.bincount(idx, minlength=BINS + 1)
        self.attacks.extend(scores[labels == 1].astype(float).tolist())

    def metrics(self) -> dict[str, float]:
        n_b = int(self.benign.sum())
        cum_le = np.cumsum(self.benign)  # benign with bin index <= i
        att = np.sort(np.array(self.attacks))[::-1]
        if not len(att) or not n_b:
            return {"roc_auc": float("nan"), "ap": float("nan")}
        idx = np.minimum((att * BINS).astype(np.int64), BINS)
        below = np.where(idx > 0, cum_le[idx - 1], 0)
        same = self.benign[idx]
        auc = float(np.mean((below + 0.5 * same) / n_b))
        above_or_equal = n_b - below
        ranks = np.arange(1, len(att) + 1)
        precision = ranks / (ranks + above_or_equal)
        return {"roc_auc": auc, "ap": float(np.mean(precision))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--tgn", action="append", default=[], help="name=scores_dir (anomaly = -logit)")
    ap.add_argument("--supervised", type=Path, required=True)
    ap.add_argument("--train-days", default="0-15")
    ap.add_argument("--calib-day", type=int, default=15)
    ap.add_argument("--test-days", default="16-29")
    ap.add_argument("--benign-train", type=int, default=1_000_000)
    ap.add_argument("--no-holdout", action="store_true")
    ap.add_argument("--feedback-budget", type=float, default=1e-4,
                    help="share of each training day's events the simulated analyst reviews; 0 disables")
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    maps = category_maps(args.id_maps)
    train_days = sorted(_days(args.train_days))
    test_days = sorted(_days(args.test_days))

    import joblib
    from sklearn.ensemble import HistGradientBoostingClassifier

    bundle = joblib.load(args.supervised)
    models = dict(bundle["models"])
    scaler = bundle["scaler"]
    tgn_dirs = {s.split("=", 1)[0]: Path(s.split("=", 1)[1]) for s in args.tgn}

    # attacker hosts of the window and their campaign-days
    campaigns: dict[tuple[int, int], int] = {}
    for d in test_days:
        f = pl.read_parquet(args.days_dir / f"day{d:02d}.parquet", columns=["label", "src"])
        for src, n in f.filter(pl.col("label") == 1).group_by("src").len().rows():
            campaigns[(int(src), d)] = int(n)
    attackers = sorted({h for h, _ in campaigns})
    log(f"attackers {[hosts[h] for h in attackers]}, campaign-days {len(campaigns)}")

    # ---------------------------------------------------------------- 4. unseen-attacker models
    holdout: dict[int, dict[str, object]] = {}
    if not args.no_holdout:
        for h in attackers:
            parts = []
            for d in train_days:
                f = pl.read_parquet(args.days_dir / f"day{d:02d}.parquet").filter(pl.col("src") != h)
                attacks = f.filter(pl.col("label") == 1)
                benign = f.filter(pl.col("label") == 0)
                take = rng.choice(benign.height, size=min(args.benign_train // len(train_days), benign.height),
                                  replace=False)
                parts.append(pl.concat([attacks, benign[np.sort(take)]]))
                del f, attacks, benign
                gc.collect()
            train = pl.concat(parts)
            x = _matrix(train, scaler, maps)
            y = train["label"].to_numpy()
            w = np.where(y == 1, (y == 0).sum() / max(1, y.sum()), 1.0)
            model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, random_state=args.seed).fit(
                x, y, sample_weight=w)
            holdout[h] = {"model": model, "train_attacks": int(y.sum())}
            log(f"holdout model without {hosts[h]}: {int(y.sum())} training attacks")
            del train, x, y, parts
            gc.collect()

    # ---------------------------------------------------------------- 5. learning from analyst decisions
    feedback: dict[str, object] = {}
    if args.feedback_budget > 0:
        cols, fn = FEATURE_DETECTORS["rarity"]
        reviewed = []
        for d in train_days:
            f = pl.read_parquet(args.days_dir / f"day{d:02d}.parquet", columns=["event_id", "label", *cols])
            r = fn({c: f[c].to_numpy().astype(np.float64) for c in cols})
            tau = np.quantile(r, 1 - args.feedback_budget, method="higher")
            queue = f.filter(pl.Series(r > tau))
            reviewed.append(queue.select(["event_id", "label"]))
            del f, r, queue
            gc.collect()
        labels_fb = pl.concat(reviewed)
        fb_train = build_training_set(labels_fb, args.days_dir, train_days, args.benign_train, rng)
        fb_bundle = fit(fb_train, maps, args.seed)
        feedback = {
            "reviewed_alerts": int(labels_fb.height),
            "confirmed": int(labels_fb["label"].sum()),
            "bundle": fb_bundle,
        }
        log(f"feedback model: {labels_fb.height} reviewed alerts, {int(labels_fb['label'].sum())} confirmed attacks")
        del fb_train, labels_fb
        gc.collect()

    # ---------------------------------------------------------------- scoring helpers
    def base_scores(day: int) -> tuple[dict[str, np.ndarray], pl.DataFrame]:
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        out: dict[str, np.ndarray] = {}
        for name, path in tgn_dirs.items():
            s = pl.read_parquet(path / f"day{day:02d}.parquet")
            assert (s["event_id"].to_numpy() == f["event_id"].to_numpy()).all()
            out[name] = (-s["logit"].to_numpy()).astype(np.float32)
        cols, fn = FEATURE_DETECTORS["rarity"]
        out["rarity"] = fn({c: f[c].to_numpy().astype(np.float64) for c in cols}).astype(np.float32)
        learned = {"isolation_forest": models["isolation_forest"], "gbdt": models["gbdt"]}
        for h, entry in holdout.items():
            learned[f"gbdt_without_{hosts[h]}"] = entry["model"]
        for name in learned:
            out[name] = np.empty(f.height, dtype=np.float32)
        for lo in range(0, f.height, SLICE):
            x = _matrix(f[lo: lo + SLICE], scaler, maps)
            for name, m in learned.items():
                if name == "isolation_forest":
                    out[name][lo: lo + len(x)] = -m.score_samples(x)
                else:
                    out[name][lo: lo + len(x)] = m.predict_proba(x)[:, 1]
            del x
        if feedback:
            fb = feedback["bundle"]
            fb_model, fb_scaler = fb["models"]["gbdt"], fb["scaler"]  # type: ignore[index]
            fb_cols = np.asarray(fb.get("columns", list(range(41))))  # type: ignore[union-attr]
            out["gbdt_feedback"] = np.empty(f.height, dtype=np.float32)
            for lo in range(0, f.height, SLICE):
                x = _matrix(f[lo: lo + SLICE], fb_scaler, maps)[:, fb_cols]
                out["gbdt_feedback"][lo: lo + len(x)] = fb_model.predict_proba(x)[:, 1]
                del x
        meta = f.select(["label", "src", "user", "timestamp"])
        del f
        gc.collect()
        return out, meta

    def to_pct(raw: dict[str, np.ndarray], ref: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
        return {k: (np.searchsorted(ref[k], v, "right") / len(ref[k])).astype(np.float32) for k, v in raw.items()}

    primary = next(iter(tgn_dirs))  # the served checkpoint; other --tgn entries are seed replicas
    lf_members = [primary, "rarity", "isolation_forest"]

    def variants(p: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
        v = dict(p)
        lf = np.stack([p[k] for k in lf_members])
        v["lf_mean"] = lf.mean(axis=0)
        v["lf_max"] = lf.max(axis=0)
        v["rarity+iforest"] = (p["rarity"] + p["isolation_forest"]) / 2
        v["lf_mean+gbdt"] = (lf.sum(axis=0) + p["gbdt"]) / (len(lf_members) + 1)
        return v

    # ---------------------------------------------------------------- calibration day (no labels)
    log(f"calibration day {args.calib_day}")
    raw_c, _ = base_scores(args.calib_day)
    ref = {k: np.sort(v) for k, v in raw_c.items()}
    var_c = variants(to_pct(raw_c, ref))
    thresholds = {k: {a: float(np.quantile(v, 1 - a, method="higher")) for a in BUDGETS} for k, v in var_c.items()}
    del raw_c, var_c
    gc.collect()

    histos: dict[str, Histo] = {}
    ops: dict[str, dict[float, dict[str, object]]] = {}
    hd_event: dict[str, dict[str, object]] = {}
    hd_host: dict[str, dict[str, object]] = {}
    locks: dict[str, dict[float, list[dict[str, int]]]] = {}
    lock_variants = [primary, "gbdt", "lf_mean", "lf_mean+gbdt"]
    for day in test_days:
        t0 = time.perf_counter()
        raw, meta = base_scores(day)
        var = variants(to_pct(raw, ref))
        labels = meta["label"].to_numpy()
        src = meta["src"].to_numpy()
        users = meta["user"].to_numpy()
        ts = meta["timestamp"].to_numpy()
        day_campaigns = [h for (h, d) in campaigns if d == day]
        for name, s in var.items():
            histos.setdefault(name, Histo()).add(s, labels)
            # budgets
            per = ops.setdefault(name, {})
            for a in BUDGETS:
                tau = thresholds[name][a]
                flag = s > tau
                row = per.setdefault(a, {"alerts": [], "benign_flags": 0, "attack_hits": 0, "campaigns": {}})
                row["alerts"].append(int(flag.sum()))  # type: ignore[union-attr]
                row["benign_flags"] += int((flag & (labels == 0)).sum())  # type: ignore[operator]
                row["attack_hits"] += int((flag & (labels == 1)).sum())  # type: ignore[operator]
                for h in day_campaigns:
                    mine = (src == h) & (labels == 1)
                    row["campaigns"][f"{hosts[h]}/day{day}"] = bool((flag & mine).any())  # type: ignore[index]
            if not day_campaigns:
                continue
            # event ranks of the day
            order = np.argsort(-s, kind="stable")
            rank = np.empty(len(s), dtype=np.int64)
            rank[order] = np.arange(1, len(s) + 1)
            # host ranks of the day: max score per source host, and mean of its top 3
            frame = pl.DataFrame({"src": src, "s": s})
            agg = frame.group_by("src").agg(
                pl.col("s").max().alias("mx"),
                pl.col("s").top_k(3).mean().alias("top3"),
            )
            for how in ("mx", "top3"):
                sorted_hosts = agg.sort(how, descending=True)["src"].to_numpy()
                host_rank = {int(hh): i + 1 for i, hh in enumerate(sorted_hosts)}
                for h in day_campaigns:
                    key = f"{hosts[h]}/day{day}"
                    hd_host.setdefault(f"{name}|{how}", {})[key] = {
                        "rank": host_rank.get(h), "hosts": len(sorted_hosts)}  # type: ignore[index]
            for h in day_campaigns:
                key = f"{hosts[h]}/day{day}"
                best = float(s[src == h].max())
                # ties broken at random: expected rank in the middle of the tie
                hd_event.setdefault(name, {})[key] = float((s > best).sum() + ((s == best).sum() + 1) / 2)  # type: ignore[index]
        # immediate-lock simulation at the action budget
        for name in lock_variants:
            for a in (1e-6, 1e-5):
                tau = thresholds[name][a]
                idx = np.flatnonzero(var[name] > tau)
                idx = idx[np.argsort(ts[idx], kind="stable")]
                held_until: dict[int, int] = {}
                recent: list[int] = []
                benign_locks = attack_locks = 0
                benign_accounts: set[int] = set()
                worst_hour = 0
                for i in idx:
                    t, u = int(ts[i]), int(users[i])
                    if held_until.get(u, -1) > t:
                        continue  # account already locked
                    recent = [r for r in recent if r > t - 3_600]
                    if len(recent) >= LOCK_PER_HOUR:
                        continue  # budget refuses: the lock waits for a person
                    recent.append(t)
                    worst_hour = max(worst_hour, len(recent))
                    held_until[u] = t + LOCK_HOLD_SECONDS
                    if labels[i] == 1:
                        attack_locks += 1
                    else:
                        benign_locks += 1
                        benign_accounts.add(u)
                locks.setdefault(name, {}).setdefault(a, []).append({
                    "day": day, "benign_locks": benign_locks, "benign_accounts": len(benign_accounts),
                    "attack_locks": attack_locks, "worst_hour": worst_hour})
        log(f"day {day}: {len(labels):,} events, {int(labels.sum())} attacks, {time.perf_counter() - t0:.0f}s")
        del raw, var, meta, labels, src, users, ts
        gc.collect()

    # ---------------------------------------------------------------- summarise
    results: dict[str, object] = {
        "protocol": {"train_days": train_days, "calibration_day": args.calib_day, "test_days": test_days,
                     "campaign_days": len(campaigns), "attackers": [hosts[h] for h in attackers],
                     "lf_members": lf_members, "holdout_training_attacks": {
                         hosts[h]: e["train_attacks"] for h, e in holdout.items()},
                     "feedback": {k: v for k, v in feedback.items() if k != "bundle"},
                     "feedback_budget": args.feedback_budget},
        "detectors": {},
    }
    for name, histo in histos.items():
        entry: dict[str, object] = histo.metrics()
        entry["budgets"] = {}
        for a, row in ops[name].items():
            entry["budgets"][str(a)] = {  # type: ignore[index]
                "alerts_per_day_median": float(np.median(row["alerts"])),
                "attack_hits": row["attack_hits"],
                "campaigns_detected": int(sum(row["campaigns"].values())),  # type: ignore[union-attr]
                "campaigns": row["campaigns"],
            }
        ev = hd_event.get(name, {})
        entry["event_hd"] = {f"top{k}": int(sum(r <= k for r in ev.values())) for k in EVENT_KS}  # type: ignore[union-attr]
        entry["event_best_rank"] = ev
        for how in ("mx", "top3"):
            hr = hd_host.get(f"{name}|{how}", {})
            ranks = [v["rank"] for v in hr.values() if v["rank"] is not None]  # type: ignore[index]
            entry[f"host_hd_{how}"] = {f"top{k}": int(sum(r <= k for r in ranks)) for k in HOST_KS}
            entry[f"host_ranks_{how}"] = hr
            entry[f"host_median_rank_{how}"] = float(np.median(ranks)) if ranks else None
        if name in locks:
            entry["immediate_lock"] = {}
            for a, rows in locks[name].items():
                entry["immediate_lock"][str(a)] = {  # type: ignore[index]
                    "benign_locks_per_day_mean": float(np.mean([r["benign_locks"] for r in rows])),
                    "benign_locks_per_day_max": int(max(r["benign_locks"] for r in rows)),
                    "worst_hour": int(max(r["worst_hour"] for r in rows)),
                    "attack_locks": int(sum(r["attack_locks"] for r in rows)),
                    "days": rows,
                }
        results["detectors"][name] = entry  # type: ignore[index]
        m = entry
        log(f"{name:>26}: AUC {m['roc_auc']:.3f} AP {m['ap']:.2e} | event HD@300 {m['event_hd']['top300']} "
            f"| host@10 {m['host_hd_mx']['top10']} host@50 {m['host_hd_mx']['top50']} "
            f"| camp@1e-4 {m['budgets']['0.0001']['campaigns_detected']}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    log(f"written {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
