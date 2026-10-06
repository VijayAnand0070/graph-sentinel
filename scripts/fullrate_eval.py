"""Evaluate detectors on the full-rate LANL test days: every event scored, no sampling.

Protocol (fixed before any test score was read):

* training days 0-7: the self-supervised model and the isolation forest use
  them without labels; supervised baselines use their labels (50 attack events,
  the incidents a SOC would plausibly have labelled);
* calibration day 7: every detector's alert threshold for a false-positive
  budget alpha is the (1 - alpha) quantile of its scores over *all* of the
  day's events -- no label is read (attacks are 1 in 7 million);
* test days 8-15: 639 attack events from three attacker hosts among ~60 M
  benign authentications. Metrics use every event.

Reported per detector: ROC-AUC and average precision with bootstrap intervals
over attack events (benign scores held fixed), and at each budget the realised
benign flag rate, recall overall and per attacker host, and alerts per day.

    python scripts/fullrate_eval.py --days-dir artifacts/fullrate/days --id-maps artifacts/fullrate/id_maps \\
        --model tgn=artifacts/transfer/scores_s1729 --out artifacts/transfer/eval.json
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
from transfer_common import canonical_codes, category_maps  # noqa: E402

from graphsentinel.features.canonical import CATEGORICAL_WIDTH  # noqa: E402
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402

#: False-positive budgets as fractions of all events. At LANL's ~8 M authentications a day,
#: 1e-4 is ~800 alerts a day; 1e-5 (~80) and 1e-6 (~8) are the budgets a SOC and an
#: unattended response can actually carry.
BUDGETS = (1e-6, 1e-5, 1e-4, 1e-3)
SLICE = 2_000_000
#: benign alerts per day at which the operating curve is read
CURVE_ALERTS_PER_DAY = (1, 3, 10, 30, 100, 300, 1_000, 3_000, 10_000)


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1 / (1 + np.exp(-x))


FEATURE_DETECTORS = {
    # label-free: each reads only the event's causal features
    "edgebank": (["pair_seen_before"], lambda f: 1.0 - f["pair_seen_before"]),
    "host_pair_novelty": (["src_dst_seen_before"], lambda f: 1.0 - f["src_dst_seen_before"]),
    "user_source_novelty": (["user_src_seen_before"], lambda f: 1.0 - f["user_src_seen_before"]),
    "rarity": (
        ["pair_rarity", "is_new_pair", "destination_novelty", "user_new_dst_ratio_1h"],
        lambda f: np.minimum(
            1.0,
            0.5 * f["pair_rarity"] + 0.25 * f["is_new_pair"] + 0.15 * f["destination_novelty"]
            + 0.10 * np.minimum(f["user_new_dst_ratio_1h"], 1.0),
        ),
    ),
    "rule": (
        ["is_new_pair", "user_unique_dst_5m", "failures_before_success_15m", "src_host_unique_dst_1h", "destination_novelty"],
        lambda f: _sigmoid(
            1.5 * f["is_new_pair"] + 0.30 * np.minimum(f["user_unique_dst_5m"], 10)
            + 0.20 * np.minimum(f["failures_before_success_15m"], 10)
            + 0.25 * np.minimum(f["src_host_unique_dst_1h"], 10) + 1.0 * f["destination_novelty"] - 3.0
        ),
    ),
}


def _matrix(frame: pl.DataFrame, scaler: FeatureScaler, maps: dict[str, np.ndarray]) -> np.ndarray:
    x = scaler.transform({c: frame[c].to_numpy() for c in NUMERIC_FEATURES})
    codes = list(canonical_codes(frame, maps).T)
    cats = np.zeros((frame.height, CATEGORICAL_WIDTH), dtype=np.float32)
    rows = np.arange(frame.height)
    cats[rows, codes[0]] = 1
    cats[rows, 4 + codes[1]] = 1
    cats[rows, 9 + codes[2]] = 1
    cats[:, -1] = codes[3]
    return np.concatenate([x, cats], axis=1)


def fanout_flags(rules: pl.DataFrame, thresholds: tuple[int, int] | tuple[int, int, float] | None,
                 baseline: np.ndarray | None = None) -> np.ndarray:
    if thresholds is None:
        return np.zeros(rules.height, dtype=bool)
    accounts, novel = thresholds[0], thresholds[1]
    out = (
        (rules["fo_novel_now"].to_numpy() == 1)
        & (rules["fo_accounts"].to_numpy() >= accounts)
        & (rules["fo_novel"].to_numpy() >= novel)
    )
    if len(thresholds) == 3 and baseline is not None:
        out &= baseline <= thresholds[2]
    return out


def choose_fanout(rules_dir: Path, days: list[int], budget: float = 1e-6) -> tuple[tuple[int, int], list[dict]]:
    """The most sensitive fan-out thresholds whose flag rate on unlabelled days stays
    within the budget. Reads no label: attacks are ~1 in 10^6 of these days."""
    frames = [pl.read_parquet(rules_dir / f"day{d:02d}.parquet", columns=["fo_accounts", "fo_novel", "fo_novel_now"]) for d in days]
    rules = pl.concat(frames)
    n = rules.height
    table = []
    for accounts in (2, 3, 4, 5, 8, 12):
        for novel in (1, 2, 3, 5, 8, 12):
            rate = float(fanout_flags(rules, (accounts, novel)).sum()) / n
            table.append({"accounts": accounts, "novel_moves": novel, "flags_per_10k": 1e4 * rate})
    within = [row for row in table if row["flags_per_10k"] <= 1e4 * budget]
    best = max(within, key=lambda r: (r["flags_per_10k"], -r["accounts"], -r["novel_moves"]))
    for row in table:
        print(f"  fan-out accounts>={row['accounts']} novel>={row['novel_moves']}: {row['flags_per_10k']:.3f}/10k", flush=True)
    return (best["accounts"], best["novel_moves"]), table


# --------------------------------------------------------------------------- metrics
def _rank_stats(scores: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """For each positive: benign strictly above, benign tied, positives >= (for AP)."""
    benign = np.sort(scores[labels == 0])
    pos = scores[labels == 1]
    n_b = len(benign)
    above = n_b - np.searchsorted(benign, pos, "right")
    tied = np.searchsorted(benign, pos, "right") - np.searchsorted(benign, pos, "left")
    return pos, above, tied


def auc_ap(scores: np.ndarray, labels: np.ndarray, rng: np.random.Generator, boots: int = 1000) -> dict[str, float]:
    pos, above, tied = _rank_stats(scores, labels)
    n_b = int((labels == 0).sum())
    # ROC-AUC: P(score_pos > score_benign) + 0.5 P(tie)
    u = (n_b - above - tied + 0.5 * tied) / n_b
    order = np.argsort(-pos, kind="stable")

    def ap_of(idx: np.ndarray) -> float:
        p = pos[idx]
        b = above[idx] + tied[idx]  # benign at or above this positive's score
        srt = np.sort(p)
        tp = len(p) - np.searchsorted(srt, p, "left")  # positives with score >= p
        return float(np.mean(tp / (tp + b)))

    full = np.arange(len(pos))
    auc = float(u.mean())
    ap = ap_of(full)
    aucs, aps = [], []
    for _ in range(boots):
        idx = rng.integers(0, len(pos), len(pos))
        aucs.append(u[idx].mean())
        aps.append(ap_of(idx))
    _ = order
    return {
        "roc_auc": auc, "roc_auc_ci": [float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))],
        "ap": ap, "ap_ci": [float(np.percentile(aps, 2.5)), float(np.percentile(aps, 97.5))],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--train-days", default="0-7")
    ap.add_argument("--calib-day", type=int, default=7)
    ap.add_argument("--test-days", default="8-15")
    ap.add_argument("--model", action="append", default=[], help="name=scores_dir (anomaly = -logit)")
    ap.add_argument("--detectors", default="all")
    ap.add_argument("--benign-train", type=int, default=1_000_000)
    ap.add_argument("--rules-dir", type=Path, help="per-day chain / fan-out rule outputs (fullrate_rules.py)")
    ap.add_argument("--fanout", default="", help="fixed fan-out thresholds 'accounts,novel'; default: chosen on training days")
    ap.add_argument("--fuse", action="append", default=[], help="model name to fuse with the rules (label-free)")
    ap.add_argument("--fanout-budget", type=float, default=1e-6, help="flag-rate budget for choosing the fan-out rule")
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    maps = category_maps(args.id_maps)
    train_days = sorted(_days(args.train_days))
    test_days = sorted(_days(args.test_days))
    eval_days = [args.calib_day, *test_days]

    # labels, attacker host, day for every eval event (kept for all detectors)
    meta = {}
    for day in eval_days:
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet", columns=["event_id", "label", "src"])
        meta[day] = {"event_id": f["event_id"].to_numpy(), "label": f["label"].to_numpy(), "src": f["src"].to_numpy()}
    test_label = np.concatenate([meta[d]["label"] for d in test_days])
    test_src = np.concatenate([meta[d]["src"] for d in test_days])
    test_day = np.concatenate([np.full(len(meta[d]["label"]), d) for d in test_days])
    attack_hosts = sorted({hosts[s] for s in test_src[test_label == 1]})
    print(f"test events {len(test_label):,}, attacks {int(test_label.sum())}, hosts {attack_hosts}", flush=True)

    detectors: dict[str, object] = {}
    wanted = None if args.detectors == "all" else set(args.detectors.split(","))
    for name in FEATURE_DETECTORS:
        if wanted is None or name in wanted:
            detectors[name] = ("feature", name)
    for spec in args.model:
        name, path = spec.split("=", 1)
        detectors[name] = ("model", Path(path))
    for name in ("logistic", "gbdt", "isolation_forest"):
        if wanted is None or name in wanted:
            detectors[name] = ("learned", name)

    fanout = None
    if args.rules_dir:
        study = args.rules_dir.parent / "fanout_baseline.json"
        if args.fanout:
            fanout = tuple(float(v) if i == 2 else int(v) for i, v in enumerate(args.fanout.split(",")))
        elif study.is_file():
            chosen = json.loads(study.read_text())["chosen"]
            fanout = (int(chosen["accounts"]), int(chosen["novel_moves"]), float(chosen["baseline_limit"]))
            table = json.loads(study.read_text())["table"]
            print("fan-out (host-relative) chosen on unlabelled training days:", fanout, flush=True)
        else:
            fanout, table = choose_fanout(args.rules_dir, [d for d in train_days if d != args.calib_day], args.fanout_budget)
            print("fan-out thresholds chosen on unlabelled training days:", fanout, flush=True)
        detectors["chain_rule"] = ("rule", "chain")
        detectors["fanout_rule"] = ("rule", "fanout")
        detectors["chain_or_fanout"] = ("rule", "either")
        for name in args.fuse:
            detectors[f"{name}+rules"] = ("fused", name)

    fitted: dict[str, object] = {}
    scaler = None
    if any(kind == "learned" for kind, _ in detectors.values()):
        from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest
        from sklearn.linear_model import LogisticRegression

        parts = []
        for day in train_days:
            f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
            attacks = f.filter(pl.col("label") == 1)
            benign = f.filter(pl.col("label") == 0)
            take = rng.choice(benign.height, size=min(args.benign_train // len(train_days), benign.height), replace=False)
            parts.append(pl.concat([attacks, benign[np.sort(take)]]))
            del f, attacks, benign
            gc.collect()
        train = pl.concat(parts)
        scaler = FeatureScaler.fit({c: train.filter(pl.col("label") == 0)[c].to_numpy() for c in NUMERIC_FEATURES})
        xtr = _matrix(train, scaler, maps)
        ytr = train["label"].to_numpy()
        print(f"supervised training: {len(ytr):,} events, {int(ytr.sum())} attacks", flush=True)
        if "logistic" in detectors:
            fitted["logistic"] = LogisticRegression(class_weight="balanced", max_iter=2000).fit(xtr, ytr)
        if "gbdt" in detectors:
            w = np.where(ytr == 1, (ytr == 0).sum() / max(1, ytr.sum()), 1.0)
            fitted["gbdt"] = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, random_state=args.seed).fit(
                xtr, ytr, sample_weight=w
            )
        if "isolation_forest" in detectors:
            benign_idx = np.flatnonzero(ytr == 0)
            fitted["isolation_forest"] = IsolationForest(
                n_estimators=100, random_state=args.seed, n_jobs=-1
            ).fit(xtr[rng.choice(benign_idx, size=min(200_000, len(benign_idx)), replace=False)])
        import joblib

        args.out.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"models": fitted, "scaler": scaler}, args.out.with_name("supervised.joblib"))
        del train, xtr, ytr, parts
        gc.collect()

    def day_scores(name: str, day: int) -> np.ndarray:
        kind, what = detectors[name]  # type: ignore[misc]
        if kind == "feature":
            cols, fn = FEATURE_DETECTORS[what]  # type: ignore[index]
            f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet", columns=cols)
            return fn({c: f[c].to_numpy().astype(np.float64) for c in cols}).astype(np.float32)
        if kind == "model":
            s = pl.read_parquet(Path(what) / f"day{day:02d}.parquet")  # type: ignore[arg-type]
            assert (s["event_id"].to_numpy() == meta[day]["event_id"]).all()
            return (-s["logit"].to_numpy()).astype(np.float32)
        if kind == "rule":
            return rule_flags(day, what).astype(np.float32)  # type: ignore[arg-type]
        if kind == "fused":
            anomaly = day_scores(what, day)  # type: ignore[arg-type]
            calib_sorted = calibration_sorted(what)  # type: ignore[arg-type]
            percentile = np.searchsorted(calib_sorted, anomaly, "right") / len(calib_sorted)
            return (percentile + rule_flags(day, "either")).astype(np.float32)
        model = fitted[what]  # type: ignore[index]
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        out = np.empty(f.height, dtype=np.float32)
        for lo in range(0, f.height, SLICE):
            x = _matrix(f[lo: lo + SLICE], scaler, maps)  # type: ignore[arg-type]
            if what == "isolation_forest":
                out[lo: lo + len(x)] = -model.score_samples(x)  # type: ignore[attr-defined]
            else:
                out[lo: lo + len(x)] = model.predict_proba(x)[:, 1]  # type: ignore[attr-defined]
        return out

    def rule_flags(day: int, which: str) -> np.ndarray:
        r = pl.read_parquet(args.rules_dir / f"day{day:02d}.parquet")
        assert (r["event_id"].to_numpy() == meta[day]["event_id"]).all() if day in meta else True
        chain = r["chain_hop"].to_numpy().astype(bool)
        base_file = args.rules_dir.parent / "fanout_baseline" / f"day{day:02d}.parquet"
        base = pl.read_parquet(base_file)["fo_baseline"].to_numpy() if base_file.is_file() else None
        fan = fanout_flags(r, fanout, base)
        return {"chain": chain, "fanout": fan, "either": chain | fan}[which]

    calib_cache: dict[str, np.ndarray] = {}

    def calibration_sorted(model_name: str) -> np.ndarray:
        if model_name not in calib_cache:
            calib_cache[model_name] = np.sort(day_scores(model_name, args.calib_day))
        return calib_cache[model_name]

    results: dict[str, object] = {
        "protocol": {
            "train_days": train_days, "calibration_day": args.calib_day, "test_days": test_days,
            "test_events": int(len(test_label)), "test_attacks": int(test_label.sum()),
            "budgets": list(BUDGETS),
        },
        "detectors": {},
    }
    if fanout is not None:
        results["protocol"]["fanout_thresholds"] = {  # type: ignore[index]
            "accounts": fanout[0], "novel_moves": fanout[1], "baseline_limit": fanout[2] if len(fanout) == 3 else None}
        if not args.fanout:
            results["protocol"]["fanout_selection"] = table  # type: ignore[index]
    host_of_attack = np.array([hosts[s] for s in test_src[test_label == 1]])
    test_time = np.concatenate([
        pl.read_parquet(args.days_dir / f"day{d:02d}.parquet", columns=["timestamp"])["timestamp"].to_numpy()
        for d in test_days
    ])
    attack_time = test_time[test_label == 1]
    attack_day = test_day[test_label == 1]
    del test_time
    campaign_index: dict[tuple[str, int], np.ndarray] = {}
    for h in attack_hosts:
        for d_ in test_days:
            idx = np.flatnonzero((host_of_attack == h) & (attack_day == d_))
            if len(idx):
                campaign_index[(h, int(d_))] = idx[np.argsort(attack_time[idx], kind="stable")]
    results["protocol"]["attack_hosts"] = {h: int((host_of_attack == h).sum()) for h in attack_hosts}  # type: ignore[index]
    for name in detectors:
        started = time.perf_counter()
        calib = day_scores(name, args.calib_day)
        test = np.concatenate([day_scores(name, d) for d in test_days])
        metrics = auc_ap(test, test_label, rng)
        attack_scores = test[test_label == 1]
        benign_scores = test[test_label == 0]
        ops = {}
        for alpha in BUDGETS:
            tau = float(np.quantile(calib, 1 - alpha, method="higher"))
            flagged_benign = int((benign_scores > tau).sum())
            hit = attack_scores > tau
            per_host = {h: float(hit[host_of_attack == h].mean()) for h in attack_hosts}
            per_day = {int(d): int(((test > tau) & (test_day == d)).sum()) for d in test_days}
            # campaign view: each attacker host on each day is one campaign;
            # it is detected when any of its events alerts, and the latency is
            # the number of its events before the first alert
            campaigns = {}
            for (h, d_), idx in campaign_index.items():
                flags = hit[idx]
                first = int(np.argmax(flags)) if flags.any() else None
                campaigns[f"{h}/day{d_}"] = {
                    "events": int(len(idx)),
                    "detected": bool(flags.any()),
                    "first_alert_event": first,
                    "minutes_to_first_alert": (
                        round((attack_time[idx][first] - attack_time[idx][0]) / 60, 1) if first is not None else None
                    ),
                }
            ops[str(alpha)] = {
                "threshold": tau,
                "benign_flags_per_10k": 1e4 * flagged_benign / len(benign_scores),
                "recall": float(hit.mean()),
                "recall_by_host": per_host,
                "alerts_per_day": per_day,
                "campaigns_detected": int(sum(c["detected"] for c in campaigns.values())),
                "campaigns": campaigns,
            }
        metrics["operating_points"] = ops
        # ranking quality as an operating curve: recall when the threshold is set
        # so that k benign events a day are flagged (thresholds read on the test
        # days themselves -- a curve, not an operating point)
        benign_sorted = np.sort(benign_scores)[::-1]
        days_n = len(test_days)
        curve = []
        for per_day in CURVE_ALERTS_PER_DAY:
            k = int(per_day * days_n)
            if k >= len(benign_sorted):
                continue
            tau_k = float(benign_sorted[k]) if k > 0 else float(benign_sorted[0]) + 1e-9
            hit_k = attack_scores > tau_k
            curve.append({
                "benign_alerts_per_day": per_day,
                "recall": float(hit_k.mean()),
                "recall_by_host": {h: float(hit_k[host_of_attack == h].mean()) for h in attack_hosts},
            })
        metrics["curve"] = curve
        metrics["seconds"] = round(time.perf_counter() - started, 1)
        results["detectors"][name] = metrics  # type: ignore[index]
        line = f"{name:>22}: ROC {metrics['roc_auc']:.4f} AP {metrics['ap']:.4f} [{metrics['ap_ci'][0]:.4f}, {metrics['ap_ci'][1]:.4f}]"
        for alpha in (1e-5, 1e-4):
            op = ops[str(alpha)]
            line += (f" | @{alpha:g}: {sum(op['alerts_per_day'].values()) / len(test_days):.0f}/day recall {op['recall']:.3f} "
                     f"{({k: round(v, 2) for k, v in op['recall_by_host'].items()})}")
        print(line, flush=True)
        del calib, test, attack_scores, benign_scores
        gc.collect()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
