"""Leave-one-attacker-host-out study on the training days: which supervised set-up
finds an attacker it has never seen?

The training days hold several attacking hosts. For each one, every event of
that host is removed from training, models are fitted on the rest, and the
held-out host's labelled events are ranked among *all* events of the days it
attacked. Feature sets differ in how much they can memorise a particular
attacker (time of day, how busy a host or account is) versus describe the
movement itself (novelty, fan-out, failures). Only the training days are used,
so the final window stays untouched for the chosen set-up.

    python scripts/loho_study.py --days-dir artifacts/fullrate/days --days 0-15 \\
        --out artifacts/transfer/improve/loho.json
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
from transfer_common import category_maps  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402

N_NUM = len(NUMERIC_FEATURES)


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)
IDENTITY_LIKE = {"hour_sin", "hour_cos", "user_historical_degree", "src_host_historical_degree",
                 "dst_historical_degree", "dst_inbound_users_1h", "user_auth_rate_5m"}
MOVEMENT = {"user_seen_before", "pair_seen_before", "is_new_pair", "pair_frequency_1h", "pair_rarity",
            "user_unique_dst_5m", "user_unique_dst_1h", "user_new_dst_ratio_1h", "src_host_unique_dst_1h",
            "destination_novelty", "user_src_seen_before", "src_dst_seen_before", "src_host_unique_users_1h",
            "failures_before_success_15m", "user_failure_rate_15m", "rare_logon_score"}


PROC_COLUMNS = ("dst_new_5m", "dst_new_30m", "src_new_1h", "user_new_1h")


def with_proc(frame: pl.DataFrame, proc_dir: Path | None, day: int) -> pl.DataFrame:
    """Append the day's process-novelty features (same row order as the day file)."""
    if proc_dir is None:
        return frame
    pf = pl.read_parquet(proc_dir / f"day{day:02d}.parquet")
    assert (pf["event_id"].to_numpy() == frame["event_id"].to_numpy()).all()
    return frame.hstack(pf.select(list(PROC_COLUMNS)))


def full_matrix(frame: pl.DataFrame, scaler: FeatureScaler, maps: dict[str, np.ndarray]) -> np.ndarray:
    """The 41 model columns, then log1p of the process features when present."""
    x = _matrix(frame, scaler, maps)
    if PROC_COLUMNS[0] in frame.columns:
        extra = np.log1p(np.stack([frame[c].to_numpy().astype(np.float32) for c in PROC_COLUMNS], axis=1))
        x = np.concatenate([x, extra], axis=1)
    return x


def columns(feature_set: str) -> np.ndarray:
    if feature_set.endswith("+proc"):
        base = columns(feature_set[: -len("+proc")])
        return np.concatenate([base, np.arange(N_NUM + 15, N_NUM + 15 + len(PROC_COLUMNS))])
    names = list(NUMERIC_FEATURES)
    if feature_set == "all":
        keep = names
    elif feature_set == "no_identity":
        keep = [n for n in names if n not in IDENTITY_LIKE]
    elif feature_set == "movement":
        keep = [n for n in names if n in MOVEMENT]
    else:
        raise ValueError(feature_set)
    num = [names.index(n) for n in keep]
    return np.array(num + list(range(N_NUM, N_NUM + 15)))  # categorical columns always kept


def make_models(seed: int) -> dict[str, object]:
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression

    return {
        "gbdt": HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, random_state=seed),
        "gbdt_reg": HistGradientBoostingClassifier(max_iter=200, learning_rate=0.05, max_depth=3,
                                                   min_samples_leaf=500, l2_regularization=1.0, random_state=seed),
        "logistic": LogisticRegression(class_weight="balanced", max_iter=2000),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, default=Path("artifacts/fullrate/id_maps_0_29"))
    ap.add_argument("--days", default="0-15")
    ap.add_argument("--feature-sets", default="all,no_identity,movement")
    ap.add_argument("--benign-train", type=int, default=1_000_000)
    ap.add_argument("--proc-dir", type=Path, default=None, help="process features (proc_features.py)")
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    days = sorted(_days(args.days))
    maps = category_maps(args.id_maps)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    feature_sets = args.feature_sets.split(",")

    # attack host-days and one shared benign sample per day (attacks are kept apart)
    attack_days: dict[int, list[int]] = {}
    attacks, benign = [], []
    for d in days:
        f = with_proc(pl.read_parquet(args.days_dir / f"day{d:02d}.parquet"), args.proc_dir, d)
        a = f.filter(pl.col("label") == 1)
        for h in a["src"].unique().to_list():
            attack_days.setdefault(int(h), []).append(d)
        b = f.filter(pl.col("label") == 0)
        take = rng.choice(b.height, size=min(args.benign_train // len(days), b.height), replace=False)
        attacks.append(a)
        benign.append(b[np.sort(take)])
        del f, a, b
        gc.collect()
    attacks_df = pl.concat(attacks)
    benign_df = pl.concat(benign)
    scaler = FeatureScaler.fit({c: benign_df[c].to_numpy() for c in NUMERIC_FEATURES})
    x_att, x_ben = full_matrix(attacks_df, scaler, maps), full_matrix(benign_df, scaler, maps)
    att_src, ben_src = attacks_df["src"].to_numpy(), benign_df["src"].to_numpy()
    log(f"attack hosts {[(hosts[h], len(v)) for h, v in attack_days.items()]}, "
        f"{len(x_att)} attacks, {len(x_ben):,} benign")

    fitted: dict[tuple[int, str, str], object] = {}
    for h in attack_days:
        keep_a, keep_b = att_src != h, ben_src != h
        if keep_a.sum() < 5:
            log(f"skip {hosts[h]}: only {int(keep_a.sum())} other attacks")
            continue
        for fs in feature_sets:
            cols = columns(fs)
            x = np.concatenate([x_att[keep_a][:, cols], x_ben[keep_b][:, cols]])
            y = np.concatenate([np.ones(int(keep_a.sum())), np.zeros(int(keep_b.sum()))])
            w = np.where(y == 1, (y == 0).sum() / y.sum(), 1.0)
            for name, model in make_models(args.seed).items():
                if name == "logistic":
                    model.fit(x, y)  # type: ignore[attr-defined]
                else:
                    model.fit(x, y, sample_weight=w)  # type: ignore[attr-defined]
                fitted[(h, fs, name)] = model
            del x, y, w
        log(f"fold without {hosts[h]}: {int(keep_a.sum())} training attacks")

    results: dict[str, dict[str, object]] = {}
    for d in sorted({d for v in attack_days.values() for d in v}):
        t0 = time.perf_counter()
        f = with_proc(pl.read_parquet(args.days_dir / f"day{d:02d}.parquet"), args.proc_dir, d)
        src, labels = f["src"].to_numpy(), f["label"].to_numpy()
        folds = [h for h, v in attack_days.items() if d in v and any(k[0] == h for k in fitted)]
        scores = {k: np.empty(f.height, dtype=np.float32) for k in fitted if k[0] in folds}
        for lo in range(0, f.height, SLICE):
            x = full_matrix(f[lo: lo + SLICE], scaler, maps)
            for (h, fs, name), model in fitted.items():
                if h in folds:
                    scores[(h, fs, name)][lo: lo + len(x)] = model.predict_proba(x[:, columns(fs)])[:, 1]  # type: ignore[attr-defined]
            del x
        for (h, fs, name), s in scores.items():
            mine = (src == h) & (labels == 1)
            best = float(s[mine].max())
            rank = int((s > best).sum()) + 1
            ap_rank = np.sort(s[mine])[::-1]
            above = np.array([(s > v).sum() + 1 for v in ap_rank])
            precision = np.arange(1, len(ap_rank) + 1) / above
            key = f"{fs}|{name}"
            results.setdefault(key, {})[f"{hosts[h]}/day{d}"] = {
                "best_rank": rank, "attacks": int(mine.sum()), "ap": float(precision.mean())}
        log(f"day {d}: folds {[hosts[h] for h in folds]} {time.perf_counter() - t0:.0f}s")
        del f, scores
        gc.collect()

    summary = {}
    for key, per in results.items():
        ranks = [v["best_rank"] for v in per.values()]
        summary[key] = {
            "host_days": len(ranks),
            "hd300": int(sum(r <= 300 for r in ranks)),
            "hd1000": int(sum(r <= 1000 for r in ranks)),
            "median_best_rank": float(np.median(ranks)),
            "mean_ap": float(np.mean([v["ap"] for v in per.values()])),
            "per_host_day": per,
        }
    ordered = dict(sorted(summary.items(), key=lambda kv: (kv[1]["hd300"], kv[1]["hd1000"], -kv[1]["median_best_rank"]),
                          reverse=True))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"days": days, "attack_days": {hosts[h]: v for h, v in attack_days.items()},
                                    "summary": ordered}, indent=2), encoding="utf-8")
    for key, s in ordered.items():
        log(f"{key:>22}: HD@300 {s['hd300']}/{s['host_days']} HD@1000 {s['hd1000']} "
            f"median rank {s['median_best_rank']:.0f} mean AP {s['mean_ap']:.2e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
