"""E1: how much does stride sampling inflate lateral-movement results?

The corpora behind the first model kept every red-team event and one benign
event in N (N = 448 or 512) and computed the features on that thinned stream.
This rebuilds such a corpus from the full-rate stream -- same events kept, same
rule -- and featurises the kept events twice: on the thinned stream, as the old
pipeline did, and against the complete history, as a deployment sees them. The
kept events, their labels and the models are identical; only the features
differ. Then:

  (a) sampled features, sampled prevalence      -- the protocol behind 0.956
  (b) the (a) model on the *same events* with full-rate features
  (c) trained and tested on full-rate features of the same events
  (full) the main evaluation: every event, full-rate features (fullrate_eval.py)

    python scripts/sampling_artefact.py --days-dir artifacts/fullrate/days --stride 448 \\
        --out artifacts/transfer/sampling_artefact.json
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
from fullrate_eval import FEATURE_DETECTORS, _matrix, auc_ap  # noqa: E402
from transfer_common import category_maps  # noqa: E402

from graphsentinel.features.vectorized import VectorizedFeatureEngine  # noqa: E402
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402

BASE = ["event_id", "timestamp", "user", "src", "dst", "auth_id", "logon_id", "orient_id", "success", "label"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--days", default="0-15")
    ap.add_argument("--train-days", default="0-7")
    ap.add_argument("--test-days", default="8-15")
    ap.add_argument("--stride", type=int, default=448)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    maps = category_maps(args.id_maps)
    engine = VectorizedFeatureEngine()
    position = 0
    kept_full: list[pl.DataFrame] = []
    kept_sampled: list[pl.DataFrame] = []
    for day in sorted(_days(args.days)):
        full = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        n = full.height
        pos = np.arange(position, position + n)
        position += n
        keep = (full["label"].to_numpy() == 1) | (pos % args.stride == 0)
        k = full.filter(pl.Series(keep))
        del full
        f = engine.chunk(
            {"t": k["timestamp"].to_numpy(), "user": k["user"].to_numpy(), "src": k["src"].to_numpy(),
             "dst": k["dst"].to_numpy(), "logon": k["logon_id"].to_numpy(), "success": k["success"].to_numpy()}
        )
        sampled = k.select(BASE).with_columns([pl.Series(c, f[c].astype(np.float32)) for c in NUMERIC_FEATURES])
        sampled = sampled.with_columns(pl.lit(day).alias("day"))
        kept_full.append(k.with_columns(pl.lit(day).alias("day")))
        kept_sampled.append(sampled)
        print(f"day {day:02d}: kept {k.height:,} of {n:,}", flush=True)
    full_k = pl.concat(kept_full)
    samp_k = pl.concat(kept_sampled)
    assert (full_k["event_id"] == samp_k["event_id"]).all()
    train_days, test_days = sorted(_days(args.train_days)), sorted(_days(args.test_days))
    tr = full_k["day"].is_in(train_days).to_numpy()
    te = full_k["day"].is_in(test_days).to_numpy()
    y = full_k["label"].to_numpy()

    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression

    def fit(frame: pl.DataFrame, name: str):
        scaler = FeatureScaler.fit({c: frame.filter(pl.col("label") == 0)[c].to_numpy() for c in NUMERIC_FEATURES})
        x = _matrix(frame, scaler, maps)
        yy = frame["label"].to_numpy()
        if name == "logistic":
            model = LogisticRegression(class_weight="balanced", max_iter=2000).fit(x, yy)
        else:
            w = np.where(yy == 1, (yy == 0).sum() / max(1, yy.sum()), 1.0)
            model = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05, random_state=args.seed).fit(x, yy, sample_weight=w)
        return model, scaler

    def score(model, scaler, frame):
        return model.predict_proba(_matrix(frame, scaler, maps))[:, 1]

    out: dict[str, object] = {
        "stride": args.stride,
        "kept_events": int(full_k.height),
        "train_attacks": int(y[tr].sum()),
        "test_attacks": int(y[te].sum()),
        "test_benign_kept": int((y[te] == 0).sum()),
        "results": {},
    }
    test_s, test_f = samp_k.filter(pl.Series(te)), full_k.filter(pl.Series(te))
    yt = test_s["label"].to_numpy()
    for name in ("logistic", "gbdt"):
        m_s, sc_s = fit(samp_k.filter(pl.Series(tr)), name)
        m_f, sc_f = fit(full_k.filter(pl.Series(tr)), name)
        out["results"][name] = {  # type: ignore[index]
            "a_sampled_features": auc_ap(score(m_s, sc_s, test_s), yt, rng),
            "b_sampled_model_on_fullrate_features": auc_ap(score(m_s, sc_s, test_f), yt, rng),
            "c_fullrate_features": auc_ap(score(m_f, sc_f, test_f), yt, rng),
        }
        print(name, json.dumps({k: round(v["ap"], 4) for k, v in out["results"][name].items()}), flush=True)  # type: ignore[index]
    for name, (cols, fn) in FEATURE_DETECTORS.items():
        a = fn({c: test_s[c].to_numpy().astype(np.float64) for c in cols})
        c = fn({c: test_f[c].to_numpy().astype(np.float64) for c in cols})
        out["results"][name] = {"a_sampled_features": auc_ap(a, yt, rng), "c_fullrate_features": auc_ap(c, yt, rng)}  # type: ignore[index]
        print(name, json.dumps({k: round(v["ap"], 4) for k, v in out["results"][name].items()}), flush=True)  # type: ignore[index]
    # which features does sampling distort most? mean of attack vs benign, both ways
    shift = {}
    for c in NUMERIC_FEATURES:
        shift[c] = {
            "sampled_attack": float(test_s.filter(pl.col("label") == 1)[c].mean()),
            "sampled_benign": float(test_s.filter(pl.col("label") == 0)[c].mean()),
            "fullrate_attack": float(test_f.filter(pl.col("label") == 1)[c].mean()),
            "fullrate_benign": float(test_f.filter(pl.col("label") == 0)[c].mean()),
        }
    out["feature_means"] = shift
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
