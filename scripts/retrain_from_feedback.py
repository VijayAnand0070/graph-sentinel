"""Retrain the estate's supervised detector from analyst decisions.

Input: the labels exported by ``GET /api/v1/feedback/labels?format=csv`` (one row
per decided alert, keyed by ``event_id``) and the estate's featurised days. The
confirmed and benign alerts are joined with their 30 causal features, a random
sample of the estate's other traffic is added as presumed benign (attacks are a
vanishing share of it), and a gradient-boosted model is fitted with the attacks
re-weighted. Identity-like features (time of day, how busy a host or account
normally is) are left out and the trees are regularised: in a leave-one-attacker-out
study on the training days this tripled the attack-days found for an attacker the
model had never seen (``loho_study.py``). The result is a bundle in the same format the evaluation scripts
read (``{"models": {"gbdt": ...}, "scaler": ...}``).

    python scripts/retrain_from_feedback.py --labels feedback.csv \\
        --days-dir artifacts/fullrate/days --id-maps artifacts/fullrate/id_maps_0_29 \\
        --days 0-15 --out artifacts/transfer/feedback/gbdt_feedback.joblib
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from fullrate_eval import _matrix  # noqa: E402
from loho_study import columns, make_models  # noqa: E402
from transfer_common import category_maps  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler  # noqa: E402


def build_training_set(
    labels: pl.DataFrame, days_dir: Path, days: list[int], background: int, rng: np.random.Generator
) -> pl.DataFrame:
    """Labelled alerts plus a background sample of presumed-benign traffic."""
    wanted = labels.select(["event_id", pl.col("label").cast(pl.Int8).alias("verdict")])
    parts = []
    for day in days:
        f = pl.read_parquet(days_dir / f"day{day:02d}.parquet")
        decided = f.join(wanted, on="event_id", how="inner")
        rest = f.join(wanted, on="event_id", how="anti")
        take = rng.choice(rest.height, size=min(background // len(days), rest.height), replace=False)
        sample = rest[np.sort(take)].with_columns(pl.lit(0, dtype=pl.Int8).alias("verdict"))
        parts.append(pl.concat([decided, sample], how="vertical_relaxed"))
        del f, decided, rest, sample
        gc.collect()
    return pl.concat(parts, how="vertical_relaxed")


FEATURE_SET = "no_identity"


def fit(train: pl.DataFrame, maps: dict[str, np.ndarray], seed: int) -> dict[str, object]:
    scaler = FeatureScaler.fit({c: train.filter(pl.col("verdict") == 0)[c].to_numpy() for c in NUMERIC_FEATURES})
    cols = columns(FEATURE_SET)
    x = _matrix(train, scaler, maps)[:, cols]
    y = train["verdict"].to_numpy()
    w = np.where(y == 1, (y == 0).sum() / max(1, y.sum()), 1.0)
    model = make_models(seed)["gbdt_reg"].fit(x, y, sample_weight=w)  # type: ignore[attr-defined]
    return {"models": {"gbdt": model}, "scaler": scaler, "columns": cols.tolist(), "feature_set": FEATURE_SET,
            "confirmed": int(y.sum()), "rows": int(len(y))}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--labels", type=Path, required=True, help="CSV exported from /api/v1/feedback/labels")
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--days", default="0-15")
    ap.add_argument("--background", type=int, default=1_000_000)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    labels = pl.read_csv(args.labels)
    if labels.filter(pl.col("label") == 1).height == 0:
        print("no confirmed alerts yet: nothing to learn from", file=sys.stderr)
        return 2
    rng = np.random.default_rng(args.seed)
    train = build_training_set(labels, args.days_dir, sorted(_days(args.days)), args.background, rng)
    bundle = fit(train, category_maps(args.id_maps), args.seed)
    import joblib

    args.out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, args.out)
    print(json.dumps({"out": str(args.out), "confirmed": bundle["confirmed"], "rows": bundle["rows"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
