"""Recompute the scored cache's signal columns under the shipped chain rule.

The model probability in ``tests/fixtures/fusion_cache.parquet`` costs 23
minutes to rebuild and is not bit-reproducible across torch builds; the
signal columns cost 20 seconds and are exact. When the chain rule changes
(Finding 25 moved it from four hops of any kind in 300 s to four novel hops
in 1,800 s, and Finding 27 stopped failed logons counting as hops) this
recomputes ``novelty``, ``burst``, ``pivot`` and ``chain`` from the feature
records with the same ``SignalTracker`` the product runs, leaves ``tgn``
untouched, and reports what moved.

    python scripts/refresh_cache_signals.py --data data/processed/features_lanl_545k_split \\
        --cache tests/fixtures/fusion_cache.parquet
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from itertools import groupby
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np  # noqa: E402
import polars as pl  # noqa: E402

from graphsentinel.detection.policy import DEFAULT_CHAIN_RULE  # noqa: E402
from graphsentinel.features.causal import FeatureRecord  # noqa: E402

FIELDS = tuple(FeatureRecord.__dataclass_fields__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    args = parser.parse_args(argv)

    frame = pl.concat([pl.read_parquet(f) for f in sorted(args.data.glob("**/*.parquet"))]).sort(
        "timestamp", "event_id"
    )
    cache = pl.read_parquet(args.cache)
    if cache.height != frame.height or not (cache["event_id"] == frame["event_id"]).all():
        raise SystemExit("cache and features are not the same events in the same order")

    tracker = DEFAULT_CHAIN_RULE.tracker()
    novelty: list[float] = []
    burst: list[float] = []
    pivot: list[float] = []
    chain: list[bool] = []
    records = (FeatureRecord(**row) for row in frame.select(list(FIELDS)).iter_rows(named=True))
    for _timestamp, grouped in groupby(records, key=lambda r: r.timestamp):
        group = list(grouped)
        for record in group:
            signals, detected = tracker.signals(record)
            novelty.append(signals.novelty)
            burst.append(signals.burst)
            pivot.append(signals.pivot)
            chain.append(detected)
        tracker.observe_group(group)

    before = cache
    after = cache.with_columns(
        pl.Series("novelty", novelty),
        pl.Series("burst", burst),
        pl.Series("pivot", pivot),
        pl.Series("chain", chain),
    )
    for column in ("novelty", "burst", "pivot"):
        delta = np.abs(before[column].to_numpy() - after[column].to_numpy())
        print(f"{column}: rows changed {(delta > 1e-9).sum():,}, max abs delta {delta.max():.3g}")
    print(
        f"chain: flagged before {int(before['chain'].sum()):,}, "
        f"after {int(after['chain'].sum()):,} "
        f"(rule {DEFAULT_CHAIN_RULE.name})"
    )
    after.write_parquet(args.cache)
    digest = hashlib.sha256(args.cache.read_bytes()).hexdigest()[:16]
    print(f"wrote {args.cache} sha256 {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
