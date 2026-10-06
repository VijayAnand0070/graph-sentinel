"""Score the full labelled corpus once and cache every fusion input per event.

This produces ``tests/fixtures/fusion_cache.parquet``, the scored cache behind
the evaluation report and the entity-contamination regression test. The
expensive part -- TGN forward passes over 543,615 events, chronologically, with
memory -- is invariant to anything downstream, so it is done once here and every
evaluation, calibration study and fusion experiment reads the result in seconds.

The replay is strictly chronological with score-before-update, exactly as
training and serving do it, and scoring goes through ``InferenceSession`` so the
checkpoint's stored feature normalisation is applied. Explicit signals are
advanced per event rather than per batch: the pivot window is 1,800 s while a
4,096-event batch spans roughly 10,000 s at this event rate, so a per-batch
update would hide every pivot inside a batch (recorded as a harness error in
``docs/DETECTION_RESEARCH_FINDINGS.md``).

Regenerate with::

    python scripts/build_scored_cache.py

The defaults point at the checkpoint and split the committed fixture was built
from. Change them only deliberately: the fixture pins Finding 14 (99.8% of test
PR-AUC from one host), and a cache scored by a different checkpoint will move
that number, at which point ``test_the_known_corpus_result_is_reproduced`` is
doing its job by failing.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from itertools import groupby
from pathlib import Path

import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from graphsentinel.detection.signals import SignalTracker  # noqa: E402
from graphsentinel.features.causal import MODEL_FEATURE_NAMES, FeatureRecord  # noqa: E402
from graphsentinel.models.serving import InferenceEvent, load_inference_session  # noqa: E402

#: The inputs the committed fixture was scored from.
DEFAULT_DATA = ROOT / "data/processed/features_lanl_545k_split"
DEFAULT_CHECKPOINT = ROOT / "artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt"
DEFAULT_REPORT = (
    ROOT / "artifacts/metrics/tgn_lanl_545k_split_v3_training-candidate-c6912ac36724.json"
)
DEFAULT_OUT = ROOT / "tests/fixtures/fusion_cache.parquet"

#: TGN scoring batch. Only the model forward pass is batched; the explicit
#: signals and the pivot window advance per event regardless.
BATCH = 4096

FIELDS = tuple(FeatureRecord.__dataclass_fields__)


def build(data: Path, checkpoint: Path, report: Path, out: Path, device: str) -> pl.DataFrame:
    split = json.loads(report.read_text(encoding="utf-8"))["split"]
    train_end = split["train_end_index"]
    validation_end = split["validation_end_index"]

    session = load_inference_session(checkpoint, device=device)
    print(f"checkpoint {session.provenance.model_version}", flush=True)

    frame = pl.concat([pl.read_parquet(f) for f in sorted(data.glob("**/*.parquet"))]).sort(
        "timestamp", "event_id"
    )
    print(f"loaded {frame.height:,} events", flush=True)

    tracker = SignalTracker()
    rows: list[dict] = []
    buffer: list[dict] = []
    started = time.perf_counter()

    def flush(chunk: list[dict]) -> None:
        """Score one batch, then advance both the TGN memory and the signal state.

        The signal state is advanced per timestamp group exactly as the live
        gateway advances it (``SignalTracker``), so the pivot channel here is
        the pivot channel the product computes -- not an approximation of it.
        """
        if not chunk:
            return
        events = [
            InferenceEvent(
                event_id=int(r["event_id"]),
                timestamp=int(r["timestamp"]),
                user_id=int(r["src_user_id"]),
                source_host_id=int(r["src_host_id"]),
                destination_host_id=int(r["dst_host_id"]),
                message=tuple(float(r[name]) for name in MODEL_FEATURE_NAMES),
            )
            for r in chunk
        ]
        preview = session.preview(events)
        session.commit(preview)

        scored = [
            (FeatureRecord(**{name: r[name] for name in FIELDS}), r, probability)
            for r, probability in zip(chunk, preview.probabilities, strict=True)
        ]
        for _timestamp, grouped in groupby(scored, key=lambda item: item[0].timestamp):
            group = list(grouped)
            for record, r, probability in group:
                signals, chain_detected = tracker.signals(record)
                rows.append(
                    {
                        "event_id": int(r["event_id"]),
                        "timestamp": int(r["timestamp"]),
                        "label": int(r["label_redteam"]),
                        "src_host_id": int(r["src_host_id"]),
                        "dst_host_id": int(r["dst_host_id"]),
                        "src_user_id": int(r["src_user_id"]),
                        "tgn": float(probability),
                        "novelty": float(signals.novelty),
                        "burst": float(signals.burst),
                        "pivot": float(signals.pivot),
                        "chain": bool(chain_detected),
                    }
                )
            tracker.observe_group(record for record, _r, _p in group)

    for row in frame.iter_rows(named=True):
        # A batch boundary never splits a timestamp group: the live gateway
        # scores a group against the state before it, in one request, and the
        # cache must see the same state for the same events.
        if len(buffer) >= BATCH and row["timestamp"] != buffer[-1]["timestamp"]:
            flush(buffer)
            buffer = []
            if len(rows) % 81920 < BATCH:
                rate = len(rows) / (time.perf_counter() - started)
                print(f"  scored {len(rows):,}  ({rate:,.0f}/s)", flush=True)
        buffer.append(row)
    flush(buffer)

    cache = pl.DataFrame(rows).with_row_index("idx")
    cache = cache.with_columns(
        pl.when(pl.col("idx") < train_end)
        .then(pl.lit("train"))
        .when(pl.col("idx") < validation_end)
        .then(pl.lit("validation"))
        .otherwise(pl.lit("test"))
        .alias("partition")
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    cache.write_parquet(out)

    print(f"\nwrote {out}  ({cache.height:,} rows, {time.perf_counter() - started:.0f}s)")
    for name in ("train", "validation", "test"):
        part = cache.filter(pl.col("partition") == name)
        print(f"  {name:<11} {part.height:>8,} events  {int(part['label'].sum()):>5} attacks")
    return cache


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument(
        "--report",
        type=Path,
        default=DEFAULT_REPORT,
        help="training report carrying the split indices",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args(argv)

    for label, path in (
        ("data", args.data),
        ("checkpoint", args.checkpoint),
        ("report", args.report),
    ):
        if not path.exists():
            parser.error(f"{label} not found: {path}")

    build(args.data, args.checkpoint, args.report, args.out, args.device)
    return 0


if __name__ == "__main__":
    sys.exit(main())
