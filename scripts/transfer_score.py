"""Score every real event of the given days with a trained transfer TGN.

Memory is warmed from day 0 with every event, then every event of the scored
days is scored against memory from before its time bucket, then folded in --
exactly the deployed path's order. No label is read.

    python scripts/transfer_score.py --checkpoint artifacts/transfer/tgn_s1729.pt \\
        --days-dir artifacts/fullrate/days --id-maps artifacts/fullrate/id_maps \\
        --score-days 7-15 --out artifacts/transfer/scores_s1729
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
import pyarrow.parquet as pq
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from transfer_common import category_maps, load_stream, node_offsets, one_hot, scaled  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler, MemoryState, TransferTGN  # noqa: E402


def load_model(path: Path, device: torch.device) -> tuple[TransferTGN, FeatureScaler, dict]:
    ckpt = torch.load(path, map_location=device, weights_only=True)
    model = TransferTGN(**ckpt["configuration"]).to(device)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    return model, FeatureScaler.from_dict(ckpt["scaler"]), ckpt


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--checkpoint", type=Path, required=True)
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--score-days", default="7-15")
    ap.add_argument("--zero-memory", action="store_true", help="ablation: score with node memory read as zeros")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    device = torch.device(args.device)
    model, scaler, ckpt = load_model(args.checkpoint, device)
    if args.zero_memory:
        model.use_memory = False
    # node indexing is the scorer's choice (memory is state, not parameters):
    # take it from the id maps actually used, which may extend the training ones
    users, hosts = node_offsets(args.id_maps)
    maps = category_maps(args.id_maps)
    bucket = int(ckpt["bucket_seconds"])
    memory_dim = int(ckpt["configuration"]["memory_dim"])
    score_days = sorted(_days(args.score_days))
    args.out.mkdir(parents=True, exist_ok=True)
    state = MemoryState.initial(users + hosts, memory_dim, device)
    for day in range(0, max(score_days) + 1):
        started = time.perf_counter()
        stream = load_stream(args.days_dir, day, users, device, bucket, maps)
        scoring = day in score_days
        if scoring:
            # read, scale and upload the features a slice at a time: a full-rate
            # day is ~9 M rows, and holding it in float64 on the host at once is
            # what exhausts a 16 GB machine
            x = torch.empty((len(stream), len(NUMERIC_FEATURES)), device=device)
            parquet = pq.ParquetFile(args.days_dir / f"day{day:02d}.parquet")
            row = 0
            for batch in parquet.iter_batches(batch_size=1_000_000, columns=list(NUMERIC_FEATURES)):
                frame = pl.from_arrow(batch)
                x[row: row + frame.height] = torch.from_numpy(scaled(frame, scaler)).to(device)
                row += frame.height
                del frame
            assert row == len(stream)
            logits = torch.empty(len(stream), device=device)
        edges = stream.bucket_edges
        with torch.no_grad():
            for b in range(len(edges) - 1):
                i0, i1 = int(edges[b]), int(edges[b + 1])
                cats = one_hot(stream.codes[i0:i1])
                if scoring:
                    logits[i0:i1] = model.score(
                        state, stream.user[i0:i1], stream.src[i0:i1], stream.dst[i0:i1], stream.t[i0:i1],
                        x[i0:i1], cats,
                    )
                state = model.update(
                    state, stream.user[i0:i1], stream.src[i0:i1], stream.dst[i0:i1], stream.t[i0:i1], cats
                )
        if scoring:
            pl.DataFrame({"event_id": stream.event_id, "logit": logits.cpu().numpy()}).write_parquet(
                args.out / f"day{day:02d}.parquet"
            )
            del x, logits
        print(f"day {day:02d}: {len(stream):,} events {'scored' if scoring else 'warmed'} "
              f"in {time.perf_counter() - started:.0f}s", flush=True)
        del stream
        torch.cuda.empty_cache()
    return 0


if __name__ == "__main__":
    sys.exit(main())
