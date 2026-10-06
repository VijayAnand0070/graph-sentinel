"""Train the label-free transfer TGN on full-rate days. No attack label is read.

The model learns to tell real authentications from counterfactual ones (same
account, time and event type; another destination or source host). Memory is
updated with *every* event of every day, in time buckets, score-before-update;
the loss is taken on a sample of real events and their negatives.

    python scripts/transfer_train.py --days-dir artifacts/fullrate/days \\
        --id-maps artifacts/fullrate/id_maps --train-days 0-6 --val-day 7 \\
        --epochs 4 --seed 1729 --out artifacts/transfer/tgn_s1729.pt
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
import torch
from sklearn.metrics import roc_auc_score
from torch import nn

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from transfer_common import category_maps, fit_scaler, load_stream, node_offsets, one_hot, scaled  # noqa: E402

from graphsentinel.models.transfer import NUMERIC_FEATURES, MemoryState, TransferTGN  # noqa: E402


class DayMaterial:
    """The scored examples of one day: sampled real events and their negatives,
    each placed at its stream index so buckets can slice them."""

    def __init__(self, days_dir: Path, day: int, stream, scaler, users: int, device: torch.device, kinds: set[int] | None):
        neg = pl.read_parquet(days_dir / f"neg{day:02d}.parquet")
        if kinds is not None:
            neg = neg.filter(pl.col("kind").is_in(list(kinds)))
        pos_ids = np.unique(neg["pos_event_id"].to_numpy())
        pos = (
            pl.read_parquet(days_dir / f"day{day:02d}.parquet", columns=["event_id", *NUMERIC_FEATURES])
            .filter(pl.col("event_id").is_in(pl.Series(pos_ids)))
            .sort("event_id")
        )
        pos_index = np.searchsorted(stream.event_id, pos["event_id"].to_numpy())
        assert (stream.event_id[pos_index] == pos["event_id"].to_numpy()).all()
        neg_pos_index = np.searchsorted(stream.event_id, neg["pos_event_id"].to_numpy())
        order = np.argsort(neg_pos_index, kind="stable")
        neg = neg[order]
        neg_pos_index = neg_pos_index[order]
        self.pos_index = pos_index
        self.neg_pos_index = neg_pos_index
        self.pos_x = torch.from_numpy(scaled(pos, scaler)).to(device)
        self.neg_x = torch.from_numpy(scaled(neg, scaler)).to(device)
        self.neg_user = torch.from_numpy(neg["user"].to_numpy().astype(np.int64)).to(device)
        self.neg_src = torch.from_numpy(neg["src"].to_numpy().astype(np.int64) + users).to(device)
        self.neg_dst = torch.from_numpy(neg["dst"].to_numpy().astype(np.int64) + users).to(device)
        self.neg_kind = neg["kind"].to_numpy()
        self.pos_index_t = torch.from_numpy(pos_index).to(device)
        self.neg_pos_index_t = torch.from_numpy(neg_pos_index).to(device)

    def ranges(self, i0: int, i1: int) -> tuple[slice, slice]:
        p = slice(*np.searchsorted(self.pos_index, [i0, i1]))
        n = slice(*np.searchsorted(self.neg_pos_index, [i0, i1]))
        return p, n


def scored_logits(model, state, stream, mat: DayMaterial, p: slice, n: slice):
    pi = mat.pos_index_t[p]
    logits_pos = model.score(
        state, stream.user[pi], stream.src[pi], stream.dst[pi], stream.t[pi], mat.pos_x[p], one_hot(stream.codes[pi])
    )
    ni = mat.neg_pos_index_t[n]
    logits_neg = model.score(
        state, mat.neg_user[n], mat.neg_src[n], mat.neg_dst[n], stream.t[ni], mat.neg_x[n], one_hot(stream.codes[ni])
    )
    return logits_pos, logits_neg


def run_day(model, state, stream, mat, *, train: bool, opt=None, tbptt: int = 8, pos_weight: float = 5.0):
    """Stream one day through the model; returns the final state and the scored logits."""
    loss_fn = nn.BCEWithLogitsLoss(reduction="sum")
    edges = stream.bucket_edges
    pending = None
    count = 0
    out_pos: list[np.ndarray] = []
    out_neg: list[np.ndarray] = []
    for b in range(len(edges) - 1):
        i0, i1 = int(edges[b]), int(edges[b + 1])
        p, n = mat.ranges(i0, i1) if mat is not None else (slice(0, 0), slice(0, 0))
        if p.stop > p.start or n.stop > n.start:
            lp, ln = scored_logits(model, state, stream, mat, p, n)
            if train:
                loss = pos_weight * loss_fn(lp, torch.ones_like(lp)) + loss_fn(ln, torch.zeros_like(ln))
                loss = loss / max(1, (p.stop - p.start))
                pending = loss if pending is None else pending + loss
            else:
                out_pos.append(lp.float().cpu().numpy())
                out_neg.append(ln.float().cpu().numpy())
        ctx = torch.enable_grad() if train else torch.no_grad()
        with ctx:
            state = model.update(
                state, stream.user[i0:i1], stream.src[i0:i1], stream.dst[i0:i1], stream.t[i0:i1],
                one_hot(stream.codes[i0:i1]),
            )
        count += 1
        if train and count % tbptt == 0:
            if pending is not None:
                opt.zero_grad(set_to_none=True)
                pending.backward()
                nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step()
                pending = None
            state = state.detach()
        elif not train:
            state = state.detach()
    if train and pending is not None:
        opt.zero_grad(set_to_none=True)
        pending.backward()
        nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
    state = state.detach()
    pos = np.concatenate(out_pos) if out_pos else np.empty(0)
    neg = np.concatenate(out_neg) if out_neg else np.empty(0)
    return state, pos, neg


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--train-days", default="0-6")
    ap.add_argument("--val-day", type=int, default=7)
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--memory-dim", type=int, default=64)
    ap.add_argument("--hidden", type=int, default=128)
    ap.add_argument("--bucket", type=int, default=60)
    ap.add_argument("--tbptt", type=int, default=8)
    ap.add_argument("--no-memory", action="store_true")
    ap.add_argument("--no-features", action="store_true")
    ap.add_argument("--kinds", default="", help="negative kinds to train on, e.g. 0,1 (default all)")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = torch.device(args.device)
    users, hosts = node_offsets(args.id_maps)
    maps = category_maps(args.id_maps)
    train_days = sorted(_days(args.train_days))
    kinds = {int(k) for k in args.kinds.split(",")} if args.kinds else None
    scaler = fit_scaler(args.days_dir, train_days, per_day=300_000, seed=args.seed)
    model = TransferTGN(
        memory_dim=args.memory_dim, hidden_dim=args.hidden,
        use_memory=not args.no_memory, use_features=not args.no_features,
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    history = []
    best = None
    args.out.parent.mkdir(parents=True, exist_ok=True)
    for epoch in range(1, args.epochs + 1):
        started = time.perf_counter()
        model.train()
        state = MemoryState.initial(users + hosts, args.memory_dim, device)
        for day in train_days:
            stream = load_stream(args.days_dir, day, users, device, args.bucket, maps)
            mat = DayMaterial(args.days_dir, day, stream, scaler, users, device, kinds)
            state, _p, _n = run_day(model, state, stream, mat, train=True, opt=opt, tbptt=args.tbptt)
            del stream, mat
            torch.cuda.empty_cache()
        model.eval()
        stream = load_stream(args.days_dir, args.val_day, users, device, args.bucket, maps)
        mat = DayMaterial(args.days_dir, args.val_day, stream, scaler, users, device, kinds)
        with torch.no_grad():
            state, lp, ln = run_day(model, state, stream, mat, train=False)
        y = np.concatenate([np.ones(len(lp)), np.zeros(len(ln))])
        s = np.concatenate([lp, ln])
        auc = float(roc_auc_score(y, s))
        per_kind = {}
        for k in np.unique(mat.neg_kind):
            sel = mat.neg_kind == k
            per_kind[int(k)] = float(roc_auc_score(np.r_[np.ones(len(lp)), np.zeros(int(sel.sum()))], np.r_[lp, ln[sel]]))
        elapsed = time.perf_counter() - started
        row = {"epoch": epoch, "val_auc": auc, "val_auc_by_kind": per_kind, "seconds": round(elapsed, 1)}
        history.append(row)
        print(json.dumps(row), flush=True)
        del stream, mat
        torch.cuda.empty_cache()
        if best is None or auc > best:
            best = auc
            torch.save(
                {
                    "model": "TransferTGN",
                    "configuration": model.configuration(),
                    "state_dict": model.state_dict(),
                    "scaler": scaler.to_dict(),
                    "users": users,
                    "hosts": hosts,
                    "bucket_seconds": args.bucket,
                    "train_days": train_days,
                    "val_day": args.val_day,
                    "seed": args.seed,
                    "epoch": epoch,
                    "val_auc": auc,
                    "labels_used": False,
                },
                args.out,
            )
    (args.out.with_suffix(".json")).write_text(json.dumps({"history": history, "best_val_auc": best}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
