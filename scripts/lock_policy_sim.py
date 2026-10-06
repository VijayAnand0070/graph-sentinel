"""Which immediate-lock rule locks attackers without locking ordinary users?

Every event of the window is scored with the served combination
mean(tgn, rarity, isolation forest) (percentiles against the calibration day,
no labels). Lock rules are replayed in time order with the product's limits --
one lock per account while it holds (two hours), at most 20 locks in any
sliding hour:

* ``gate@a``: lock when the score clears the action threshold at budget a;
* ``repeat@a``: as ``gate@a``, but only if the same account already raised an
  alert (score above the alert threshold, budget 1e-4) in the previous hour;
* ``repeat2@a``: the same with two earlier alerts;
* ``hostrepeat@a``: as ``repeat@a``, counting earlier alerts from the same source host
  (an attacker on one beachhead often rotates accounts).

Reported per rule: ordinary accounts locked per day, attack events locked and
attack campaign-days with at least one lock.

    python scripts/lock_policy_sim.py --days-dir artifacts/fullrate/days --tgn artifacts/transfer/scores_s1729 \\
        --supervised artifacts/transfer/supervised.joblib --calib-day 7 --test-days 8-15 \\
        --out artifacts/transfer/improve/locks_dev.json
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
from collections import deque
from pathlib import Path

import numpy as np
import polars as pl

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_build import _days  # noqa: E402
from fullrate_eval import FEATURE_DETECTORS, SLICE, _matrix  # noqa: E402
from improve_eval import log  # noqa: E402
from transfer_common import category_maps  # noqa: E402

ALERT_BUDGET = 1e-4
ACTION_BUDGETS = (1e-6, 3e-6, 1e-5, 3e-5)
HOLD, PER_HOUR, WINDOW = 7_200, 20, 3_600


def simulate(ts: np.ndarray, users: np.ndarray, labels: np.ndarray, src: np.ndarray, score: np.ndarray,
             tau_alert: float, tau_action: float, need_prior: int, by_host: bool = False) -> dict[str, object]:
    """Replay one day; prior alerts are counted per account over the previous hour."""
    alert_idx = np.flatnonzero(score > tau_alert)
    alert_idx = alert_idx[np.argsort(ts[alert_idx], kind="stable")]
    recent_alerts: dict[int, deque[int]] = {}
    held: dict[int, int] = {}
    locks: deque[int] = deque()
    benign_accounts: set[int] = set()
    benign = attack = 0
    attack_hosts: set[int] = set()
    for i in alert_idx:
        t, u = int(ts[i]), int(users[i])
        q = recent_alerts.setdefault(int(src[i]) if by_host else u, deque())
        while q and q[0] <= t - WINDOW:
            q.popleft()
        prior = len(q)
        q.append(t)
        if score[i] <= tau_action or prior < need_prior:
            continue
        if held.get(u, -1) > t:
            continue
        while locks and locks[0] <= t - 3_600:
            locks.popleft()
        if len(locks) >= PER_HOUR:
            continue
        locks.append(t)
        held[u] = t + HOLD
        if labels[i] == 1:
            attack += 1
            attack_hosts.add(int(src[i]))
        else:
            benign += 1
            benign_accounts.add(u)
    return {"benign_locks": benign, "benign_accounts": len(benign_accounts), "attack_locks": attack,
            "attack_hosts_locked": sorted(attack_hosts)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--days-dir", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, default=Path("artifacts/fullrate/id_maps_0_29"))
    ap.add_argument("--tgn", type=Path, required=True)
    ap.add_argument("--supervised", type=Path, required=True)
    ap.add_argument("--calib-day", type=int, default=7)
    ap.add_argument("--test-days", default="8-15")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    import joblib

    bundle = joblib.load(args.supervised)
    forest, scaler = bundle["models"]["isolation_forest"], bundle["scaler"]
    maps = category_maps(args.id_maps)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    cols, rarity_fn = FEATURE_DETECTORS["rarity"]

    def raw(day: int) -> tuple[dict[str, np.ndarray], pl.DataFrame]:
        f = pl.read_parquet(args.days_dir / f"day{day:02d}.parquet")
        s = pl.read_parquet(args.tgn / f"day{day:02d}.parquet")
        assert (s["event_id"].to_numpy() == f["event_id"].to_numpy()).all()
        out = {"tgn": (-s["logit"].to_numpy()).astype(np.float32),
               "rarity": rarity_fn({c: f[c].to_numpy().astype(np.float64) for c in cols}).astype(np.float32),
               "iforest": np.empty(f.height, dtype=np.float32)}
        for lo in range(0, f.height, SLICE):
            x = _matrix(f[lo: lo + SLICE], scaler, maps)
            out["iforest"][lo: lo + len(x)] = -forest.score_samples(x)
            del x
        meta = f.select(["label", "src", "user", "timestamp"])
        del f, s
        gc.collect()
        return out, meta

    raw_c, _ = raw(args.calib_day)
    ref = {k: np.sort(v) for k, v in raw_c.items()}

    def combined(r: dict[str, np.ndarray]) -> np.ndarray:
        return np.mean([np.searchsorted(ref[k], v, "right") / len(ref[k]) for k, v in r.items()], axis=0)

    calib = combined(raw_c)
    tau_alert = float(np.quantile(calib, 1 - ALERT_BUDGET, method="higher"))
    tau_action = {a: float(np.quantile(calib, 1 - a, method="higher")) for a in ACTION_BUDGETS}
    del raw_c, calib
    gc.collect()
    rules = {f"{kind}@{a:g}": (a, need, by_host) for a in ACTION_BUDGETS for kind, need, by_host in
             (("gate", 0, False), ("repeat", 1, False), ("repeat2", 2, False), ("hostrepeat", 1, True))}
    rows: dict[str, list[dict[str, object]]] = {k: [] for k in rules}
    campaigns: set[tuple[int, int]] = set()
    for day in sorted(_days(args.test_days)):
        t0 = time.perf_counter()
        r, meta = raw(day)
        score = combined(r)
        del r
        labels, src = meta["label"].to_numpy(), meta["src"].to_numpy()
        users, ts = meta["user"].to_numpy(), meta["timestamp"].to_numpy()
        campaigns |= {(int(h), day) for h in np.unique(src[labels == 1])}
        for name, (a, need, by_host) in rules.items():
            row = simulate(ts, users, labels, src, score, tau_alert, tau_action[a], need, by_host)
            row["day"] = day
            rows[name].append(row)
        log(f"day {day}: {len(labels):,} events {time.perf_counter() - t0:.0f}s")
        del meta, score, labels, src, users, ts
        gc.collect()
    summary = {}
    for name, per in rows.items():
        locked_campaigns = {(h, r["day"]) for r in per for h in r["attack_hosts_locked"]}  # type: ignore[union-attr]
        summary[name] = {
            "benign_locks_per_day_mean": float(np.mean([r["benign_locks"] for r in per])),
            "benign_locks_per_day_max": int(max(r["benign_locks"] for r in per)),
            "attack_locks": int(sum(r["attack_locks"] for r in per)),
            "campaign_days_locked": len(locked_campaigns & campaigns),
            "campaign_days": len(campaigns),
            "locked": sorted(f"{hosts[h]}/day{d}" for h, d in locked_campaigns),
            "days": per,
        }
        s = summary[name]
        log(f"{name:>14}: innocent locks/day {s['benign_locks_per_day_mean']:.1f} (max {s['benign_locks_per_day_max']})"
            f" | attack locks {s['attack_locks']} | campaign-days locked {s['campaign_days_locked']}/{len(campaigns)}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"alert_budget": ALERT_BUDGET, "summary": summary}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
