"""Cross-organisation test: LANL-trained detectors on the OTRF lab, with no labels from the lab.

The OTRF Security-Datasets lateral-movement recordings come from a different
organisation (a small Windows lab domain, ``theshire.local``), a different
logging pipeline (Windows Security JSON) and a different time (2020-2021). The
recordings are replayed as one chronological stream of the lab's
authentications, featurised with the same causal features against the lab's
own history, and scored by:

* the label-free transfer TGN trained on LANL, with node memory starting empty
  (a new estate) and features standardised either with LANL's statistics
  (``lanl-scaled``, no adaptation) or with the lab's own unlabelled events
  (``lab-scaled``, the label-free adaptation the product performs at onboarding);
* the LANL-trained supervised baselines (logistic regression, gradient-boosted
  trees) and the label-free feature baselines;
* the first GraphSentinel model, from the earlier run through the live API
  (``artifacts/otrf/otrf_events.json``).

Ground truth is the reviewed per-recording label in ``data/raw/otrf/ground_truth.json``.

    python scripts/otrf_transfer.py --model tgn=artifacts/transfer/tgn_s1729.pt \\
        --supervised artifacts/transfer/supervised.joblib --out artifacts/transfer/otrf.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from fullrate_eval import FEATURE_DETECTORS  # noqa: E402
from otrf_evaluate import Truth, is_attack, load_truth, read_recording  # noqa: E402
from transfer_score import load_model  # noqa: E402

from graphsentinel.features.canonical import (  # noqa: E402
    AUTH_CATEGORIES,
    CATEGORICAL_WIDTH,
    LOGON_CATEGORIES,
    ORIENTATION_CATEGORIES,
    canonical_auth,
    canonical_logon,
    canonical_orientation,
)
from graphsentinel.features.vectorized import VectorizedFeatureEngine  # noqa: E402
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler, MemoryState  # noqa: E402


def lab_stream(data: Path) -> dict[str, np.ndarray | list]:
    truths = load_truth(data / "ground_truth.json")
    rows = []
    for zip_path in sorted((data / "lateral_movement").glob("*.zip")):
        _fmt, events, _stats = read_recording(zip_path)
        truth = truths.get(zip_path.stem) or Truth(zip_path.stem, "excluded", "not in ground_truth.json")
        for e in events:
            rows.append((e.timestamp, zip_path.stem, e, truth.usable, is_attack(e, truth)))
    rows.sort(key=lambda r: r[0])
    users: dict[str, int] = {}
    hosts: dict[str, int] = {}
    logons: dict[str, int] = {}

    def uid(name: str) -> int:
        return users.setdefault(name, len(users))

    def hid(name: str) -> int:
        return hosts.setdefault(name, len(hosts))

    out = {
        "t": np.array([r[0] for r in rows], dtype=np.int64),
        "user": np.array([uid(r[2].user) for r in rows], dtype=np.int64),
        "src": np.array([hid(r[2].source_host) for r in rows], dtype=np.int64),
        "dst": np.array([hid(r[2].destination_host) for r in rows], dtype=np.int64),
        "logon": np.array([logons.setdefault(r[2].logon_type, len(logons)) for r in rows], dtype=np.int64),
        "success": np.array([int(bool(r[2].success)) for r in rows], dtype=np.int64),
        "codes": np.array(
            [
                (
                    AUTH_CATEGORIES.index(canonical_auth(r[2].auth_type)),
                    LOGON_CATEGORIES.index(canonical_logon(r[2].logon_type)),
                    ORIENTATION_CATEGORIES.index(canonical_orientation(r[2].orientation)),
                    int(bool(r[2].success)),
                )
                for r in rows
            ],
            dtype=np.int64,
        ),
        "recording": [r[1] for r in rows],
        "usable": np.array([r[3] for r in rows], dtype=bool),
        "attack": np.array([r[4] for r in rows], dtype=bool),
        "n_users": len(users),
        "n_hosts": len(hosts),
    }
    return out


def features(stream: dict) -> dict[str, np.ndarray]:
    engine = VectorizedFeatureEngine()
    return engine.chunk({k: stream[k] for k in ("t", "user", "src", "dst", "logon", "success")})


def one_hot_np(codes: np.ndarray) -> np.ndarray:
    n = len(codes)
    out = np.zeros((n, CATEGORICAL_WIDTH), dtype=np.float32)
    r = np.arange(n)
    out[r, codes[:, 0]] = 1
    out[r, len(AUTH_CATEGORIES) + codes[:, 1]] = 1
    out[r, len(AUTH_CATEGORIES) + len(LOGON_CATEGORIES) + codes[:, 2]] = 1
    out[:, -1] = codes[:, 3]
    return out


def tgn_scores(ckpt_path: Path, stream: dict, feats: dict, scaler: FeatureScaler | None, device) -> np.ndarray:
    model, lanl_scaler, ckpt = load_model(ckpt_path, device)
    scaler = scaler or lanl_scaler
    users = int(stream["n_users"])
    n_nodes = users + int(stream["n_hosts"])
    state = MemoryState.initial(n_nodes, int(ckpt["configuration"]["memory_dim"]), device)
    x = torch.from_numpy(scaler.transform({c: feats[c] for c in NUMERIC_FEATURES})).to(device)
    cats = torch.from_numpy(one_hot_np(stream["codes"])).to(device)
    t = torch.from_numpy(stream["t"]).to(device)
    u = torch.from_numpy(stream["user"]).to(device)
    s = torch.from_numpy(stream["src"] + users).to(device)
    d = torch.from_numpy(stream["dst"] + users).to(device)
    bucket = stream["t"] // int(ckpt["bucket_seconds"])
    edges = np.concatenate(([0], np.flatnonzero(np.diff(bucket)) + 1, [len(bucket)]))
    logits = torch.empty(len(bucket), device=device)
    with torch.no_grad():
        for b in range(len(edges) - 1):
            i0, i1 = int(edges[b]), int(edges[b + 1])
            logits[i0:i1] = model.score(state, u[i0:i1], s[i0:i1], d[i0:i1], t[i0:i1], x[i0:i1], cats[i0:i1])
            state = model.update(state, u[i0:i1], s[i0:i1], d[i0:i1], t[i0:i1], cats[i0:i1])
    return (-logits).cpu().numpy()


def evaluate(scores: np.ndarray, stream: dict, rng: np.random.Generator, threshold: float | None) -> dict:
    usable = stream["usable"]
    recordings = np.array(stream["recording"])
    attack = stream["attack"]
    names = sorted({r for r, ok in zip(recordings, usable, strict=True) if ok})
    per = []
    for name in names:
        m = recordings == name
        a, b = scores[m & attack], scores[m & ~attack]
        if len(a) == 0:
            continue
        auc = float(((a[:, None] > b[None, :]).mean() + 0.5 * (a[:, None] == b[None, :]).mean())) if len(b) else None
        rank = int((scores[m] > a.max()).sum()) + 1
        per.append({"recording": name, "attacks": int(len(a)), "benign": int(len(b)), "auc": auc, "best_attack_rank": rank,
                    "events": int(m.sum()), "detected": bool(threshold is not None and (a > threshold).any()),
                    "benign_alerts": int((b > threshold).sum()) if threshold is not None else None})
    sel = np.isin(recordings, [p["recording"] for p in per])
    a_all, b_all = scores[sel & attack], scores[sel & ~attack]
    pooled = float(((a_all[:, None] > b_all[None, :]).mean() + 0.5 * (a_all[:, None] == b_all[None, :]).mean()))
    boots = []
    recs = np.array([p["recording"] for p in per])
    for _ in range(1000):
        pick = rng.choice(recs, size=len(recs), replace=True)
        aa = np.concatenate([scores[(recordings == r) & attack] for r in pick])
        bb = np.concatenate([scores[(recordings == r) & ~attack] for r in pick])
        boots.append(((aa[:, None] > bb[None, :]).mean() + 0.5 * (aa[:, None] == bb[None, :]).mean()))
    within = [p["auc"] for p in per if p["auc"] is not None]
    first = sum(1 for p in per if p["best_attack_rank"] == 1)
    chance_first = float(sum(p["attacks"] / p["events"] for p in per))
    return {
        "recordings": len(per),
        "attack_events": int(len(a_all)),
        "benign_events": int(len(b_all)),
        "pooled_roc_auc": pooled,
        "pooled_roc_auc_ci": [float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))],
        "mean_within_recording_auc": float(np.mean(within)) if within else None,
        "within_recordings": len(within),
        "attack_ranked_first": first,
        "attack_ranked_first_by_chance": chance_first,
        "detected_at_threshold": int(sum(p["detected"] for p in per)) if threshold is not None else None,
        "benign_alerts_at_threshold": int(sum(p["benign_alerts"] or 0 for p in per)) if threshold is not None else None,
        "per_recording": per,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data", type=Path, default=Path("data/raw/otrf"))
    ap.add_argument("--model", action="append", default=[], help="name=checkpoint")
    ap.add_argument("--thresholds", type=Path, help="LANL eval json: 1/10k thresholds per detector")
    ap.add_argument("--supervised", type=Path, help="joblib with LANL-fitted supervised models and scaler")
    ap.add_argument("--v1-events", type=Path, default=Path("artifacts/otrf/otrf_events.json"))
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    rng = np.random.default_rng(args.seed)
    device = torch.device(args.device)
    stream = lab_stream(args.data)
    feats = features(stream)
    lab_scaler = FeatureScaler.fit({c: feats[c] for c in NUMERIC_FEATURES})
    lanl = json.loads(args.thresholds.read_text()) if args.thresholds else None

    def lanl_threshold(name: str) -> float | None:
        if not lanl or name not in lanl["detectors"]:
            return None
        return float(lanl["detectors"][name]["operating_points"]["0.0001"]["threshold"])

    results: dict[str, object] = {
        "events": int(len(stream["t"])),
        "users": int(stream["n_users"]),
        "hosts": int(stream["n_hosts"]),
        "usable_attack_events": int((stream["attack"] & stream["usable"]).sum()),
        "detectors": {},
    }
    for spec in args.model:
        name, path = spec.split("=", 1)
        for variant, scaler in (("lanl-scaled", None), ("lab-scaled", lab_scaler)):
            s = tgn_scores(Path(path), stream, feats, scaler, device)
            results["detectors"][f"{name} ({variant})"] = evaluate(s, stream, rng, lanl_threshold(name))  # type: ignore[index]
    for name, (cols, fn) in FEATURE_DETECTORS.items():
        s = fn({c: feats[c].astype(np.float64) for c in cols}).astype(np.float32)
        results["detectors"][name] = evaluate(s, stream, rng, lanl_threshold(name))  # type: ignore[index]
    if args.supervised and args.supervised.exists():
        import joblib

        bundle = joblib.load(args.supervised)
        x = np.concatenate([bundle["scaler"].transform({c: feats[c] for c in NUMERIC_FEATURES}), one_hot_np(stream["codes"])], axis=1)
        for name, model in bundle["models"].items():
            s = -model.score_samples(x) if name == "isolation_forest" else model.predict_proba(x)[:, 1]
            results["detectors"][name] = evaluate(s.astype(np.float32), stream, rng, lanl_threshold(name))  # type: ignore[index]
    if args.v1_events.exists():
        # the first model (supervised TGN + noisy-OR, LANL dictionary), scored
        # earlier through the live API: same recordings, same labels, same metrics
        v1 = json.loads(args.v1_events.read_text(encoding="utf-8"))
        v1_stream = {
            "recording": [e["dataset"] for e in v1],
            "usable": np.array([e["label"] != "excluded" for e in v1], dtype=bool),
            "attack": np.array([bool(e["attack"]) for e in v1], dtype=bool),
        }
        v1_scores = np.array([float(e["risk"]) for e in v1])
        v1_eval = evaluate(v1_scores, v1_stream, rng, 0.3292)
        v1_eval["note"] = "first GraphSentinel model through the live API (earlier run), alert threshold 0.3292"
        results["detectors"]["v1 supervised TGN + noisy-OR"] = v1_eval  # type: ignore[index]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    for name, r in results["detectors"].items():  # type: ignore[union-attr]
        print(f"{name:>28}: pooled AUC {r['pooled_roc_auc']:.3f} [{r['pooled_roc_auc_ci'][0]:.3f}, {r['pooled_roc_auc_ci'][1]:.3f}]"
              f"  within {r['mean_within_recording_auc']:.3f}  first {r['attack_ranked_first']}/{r['recordings']}"
              f" (chance {r['attack_ranked_first_by_chance']:.1f})  detected {r['detected_at_threshold']}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
