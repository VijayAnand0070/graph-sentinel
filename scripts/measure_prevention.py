"""Measure what the shipped detection stack does to campaigns it has never seen.

Pipeline
--------
1. **Warm state.** Replay the real corpus through the validation boundary
   (427,623 events -- everything the model was trained and tuned on, nothing
   it was tested on) with the onboarding backfill, producing the feature-engine
   snapshot and the checkpoint's node memory. Cold state costs 46% of PR-AUC
   (Finding 9); measuring prevention cold would measure the wrong system.
2. **Profile.** Measure benign behaviour over the same prefix.
3. **Campaigns.** A grid of families x inter-hop intervals x replicates, each
   from a distinct ordinary workstation with benign history, laid over a
   synthetic continuation of the stream.
4. **Score.** Restore state, compute features, run the production composition
   (signals, chain tracker, tactics, TGN, fusion, rule floor, response plan).
5. **Account.** Detection latency in hops, prevented hops under both
   semantics, benign cost, evasion curve. Written as JSON and a readable table.

Usage::

    python scripts/measure_prevention.py --out artifacts/prevention/production
    python scripts/measure_prevention.py --checkpoint path/to/variant.pt --out ...

The warm state is cached per checkpoint under ``--warm-root`` so re-running
with a different campaign grid does not replay the corpus again.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import numpy as np  # noqa: E402
import polars as pl  # noqa: E402

from graphsentinel.features.causal import CausalFeatureEngine  # noqa: E402
from graphsentinel.ingestion.id_map import AuthIdMaps  # noqa: E402
from graphsentinel.models.serving import load_inference_session  # noqa: E402
from graphsentinel.onboarding.backfill import (  # noqa: E402
    FEATURE_STATE_NAME,
    TGN_MEMORY_NAME,
    run_backfill,
)
from graphsentinel.simulation.campaigns import FAMILIES, plan_campaign  # noqa: E402
from graphsentinel.simulation.generator import generate_stream  # noqa: E402
from graphsentinel.simulation.prevention import (  # noqa: E402
    EntityNames,
    measure_prevention,
    render_prevention,
    session_scorer,
)
from graphsentinel.simulation.profile import SECONDS_PER_DAY, CorpusProfile  # noqa: E402

DEFAULT_CHECKPOINT = ROOT / "artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt"
DEFAULT_DATA = ROOT / "data/processed/features_lanl_545k_split"
DEFAULT_ID_MAPS = ROOT / "artifacts/id_maps_lanl_1m_cuda"
DEFAULT_WARM_ROOT = ROOT / "artifacts/prevention/warm"

#: Everything the model was trained and tuned on; nothing it was tested on.
VALIDATION_END_INDEX = 427_623

#: Inter-hop intervals for the evasion curve. 300 s is the chain window and
#: 1,800 s the pivot window, so the grid straddles both.
INTERVALS = (15, 60, 120, 240, 300, 360, 600, 900, 1_800, 3_600)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def warm_state(checkpoint: Path, data: Path, warm_root: Path, *, limit: int, log) -> Path:
    """Backfill through ``limit`` events, cached per (checkpoint, limit)."""
    target = warm_root / f"{_sha(checkpoint)}-{limit}"
    if (target / FEATURE_STATE_NAME).is_file() and (target / TGN_MEMORY_NAME).is_file():
        log(f"warm state cached at {target}")
        return target
    log(
        f"building warm state for {checkpoint.name} -> {target} ({limit:,} events, several minutes)"
    )
    result = run_backfill(
        data,
        target,
        checkpoint=checkpoint,
        limit=limit,
        progress=lambda n: log(f"  backfill {n:,}"),
    )
    log(
        f"warm state built in {result.duration_seconds / 60:.1f} min; "
        f"memory coverage {result.memory_coverage}"
    )
    return target


def load_frame(data: Path) -> pl.DataFrame:
    frame = pl.concat([pl.read_parquet(f) for f in sorted(data.glob("**/*.parquet"))])
    return frame.sort("timestamp", "event_id")


def build_campaigns(
    profile: CorpusProfile,
    *,
    hops: int,
    replicates: int,
    seed: int,
    start: int,
    window_seconds: int,
) -> list:
    """The grid. Each campaign gets a distinct attacker host and a start time
    placed so its last hop lands inside the window."""
    rng = np.random.default_rng(seed)
    hosts = profile.candidate_attacker_hosts()
    rng.shuffle(hosts)
    if len(hosts) < len(FAMILIES) * len(INTERVALS) * replicates:
        raise ValueError("not enough candidate attacker hosts for the grid")
    # Trackers and rolling windows warm up on benign traffic first; the pivot
    # window is 1,800 s, so an hour is plenty and six is comfortable.
    lead_in = min(6 * 3_600, window_seconds // 4)
    campaigns = []
    reserved: dict[int, set[int]] = {}  # every campaign's hops stay novel for its account
    index = 0
    for family in FAMILIES:
        for interval in INTERVALS:
            for replicate in range(replicates):
                duration = interval * (hops - 1)
                latest_start = start + window_seconds - duration - 60
                if latest_start <= start + lead_in:
                    raise ValueError(
                        f"window of {window_seconds:,}s cannot hold a {hops}-hop campaign "
                        f"at {interval}s intervals after a {lead_in:,}s lead-in; "
                        "increase --days"
                    )
                start_at = int(rng.integers(start + lead_in, latest_start))
                campaigns.append(
                    plan_campaign(
                        profile,
                        rng,
                        campaign_id=f"{family[:1].upper()}-{interval}s-{replicate:02d}",
                        family=family,
                        hops=hops,
                        interval_seconds=interval,
                        start_timestamp=start_at,
                        attacker_host_id=int(hosts[index]),
                        reserved=reserved,
                    )
                )
                index += 1
    return campaigns


def run_transfer(args, log) -> int:  # type: ignore[no-untyped-def]
    """The label-free system: onboard on the warm prefix (no labels), then measure.

    Onboarding is the product's own: features from the prefix, the estate's
    scaling, warm memory and the reference distribution the budgets are read on.
    """
    from graphsentinel.detection.signals import FanOutTracker
    from graphsentinel.models.transfer_serving import load_transfer_session
    from graphsentinel.onboarding.backfill import events_from_parquet
    from graphsentinel.onboarding.calibrate import MEMORY_NAME, PROFILE_NAME, run_onboarding
    from graphsentinel.simulation.prevention import transfer_scorer

    ckpt = args.transfer_checkpoint
    warm = args.warm_root / f"transfer-{_sha(ckpt)}-{args.warm_limit}-{args.alert_budget:g}-{args.action_budget:g}"
    if not (warm / PROFILE_NAME).is_file():
        log(f"onboarding the transfer model on {args.warm_limit:,} prefix events -> {warm}")
        run_onboarding(
            events_from_parquet(args.data, limit=args.warm_limit), id_maps_dir=args.id_maps, checkpoint=ckpt,
            output_dir=warm, alert_budget=args.alert_budget, action_budget=args.action_budget, device=args.device,
            progress=lambda stage, n: log(f"  {stage} {n:,}") if n % 100_000 == 0 else None,
        )
    frame = load_frame(args.data)
    profile = CorpusProfile.measure(frame.head(args.warm_limit))
    start = profile.last_timestamp + 1
    window = int(args.days * SECONDS_PER_DAY)
    campaigns = build_campaigns(profile, hops=args.hops, replicates=args.replicates, seed=args.seed,
                                start=start, window_seconds=window)
    stream = generate_stream(profile, campaigns=campaigns, start_timestamp=start, end_timestamp=start + window,
                             seed=args.seed)
    log(f"stream: {len(stream.events):,} events ({stream.benign_count:,} benign, {stream.attack_count} attack)")
    engine = CausalFeatureEngine()
    with gzip.open(warm / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        engine.restore(json.load(handle))
    records = list(engine.transform(stream.events))
    maps = AuthIdMaps.load(args.id_maps)
    names = EntityNames.from_id_maps(maps)
    hosts = list(maps.hosts.to_dict()["values"])
    session = load_transfer_session(ckpt, profile_path=warm / PROFILE_NAME, device=args.device)
    results: dict[str, object] = {"transfer_checkpoint": str(ckpt), "warm": str(warm), "fanout": args.fanout,
                                  "alert_budget": args.alert_budget, "action_budget": args.action_budget,
                                  "operating_points": {}}
    for fanout in ([False, True] if args.fanout else [False]):
        session.load_memory(warm / MEMORY_NAME)
        name = "transfer+fanout" if fanout else "transfer"
        log(f"scoring {name}")
        report = measure_prevention(
            records, stream.truth, stream.campaigns, scorer=transfer_scorer(session, names, hosts), names=names,
            operating_point="transfer", fanout=FanOutTracker() if fanout else None,
        )
        results["operating_points"][name] = report.to_dict()  # type: ignore[index]
        text = render_prevention(report)
        (args.out / f"prevention_{name}.md").write_text(text + "\n", encoding="utf-8")
        print("\n" + text + "\n", flush=True)
    (args.out / "prevention_report.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    log(f"wrote {args.out / 'prevention_report.json'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--id-maps", type=Path, default=DEFAULT_ID_MAPS)
    parser.add_argument("--warm-root", type=Path, default=DEFAULT_WARM_ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", type=float, default=3.0, help="synthetic window length")
    parser.add_argument("--hops", type=int, default=8)
    parser.add_argument("--replicates", type=int, default=5)
    parser.add_argument("--seed", type=int, default=2024)
    parser.add_argument("--operating-points", default="noisy_or,tgn_only")
    parser.add_argument("--device", default="cpu")
    parser.add_argument(
        "--chain-rule-floor",
        type=float,
        default=None,
        help="score a rule-detected chain is raised to (default: the shipped floor)",
    )
    parser.add_argument("--transfer-checkpoint", type=Path, default=None,
                        help="measure the label-free transfer model (onboarded on the warm prefix) instead")
    parser.add_argument("--fanout", action="store_true", help="add the fan-out rule beside the chain rule")
    parser.add_argument("--alert-budget", type=float, default=25e-4)
    parser.add_argument("--action-budget", type=float, default=5e-4)
    parser.add_argument(
        "--warm-limit",
        type=int,
        default=VALIDATION_END_INDEX,
        help="events to warm on; below the default only for smoke tests",
    )
    args = parser.parse_args(argv)

    def log(message: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    args.out.mkdir(parents=True, exist_ok=True)
    if args.transfer_checkpoint is not None:
        return run_transfer(args, log)
    warm = warm_state(args.checkpoint, args.data, args.warm_root, limit=args.warm_limit, log=log)

    log("profiling the warm-up prefix")
    frame = load_frame(args.data)
    prefix = frame.head(args.warm_limit)
    profile = CorpusProfile.measure(prefix)
    log(f"profile: {profile.summary()}")

    start = profile.last_timestamp + 1
    window = int(args.days * SECONDS_PER_DAY)
    campaigns = build_campaigns(
        profile,
        hops=args.hops,
        replicates=args.replicates,
        seed=args.seed,
        start=start,
        window_seconds=window,
    )
    log(f"{len(campaigns)} campaigns over {args.days} days from t={start}")

    stream = generate_stream(
        profile,
        campaigns=campaigns,
        start_timestamp=start,
        end_timestamp=start + window,
        seed=args.seed,
    )
    log(
        f"stream: {len(stream.events):,} events ({stream.benign_count:,} benign, "
        f"{stream.attack_count} attack)"
    )
    (args.out / "stream_manifest.json").write_text(
        json.dumps(stream.manifest(), indent=2), encoding="utf-8"
    )

    log("restoring feature state and computing features")
    engine = CausalFeatureEngine()
    with gzip.open(warm / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        engine.restore(json.load(handle))
    records = list(engine.transform(stream.events))

    log("loading checkpoint and restoring node memory")
    session = load_inference_session(args.checkpoint, device=args.device)
    session.load_memory(warm / TGN_MEMORY_NAME)
    names = EntityNames.from_id_maps(AuthIdMaps.load(args.id_maps))

    results: dict[str, object] = {
        "checkpoint": str(args.checkpoint),
        "checkpoint_sha16": _sha(args.checkpoint),
        "model_version": session.provenance.model_version,
        "warm_state": str(warm),
        "warm_limit": args.warm_limit,
        "chain_rule_floor": args.chain_rule_floor,
        "campaign_grid": {
            "families": list(FAMILIES),
            "intervals": list(INTERVALS),
            "hops": args.hops,
            "replicates": args.replicates,
        },
        "operating_points": {},
    }
    memory_after_warm = session.memory_coverage()
    for point in [p.strip() for p in args.operating_points.split(",") if p.strip()]:
        # Each operating point replays from the same warm memory.
        session.load_memory(warm / TGN_MEMORY_NAME)
        log(f"scoring under operating point {point}")
        started = time.perf_counter()
        floor_override = (
            {} if args.chain_rule_floor is None else {"chain_rule_floor": args.chain_rule_floor}
        )
        report = measure_prevention(
            records,
            stream.truth,
            stream.campaigns,
            scorer=session_scorer(session),
            names=names,
            operating_point=point,
            **floor_override,
        )
        log(f"  done in {(time.perf_counter() - started) / 60:.1f} min")
        results["operating_points"][point] = report.to_dict()
        text = render_prevention(report)
        (args.out / f"prevention_{point}.md").write_text(text + "\n", encoding="utf-8")
        print("\n" + text + "\n", flush=True)
    results["memory_coverage_after_warm"] = memory_after_warm
    (args.out / "prevention_report.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    log(f"wrote {args.out / 'prevention_report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
