"""Measure recall and precision for the six techniques that have no labels.

The corpus labels lateral movement only. For everything else the project has
published a benign firing rate, which says how noisy a signature is and nothing
about whether it fires on the behaviour it names. This injects each technique
-- built from ATT&CK's description of the behaviour, not from the rule -- into
a warm synthetic continuation of the real stream and measures three things:

* detection recall: did the product alert on the injected events at all
* attribution recall: did the engine name the right technique, confidently
* precision: of everything the engine called this technique, how much was

Usage::

    python scripts/validate_techniques.py --out artifacts/prevention/techniques
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import numpy as np  # noqa: E402
from measure_prevention import (  # noqa: E402
    DEFAULT_CHECKPOINT,
    DEFAULT_DATA,
    DEFAULT_ID_MAPS,
    DEFAULT_WARM_ROOT,
    VALIDATION_END_INDEX,
    load_frame,
    warm_state,
)

from graphsentinel.features.causal import CausalFeatureEngine  # noqa: E402
from graphsentinel.ingestion.id_map import AuthIdMaps  # noqa: E402
from graphsentinel.models.serving import load_inference_session  # noqa: E402
from graphsentinel.onboarding.backfill import FEATURE_STATE_NAME, TGN_MEMORY_NAME  # noqa: E402
from graphsentinel.simulation.generator import generate_stream  # noqa: E402
from graphsentinel.simulation.prevention import (  # noqa: E402
    EntityNames,
    measure_prevention,
    render_technique_validation,
    session_scorer,
    technique_validation,
)
from graphsentinel.simulation.profile import SECONDS_PER_DAY, CorpusProfile  # noqa: E402
from graphsentinel.simulation.techniques import SCENARIOS, CategoryIds  # noqa: E402


def machine_account_ids(maps: AuthIdMaps) -> list[int]:
    names = maps.users.to_dict()["values"]
    return [index for index, name in enumerate(names) if name.split("@", 1)[0].endswith("$")]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--id-maps", type=Path, default=DEFAULT_ID_MAPS)
    parser.add_argument("--warm-root", type=Path, default=DEFAULT_WARM_ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", type=float, default=3.0)
    parser.add_argument("--replicates", type=int, default=12, help="scenarios per builder")
    parser.add_argument("--seed", type=int, default=4096)
    parser.add_argument("--operating-point", default="noisy_or")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--warm-limit", type=int, default=VALIDATION_END_INDEX)
    args = parser.parse_args(argv)

    def log(message: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    args.out.mkdir(parents=True, exist_ok=True)
    warm = warm_state(args.checkpoint, args.data, args.warm_root, limit=args.warm_limit, log=log)
    maps = AuthIdMaps.load(args.id_maps)
    ids = CategoryIds.from_id_maps(maps)
    machines = machine_account_ids(maps)

    log("profiling the warm-up prefix")
    profile = CorpusProfile.measure(load_frame(args.data).head(args.warm_limit))
    start = profile.last_timestamp + 1
    window = int(args.days * SECONDS_PER_DAY)
    lead_in = min(6 * 3_600, window // 4)

    rng = np.random.default_rng(args.seed)
    hosts = profile.candidate_attacker_hosts()
    rng.shuffle(hosts)
    scenarios = []
    index = 0
    for technique, builders in SCENARIOS.items():
        for builder in builders:
            for replicate in range(args.replicates):
                # The off-hours scenario slides forward to the next 02:00, so every
                # start leaves more than a day of headroom before the window ends.
                headroom = 30 * 3_600
                if start + window - headroom <= start + lead_in:
                    raise ValueError("window too short for the scenarios; increase --days")
                at = int(rng.integers(start + lead_in, start + window - headroom))
                extra = {"machine_accounts": machines} if technique == "T1078.002" else {}
                scenarios.append(
                    builder(
                        profile,
                        rng,
                        ids,
                        scenario_id=f"{builder.__name__}-{replicate:02d}",
                        start=at,
                        attacker_host=int(hosts[index % len(hosts)]),
                        **extra,
                    )
                )
                index += 1
    injected = [
        (event, truth)
        for s in scenarios
        for event, truth in zip(s.events, s.truths(), strict=False)
    ]
    log(f"{len(scenarios)} scenarios, {len(injected)} injected events over {args.days} days")

    stream = generate_stream(
        profile,
        campaigns=[],
        start_timestamp=start,
        end_timestamp=start + window,
        seed=args.seed,
        extra=injected,
    )
    log(f"stream: {len(stream.events):,} events ({stream.benign_count:,} benign)")
    (args.out / "stream_manifest.json").write_text(
        json.dumps(
            {
                **stream.manifest(),
                "scenarios": [s.to_dict() for s in scenarios],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    log("restoring state and computing features")
    engine = CausalFeatureEngine()
    with gzip.open(warm / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        engine.restore(json.load(handle))
    records = list(engine.transform(stream.events))
    session = load_inference_session(args.checkpoint, device=args.device)
    session.load_memory(warm / TGN_MEMORY_NAME)
    names = EntityNames.from_id_maps(maps)

    log(f"scoring under {args.operating_point}")
    started = time.perf_counter()
    report = measure_prevention(
        records,
        stream.truth,
        [],
        scorer=session_scorer(session),
        names=names,
        operating_point=args.operating_point,
    )
    log(f"  done in {(time.perf_counter() - started) / 60:.1f} min")

    results = technique_validation(report.events, list(SCENARIOS))
    text = render_technique_validation(results)
    print("\n" + text + "\n", flush=True)
    (args.out / "technique_validation.md").write_text(text + "\n", encoding="utf-8")
    (args.out / "technique_validation.json").write_text(
        json.dumps(
            {
                "checkpoint": str(args.checkpoint),
                "model_version": session.provenance.model_version,
                "operating_point": args.operating_point,
                "threshold": report.threshold,
                "replicates_per_builder": args.replicates,
                "benign_events": report.benign_events,
                "benign_alert_rate_per_10k": round(report.benign_alert_rate_per_10k, 3),
                "techniques": {k: v.to_dict() for k, v in results.items()},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    log(f"wrote {args.out / 'technique_validation.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
