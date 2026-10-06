"""Open item 13: give the model a second attack pattern to learn from.

The shipped checkpoint learned one campaign -- a fast fan-out from one host --
and detects one in five campaigns that differ from it (Findings 20, 21).
This experiment injects labelled synthetic campaigns from ordinary
workstations into the *training window only* of the real corpus, retrains
with the production recipe, and measures the result where it matters:

* on the real sealed test partition -- the same 126 attacks, unchanged, so
  the number is comparable with the shipped model's;
* on the prevention instrument -- 100 campaigns from hosts the injection
  never used, so nothing the model saw in training reappears at test.

The injected campaigns use attacker hosts disjoint from the instrument's, a
different seed, and the same families and interval grid; the split
boundaries are pinned to the same timestamps as the shipped run so that
validation and test are byte-for-byte the partitions Finding 14 was measured
on.

    python scripts/train_second_pattern.py --out artifacts/experiments/second_pattern --device cuda
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import numpy as np  # noqa: E402
import polars as pl  # noqa: E402
import yaml  # noqa: E402
from measure_prevention import (  # noqa: E402
    DEFAULT_DATA,
    DEFAULT_ID_MAPS,
    INTERVALS,
    VALIDATION_END_INDEX,
    build_campaigns,
    load_frame,
)

from graphsentinel.evaluation.splits import fit_chronological_split  # noqa: E402
from graphsentinel.ingestion.auth import NormalizedAuthEvent  # noqa: E402
from graphsentinel.ingestion.parquet import ParquetPartitionWriter  # noqa: E402
from graphsentinel.simulation.campaigns import FAMILIES, plan_campaign  # noqa: E402
from graphsentinel.simulation.generator import attack_events  # noqa: E402
from graphsentinel.simulation.profile import SECONDS_PER_DAY, CorpusProfile  # noqa: E402

INTERIM = ROOT / "data/interim_lanl_1m_cuda"
TRAINING_REPORT = (
    ROOT / "artifacts/metrics/tgn_lanl_545k_split_v3_training-candidate-c6912ac36724.json"
)
RECIPE = ROOT / "configs/model_tgn_v3_high_accuracy.yaml"
FIELDS = tuple(NormalizedAuthEvent.__dataclass_fields__)


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


def run(command: list[str], log_path: Path, env: dict[str, str] | None = None) -> int:
    log("$ " + " ".join(command))
    with log_path.open("w", encoding="utf-8") as stream:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env or dict(os.environ),
            stdout=stream,
            stderr=subprocess.STDOUT,
            check=False,
        )
    return completed.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--campaigns", type=int, default=60, help="injected campaigns, half per family"
    )
    parser.add_argument("--hops", type=int, default=8)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--epochs", type=int, default=16)
    parser.add_argument("--patience", type=int, default=5)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--skip-measure", action="store_true")
    args = parser.parse_args(argv)

    out = args.out
    (out / "logs").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONIOENCODING="utf-8")

    # ------------------------------------------------------------ the corpus and its split
    split = json.loads(TRAINING_REPORT.read_text(encoding="utf-8"))["split"]
    corpus_size = sum(split["counts"].values())
    train_end_ts = int(split["train_end_timestamp"])
    frame = load_frame(INTERIM).head(corpus_size)
    if frame.height != corpus_size:
        raise SystemExit("interim prefix does not match the shipped corpus")
    log(f"corpus: {frame.height:,} events; training window ends at t={train_end_ts:,}")

    # ---------------------------------------------- campaigns inside the training window
    training = frame.filter(pl.col("timestamp") <= train_end_ts)
    profile = CorpusProfile.measure(training)
    instrument_profile = CorpusProfile.measure(load_frame(DEFAULT_DATA).head(VALIDATION_END_INDEX))
    instrument_hosts = {
        c.attacker_host_id
        for c in build_campaigns(
            instrument_profile,
            hops=8,
            replicates=5,
            seed=2024,
            start=instrument_profile.last_timestamp + 1,
            window_seconds=3 * SECONDS_PER_DAY,
        )
    }
    rng = np.random.default_rng(args.seed)
    candidates = [h for h in profile.candidate_attacker_hosts() if h not in instrument_hosts]
    rng.shuffle(candidates)
    if len(candidates) < args.campaigns:
        raise SystemExit("not enough candidate hosts disjoint from the instrument's")
    first_ts = int(training["timestamp"].min())
    lead_in = 6 * 3_600
    campaigns = []
    reserved: dict[int, set[int]] = {}
    per_family = args.campaigns // len(FAMILIES)
    index = 0
    for family in FAMILIES:
        for k in range(per_family):
            interval = int(INTERVALS[k % len(INTERVALS)])
            duration = interval * (args.hops - 1)
            start_at = int(rng.integers(first_ts + lead_in, train_end_ts - duration - 60))
            campaigns.append(
                plan_campaign(
                    profile,
                    rng,
                    campaign_id=f"train-{family[:1].upper()}-{interval}s-{k:02d}",
                    family=family,
                    hops=args.hops,
                    interval_seconds=interval,
                    start_timestamp=start_at,
                    attacker_host_id=int(candidates[index]),
                    reserved=reserved,
                )
            )
            index += 1
    injected, _truths = attack_events(profile, rng, campaigns)
    log(
        f"injected {len(injected)} attack events from {len(campaigns)} campaigns "
        f"({per_family} per family) on {len({c.attacker_host_id for c in campaigns})} hosts"
    )
    assert all(e.timestamp <= train_end_ts for e in injected)

    # ------------------------------------------------------------ merged interim
    next_id = int(frame["event_id"].max()) + 1
    rows = frame.select(list(FIELDS)).to_dicts()
    events = [NormalizedAuthEvent(**row) for row in rows]
    for offset, event in enumerate(injected):
        events.append(replace(event, event_id=next_id + offset))
    events.sort(key=lambda e: (e.timestamp, e.event_id))
    # The feature build requires contiguous ids in stream order.
    events = [replace(event, event_id=index) for index, event in enumerate(events)]
    interim = out / "interim"
    if interim.exists():
        import shutil

        shutil.rmtree(interim)
    writer = ParquetPartitionWriter(interim)
    files = 0
    for start in range(0, len(events), 250_000):
        files += writer.write(events[start : start + 250_000])
    log(f"wrote {len(events):,} events in {files} parquet files -> {interim}")
    (out / "injection_manifest.json").write_text(
        json.dumps(
            {
                "campaigns": [c.to_dict() for c in campaigns],
                "injected_events": len(injected),
                "attacker_hosts": sorted({c.attacker_host_id for c in campaigns}),
                "instrument_hosts_excluded": sorted(instrument_hosts),
                "seed": args.seed,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # ---------------------------------------------- split fractions that pin the boundaries
    timestamps = [e.timestamp for e in events]
    labels = [e.label_redteam for e in events]
    total = len(events)
    want_train = split["train_end_index"] + len(injected)
    want_validation = split["validation_end_index"] + len(injected)
    train_fraction = want_train / total
    validation_fraction = want_validation / total - train_fraction
    fitted = fit_chronological_split(
        timestamps, labels, train_fraction=train_fraction, validation_fraction=validation_fraction
    )
    if (fitted.train_end_timestamp, fitted.validation_end_timestamp) != (
        train_end_ts,
        int(split["validation_end_timestamp"]),
    ):
        raise SystemExit(
            f"split boundaries moved: {fitted.train_end_timestamp}, "
            f"{fitted.validation_end_timestamp}"
        )
    log(
        f"split pinned: train {fitted.counts['train']:,} ({fitted.positives['train']} attacks), "
        f"validation {fitted.counts['validation']:,} ({fitted.positives['validation']}), "
        f"test {fitted.counts['test']:,} ({fitted.positives['test']})"
    )
    recipe = yaml.safe_load(RECIPE.read_text(encoding="utf-8"))
    recipe["selection"]["train_fraction"] = float(train_fraction)
    recipe["selection"]["validation_fraction"] = float(validation_fraction)
    recipe["training"]["epochs"] = args.epochs
    recipe["training"]["patience"] = args.patience
    config_path = out / "model_tgn.yaml"
    config_path.write_text(yaml.safe_dump(recipe, sort_keys=False), encoding="utf-8")
    env["GRAPHSENTINEL_MODEL_CONFIG"] = str(config_path)
    env["GRAPHSENTINEL_TRAINING_STATUS_PATH"] = str(out / "cli-training-status.json")

    # ------------------------------------------------------------ features, baselines, training
    features = out / "features"
    feature_report = out / "features_v1.json"
    if features.exists():
        import shutil

        shutil.rmtree(features)  # the build refuses to overwrite; the interim is fresh anyway
    if run(
        [
            args.python,
            "-m",
            "graphsentinel",
            "features",
            "build",
            "--input",
            str(interim),
            "--output",
            str(features),
            "--report",
            str(feature_report),
        ],
        out / "logs" / "02_features.log",
        env,
    ):
        raise SystemExit("features build failed")
    baselines = out / "baselines_v1.json"
    if run(
        [
            args.python,
            "-m",
            "graphsentinel",
            "evaluate",
            "baselines",
            "--input",
            str(features),
            "--feature-report",
            str(feature_report),
            "--output",
            str(baselines),
            "--train-fraction",
            f"{train_fraction:.10f}",
            "--validation-fraction",
            f"{validation_fraction:.10f}",
        ],
        out / "logs" / "03_baselines.log",
        env,
    ):
        raise SystemExit("baselines failed")
    checkpoint = out / "tgn-second-pattern.pt"
    report = out / "tgn_training.json"
    code = run(
        [
            args.python,
            "-m",
            "graphsentinel",
            "train",
            "tgn",
            "--input",
            str(features),
            "--feature-report",
            str(feature_report),
            "--checkpoint",
            str(checkpoint),
            "--report",
            str(report),
            "--baseline-report",
            str(baselines),
            "--raw-manifest-dir",
            str(ROOT / "data/raw/lanl"),
            "--epochs",
            str(args.epochs),
            "--patience",
            str(args.patience),
            "--id-maps",
            str(DEFAULT_ID_MAPS),
            "--device",
            args.device,
        ],
        out / "logs" / "04_train.log",
        env,
    )
    if code not in (0, 3):
        raise SystemExit(f"training failed ({code})")
    if code == 3:
        candidates_ = sorted(out.glob("tgn-second-pattern-candidate-*.pt"))
        reports_ = sorted(out.glob("tgn_training-candidate-*.json"))
        checkpoint, report = candidates_[-1], reports_[-1]
        log(f"candidate not promoted; using {checkpoint.name}")
    log(f"checkpoint {checkpoint}")

    if args.skip_measure:
        return 0

    # ---------------------------------------------- measure on the real sealed test, unchanged
    cache = out / "fusion_cache.parquet"
    if run(
        [
            args.python,
            str(ROOT / "scripts/build_scored_cache.py"),
            "--data",
            str(DEFAULT_DATA),
            "--checkpoint",
            str(checkpoint),
            "--report",
            str(TRAINING_REPORT),
            "--out",
            str(cache),
            "--device",
            "cpu",
        ],
        out / "logs" / "05_score.log",
        env,
    ):
        raise SystemExit("scoring failed")
    if run(
        [
            args.python,
            "-m",
            "graphsentinel",
            "evaluation-report",
            "--cache",
            str(cache),
            "--output",
            str(out / "docs"),
            "--resamples",
            "2000",
        ],
        out / "logs" / "06_report.log",
        env,
    ):
        raise SystemExit("evaluation report failed")
    # ------------------------------------------------------------ and against unseen campaigns
    if run(
        [
            args.python,
            str(ROOT / "scripts/measure_prevention.py"),
            "--checkpoint",
            str(checkpoint),
            "--out",
            str(out / "prevention"),
        ],
        out / "logs" / "07_prevention.log",
        env,
    ):
        raise SystemExit("prevention instrument failed")
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
