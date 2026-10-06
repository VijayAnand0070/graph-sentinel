"""End-to-end pipeline check: raw LANL text to a served, responding API, in one run.

    python scripts/e2e_pipeline.py --raw-dir data/raw/lanl --run-dir artifacts/e2e/lanl_900k \
        --end-timestamp 900000 --sample-stride 448 --epochs 6 --device cuda

    python scripts/e2e_pipeline.py --synthetic --run-dir artifacts/e2e/synthetic --epochs 2

Every stage is the product's own entry point -- the ``graphsentinel`` CLI, the
scored-cache builder, the API process -- run as a subprocess with the run
directory's artefacts wired in through the same environment variables an
operator would set. Nothing is re-implemented here; the script only asserts
what each stage must leave behind and what the next one must see.

Stages, in order, each with the assertion that fails the run:

1. ``verify``    the raw manifest passes the dataset contract
2. ``ingest``    interim parquet with labels, no local logons, chronological
3. ``features``  the causal feature dataset and its report
4. ``baselines`` E1/E2 baselines with validation PR-AUC
5. ``train``     a TGN checkpoint that loads under the serving contract
6. ``score``     the per-event scored cache over every partition
7. ``report``    the evaluation report with bootstrap intervals
8. ``backfill``  warm feature state and model memory through the validation boundary
9. ``serve``     the API starts warm, streams the run's own test partition through
                 the live gateway, dispatches automatic responses, takes an approval,
                 answers every console endpoint, and survives a restart with its
                 records intact

The live stage also compares what the deployed path computed for each test
event against what the offline evaluation computed for the same event: every
channel (novelty, burst, pivot, the model probability) and the fused risk
with the chain-rule floor must agree, the only allowance being the first 30
minutes of the stream while the windowed signal state, which is not part of
the warm snapshot, fills. That comparison is the end-to-end claim: the served
product reproduces the evaluated one, number for number.

Stages whose artefacts already exist are reused (``--fresh`` rebuilds), so a
run interrupted after the long ingest resumes from the feature build.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def _say(message: str) -> None:
    print(message, flush=True)


class StageFailure(Exception):
    """A stage's assertion did not hold."""


@dataclass
class StageResult:
    name: str
    status: str = "pending"  # passed | reused | failed | skipped
    seconds: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "seconds": round(self.seconds, 1),
            "details": self.details,
            "error": self.error,
        }


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise StageFailure(f"{path} is not a JSON object")
    return payload


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StageFailure(message)


class Http:
    """The smallest client the check needs; urllib so nothing is added."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")

    def get(self, path: str, *, timeout: float = 30) -> tuple[int, Any]:
        request = urllib.request.Request(self.base + path, method="GET")
        return self._send(request, timeout)

    def post(self, path: str, payload: object, *, timeout: float = 30) -> tuple[int, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self.base + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        return self._send(request, timeout)

    @staticmethod
    def _send(request: urllib.request.Request, timeout: float) -> tuple[int, Any]:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            status = error.code
        content = raw.decode("utf-8", errors="replace")
        try:
            return status, json.loads(content)
        except json.JSONDecodeError:
            return status, content


@dataclass
class Pipeline:
    raw_dir: Path
    run_dir: Path
    end_timestamp: int | None
    sample_stride: int
    epochs: int
    patience: int
    device: str
    port: int
    fresh: bool
    resamples: int
    live_limit: int | None
    batch_events: int
    model_config: Path = Path("configs/model_tgn_v3_high_accuracy.yaml")
    train_fraction: float = 0.70
    validation_fraction: float = 0.15
    #: ``lanl`` runs ``ingest auth`` on the raw directory; any other name is a
    #: source adapter (``graphsentinel sources list``) run through ``ingest logs``
    #: on ``source_inputs`` with ``labels_path`` for ground truth.
    source_format: str = "lanl"
    source_inputs: tuple[Path, ...] = ()
    labels_path: Path | None = None
    column_map: str | None = None
    python: str = sys.executable
    log: Callable[[str], None] = field(default=_say)

    def __post_init__(self) -> None:
        r = self.run_dir
        self.interim = r / "interim"
        self.id_maps = r / "id_maps"
        self.features = r / "features"
        self.reports = r / "reports"
        self.metrics = r / "metrics"
        self.models = r / "models"
        self.state = r / "state"
        self.docs = r / "docs"
        self.logs = r / "logs"
        self.runtime = r / "runtime"
        self.serve_dir = r / "serve"
        self.ingestion_report = self.reports / "ingestion_auth.json"
        self.feature_report = self.reports / "features_v1.json"
        self.baseline_report = self.metrics / "baselines_v1.json"
        self.checkpoint = self.models / "tgn-production.pt"
        self.training_report = self.metrics / "tgn_training.json"
        self.cache = r / "fusion_cache.parquet"
        self.evaluation_report = self.docs / "evaluation_report.json"
        self.stages: list[StageResult] = []
        for directory in (self.reports, self.metrics, self.models, self.logs, self.runtime):
            directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ plumbing
    def _env(self, **extra: str) -> dict[str, str]:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["GRAPHSENTINEL_TRAINING_STATUS_PATH"] = str(self.runtime / "cli-training-status.json")
        env["GRAPHSENTINEL_MODEL_CONFIG"] = str(self.run_model_config)
        env.update(extra)
        return env

    @property
    def run_model_config(self) -> Path:
        return self.run_dir / "model_tgn.yaml"

    def _write_model_config(self) -> dict[str, Any]:
        """The training recipe, copied into the run with this run's split.

        The recipe is the one the shipped checkpoint was trained with
        (``configs/model_tgn_v3_high_accuracy.yaml``: 60-second time buckets,
        the raised positive-weight cap), not the package default, which
        differs from it in five settings and trains an order of magnitude
        slower. Its split fractions are corpus-specific and are replaced by
        this run's, so the recipe and the split are both recorded.
        """
        import yaml

        recipe = yaml.safe_load(self.model_config.read_text(encoding="utf-8"))
        recipe["selection"]["train_fraction"] = self.train_fraction
        recipe["selection"]["validation_fraction"] = self.validation_fraction
        self.run_model_config.write_text(
            f"# copied from {self.model_config} by scripts/e2e_pipeline.py; "
            "split fractions are this run's\n" + yaml.safe_dump(recipe, sort_keys=False),
            encoding="utf-8",
        )
        return recipe

    def _cli(self, name: str, args: Sequence[str], *, ok: Sequence[int] = (0,)) -> int:
        log_path = self.logs / f"{name}.log"
        command = [self.python, "-m", "graphsentinel", *args]
        self.log(f"  $ graphsentinel {' '.join(args)}")
        with log_path.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=self._env(),
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if completed.returncode not in ok:
            tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-25:]
            raise StageFailure(
                f"graphsentinel {args[0]} exited {completed.returncode}; "
                f"see {log_path}\n" + "\n".join(tail)
            )
        return completed.returncode

    def _stage(self, name: str, body: Callable[[StageResult], bool]) -> None:
        result = StageResult(name=name)
        started = time.perf_counter()
        self.log(f"[{name}]")
        try:
            reused = body(result)
            result.status = "reused" if reused else "passed"
        except StageFailure as error:
            result.status = "failed"
            result.error = str(error)
        except Exception as error:  # the report must say what broke
            result.status = "failed"
            result.error = f"{type(error).__name__}: {error}\n{traceback.format_exc()}"
        result.seconds = time.perf_counter() - started
        self.stages.append(result)
        self.log(f"  -> {result.status} ({result.seconds:.1f}s)")
        if result.status == "failed":
            self.log(f"  {result.error}")
            raise StageFailure(name)

    # ------------------------------------------------------------ stages
    def stage_verify(self, result: StageResult) -> bool:
        if self.source_format != "lanl":
            # No LANL manifest: the inputs must exist and be readable by the
            # adapter; the ingest report records their digests as provenance.
            for path in self.source_inputs:
                _require(path.is_file(), f"source input missing: {path}")
            _require(bool(self.source_inputs), "no source inputs given")
            result.details = {
                "format": self.source_format,
                "inputs": [str(p) for p in self.source_inputs],
                "labels": str(self.labels_path) if self.labels_path else None,
            }
            return False
        self._cli(
            "00_verify", ["dataset", "verify", "--require", "core", "--raw-dir", str(self.raw_dir)]
        )
        manifest = _read_json(self.raw_dir / "manifest.json")
        files = {f["file"]: f for f in manifest.get("files", []) if isinstance(f, dict)}
        for name in ("auth.txt.gz", "redteam.txt.gz"):
            _require(name in files, f"manifest lacks {name}")
            _require(files[name].get("validation_level") == "full", f"{name} needs a full scan")
        result.details = {"files": sorted(files), "dataset": manifest.get("dataset")}
        return False

    def stage_ingest(self, result: StageResult) -> bool:
        reused = False
        if self.ingestion_report.is_file() and not self.fresh:
            existing = _read_json(self.ingestion_report)
            if self.source_format == "lanl":
                matches = (
                    existing.get("end_timestamp") == self.end_timestamp
                    and existing.get("sample_stride") == self.sample_stride
                    and existing.get("drop_self_loops") is True
                    and any(self.interim.rglob("*.parquet"))
                )
            else:
                matches = existing.get("format") == self.source_format and any(
                    self.interim.rglob("*.parquet")
                )
            reused = bool(matches)
        if not reused and self.source_format != "lanl":
            if self.interim.exists():
                shutil.rmtree(self.interim)
            args = ["ingest", "logs", "--format", self.source_format]
            for path in self.source_inputs:
                args += ["--input", str(path)]
            args += [
                "--output",
                str(self.interim),
                "--id-maps",
                str(self.id_maps),
                "--report",
                str(self.ingestion_report),
            ]
            if self.labels_path is not None:
                args += ["--labels", str(self.labels_path)]
            if self.column_map:
                args += ["--map", self.column_map]
            self._cli("01_ingest", args)
        elif not reused:
            if self.interim.exists():
                shutil.rmtree(self.interim)
            args = [
                "ingest",
                "auth",
                "--auth",
                str(self.raw_dir / "auth.txt.gz"),
                "--redteam",
                str(self.raw_dir / "redteam.txt.gz"),
                "--output",
                str(self.interim),
                "--id-maps",
                str(self.id_maps),
                "--report",
                str(self.ingestion_report),
                "--sample-stride",
                str(self.sample_stride),
            ]
            if self.end_timestamp is not None:
                args += ["--end-timestamp", str(self.end_timestamp)]
            self._cli("01_ingest", args)
        report = _read_json(self.ingestion_report)
        _require(report["rows_parsed"] > 0, "ingest wrote no rows")
        _require(report["redteam_matches"] > 0, "ingest matched no red-team events")
        _require(report["timestamps_non_decreasing"] is True, "ingest saw out-of-order rows")
        _require(report["drop_self_loops"] is True, "ingest kept self-loops")
        _require(report.get("redteam_self_loops", 0) == 0, "a red-team event was a self-loop")

        import polars as pl

        frame = pl.concat([pl.read_parquet(f) for f in sorted(self.interim.rglob("*.parquet"))])
        _require(frame.height == report["rows_parsed"], "parquet rows != report rows_parsed")
        loops = frame.filter(pl.col("src_host_id") == pl.col("dst_host_id")).height
        _require(loops == 0, f"{loops} self-loops reached the interim dataset")
        _require(
            int(frame["label_redteam"].sum()) == report["redteam_matches"], "label count mismatch"
        )
        _require(bool(frame["timestamp"].is_sorted()), "interim is not chronological")
        result.details = {
            "format": self.source_format,
            "rows_read": report.get("rows_read", report.get("parse", {}).get("lines")),
            "rows_parsed": report["rows_parsed"],
            "rows_self_loop": report.get("rows_self_loop", report.get("self_loops_dropped", 0)),
            "rows_sampled_out": report.get("rows_sampled_out", 0),
            "redteam_matches": report["redteam_matches"],
            "timestamp_max": report["timestamp_max"],
            "unique_counts": report["unique_counts"],
            "parquet_files": report["parquet_files"],
            "skipped": report.get("parse", {}).get("skipped"),
            "dataset_sha256": report.get("dataset_sha256"),
        }
        return reused

    def stage_features(self, result: StageResult) -> bool:
        reused = (
            self.feature_report.is_file()
            and any(self.features.rglob("*.parquet"))
            and not self.fresh
        )
        if not reused:
            if self.features.exists():
                shutil.rmtree(self.features)
            self._cli(
                "02_features",
                [
                    "features",
                    "build",
                    "--input",
                    str(self.interim),
                    "--output",
                    str(self.features),
                    "--report",
                    str(self.feature_report),
                ],
            )
        report = _read_json(self.feature_report)
        import polars as pl

        files = sorted(self.features.rglob("*.parquet"))
        rows = sum(pl.scan_parquet(f).select(pl.len()).collect().item() for f in files)
        ingested = _read_json(self.ingestion_report)["rows_parsed"]
        _require(rows == ingested, f"feature rows {rows} != ingested rows {ingested}")
        contract = report.get("feature_contract_sha256") or report.get("contract_sha256")
        result.details = {
            "rows": rows,
            "files": len(files),
            "feature_contract_sha256": contract,
            "feature_version": report.get("feature_version"),
        }
        return bool(reused)

    def stage_baselines(self, result: StageResult) -> bool:
        reused = self.baseline_report.is_file() and not self.fresh
        if not reused:
            self._cli(
                "03_baselines",
                [
                    "evaluate",
                    "baselines",
                    "--input",
                    str(self.features),
                    "--feature-report",
                    str(self.feature_report),
                    "--output",
                    str(self.baseline_report),
                    "--train-fraction",
                    str(self.train_fraction),
                    "--validation-fraction",
                    str(self.validation_fraction),
                ],
            )
        report = _read_json(self.baseline_report)
        models = report.get("models")
        _require(isinstance(models, dict) and models, "baseline report has no models")
        summary = {}
        for name, entry in models.items():
            validation = entry.get("validation", {}) if isinstance(entry, dict) else {}
            summary[name] = validation.get("pr_auc")
        _require(any(v is not None for v in summary.values()), "no baseline validation PR-AUC")
        result.details = {"validation_pr_auc": summary}
        return bool(reused)

    def stage_train(self, result: StageResult) -> bool:
        reused = self.training_report.is_file() and self.checkpoint.is_file() and not self.fresh
        promoted: bool | None = None
        recipe = self._write_model_config()
        if not reused:
            code = self._cli(
                "04_train",
                [
                    "train",
                    "tgn",
                    "--input",
                    str(self.features),
                    "--feature-report",
                    str(self.feature_report),
                    "--checkpoint",
                    str(self.checkpoint),
                    "--report",
                    str(self.training_report),
                    "--baseline-report",
                    str(self.baseline_report),
                    *(
                        ["--raw-manifest-dir", str(self.raw_dir)]
                        if self.source_format == "lanl"
                        else ["--ingestion-report", str(self.ingestion_report)]
                    ),
                    "--epochs",
                    str(self.epochs),
                    "--patience",
                    str(self.patience),
                    "--id-maps",
                    str(self.id_maps),
                    "--device",
                    self.device,
                ],
                ok=(0, 3),
            )
            promoted = code == 0
            if not promoted:
                # The candidate was retained but not promoted (it did not beat
                # the declared baselines). The pipeline check continues with
                # it -- serving a checkpoint is what is being verified -- and
                # the summary says so.
                candidates = sorted(self.models.glob("tgn-production-candidate-*.pt"))
                reports = sorted(self.metrics.glob("tgn_training-candidate-*.json"))
                _require(bool(candidates) and bool(reports), "no candidate checkpoint retained")
                shutil.copyfile(candidates[-1], self.checkpoint)
                shutil.copyfile(reports[-1], self.training_report)
        report = _read_json(self.training_report)
        promotion = report.get("promotion", {})
        if promoted is None:
            promoted = bool(promotion.get("eligible"))

        from graphsentinel.ingestion.id_map import auth_id_map_sha256
        from graphsentinel.models.serving import load_inference_session

        session = load_inference_session(self.checkpoint, device="cpu")
        _require(
            session.provenance.entity_dictionary_sha256 == auth_id_map_sha256(self.id_maps),
            "checkpoint entity dictionary does not match the run's id maps",
        )
        split = report["split"]
        result.details = {
            "promoted": promoted,
            "model_config": str(self.model_config),
            "recipe": {
                "model": recipe.get("model"),
                "training": {
                    k: v
                    for k, v in recipe.get("training", {}).items()
                    if k not in ("epochs", "patience")
                },
                "split": {
                    "train_fraction": self.train_fraction,
                    "validation_fraction": self.validation_fraction,
                },
            },
            "model_version": session.provenance.model_version,
            "epochs_completed": report.get("epochs_completed"),
            "validation_pr_auc": report.get("validation_metrics", {}).get("pr_auc"),
            "test_pr_auc": report.get("test_metrics", {}).get("pr_auc"),
            "promotion": {
                k: promotion.get(k)
                for k in (
                    "model_validation_pr_auc",
                    "best_baseline_validation_pr_auc",
                    "improvement",
                )
            },
            "split": {
                "train_end_index": split["train_end_index"],
                "validation_end_index": split["validation_end_index"],
                "counts": split.get("counts"),
                "positives": split.get("positives"),
            },
        }
        return bool(reused)

    def stage_score(self, result: StageResult) -> bool:
        reused = self.cache.is_file() and not self.fresh
        if not reused:
            log_path = self.logs / "05_score.log"
            command = [
                self.python,
                str(ROOT / "scripts" / "build_scored_cache.py"),
                "--data",
                str(self.features),
                "--checkpoint",
                str(self.checkpoint),
                "--report",
                str(self.training_report),
                "--out",
                str(self.cache),
                "--device",
                self.device,
            ]
            with log_path.open("w", encoding="utf-8") as stream:
                completed = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=self._env(),
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    check=False,
                )
            _require(
                completed.returncode == 0,
                f"scored cache builder exited {completed.returncode}; see {log_path}",
            )
        import polars as pl

        cache = pl.read_parquet(self.cache)
        counts = {
            name: {
                "events": cache.filter(pl.col("partition") == name).height,
                "attacks": int(cache.filter(pl.col("partition") == name)["label"].sum()),
            }
            for name in ("train", "validation", "test")
        }
        _require(counts["test"]["attacks"] > 0, "no attacks in the test partition")
        _require(counts["validation"]["attacks"] > 0, "no attacks in the validation partition")
        result.details = {"rows": cache.height, "partitions": counts}
        return bool(reused)

    def stage_report(self, result: StageResult) -> bool:
        reused = self.evaluation_report.is_file() and not self.fresh
        if not reused:
            self._cli(
                "06_report",
                [
                    "evaluation-report",
                    "--cache",
                    str(self.cache),
                    "--output",
                    str(self.docs),
                    "--resamples",
                    str(self.resamples),
                ],
            )
        report = _read_json(self.evaluation_report)
        detectors = report.get("detectors") or {}
        _require("noisy_or" in detectors, "evaluation report lacks the noisy_or detector")
        production = detectors["noisy_or"]
        result.details = {
            "headline": report.get("headline", {}).get("best_test_pr_auc"),
            "noisy_or_test_pr_auc": production.get("test_pr_auc"),
            "noisy_or_operating_point": production.get("test_operating_point"),
            "detectors": {
                name: (entry.get("test_pr_auc") or {}).get("point")
                for name, entry in detectors.items()
            },
            "markdown": str(self.docs / "EVALUATION_REPORT.md"),
        }
        _require((self.docs / "EVALUATION_REPORT.md").is_file(), "markdown report missing")
        return bool(reused)

    def stage_backfill(self, result: StageResult) -> bool:
        manifest = self.state / "backfill_manifest.json"
        reused = (
            (self.state / "feature_state.json.gz").is_file()
            and (self.state / "tgn_memory.npz").is_file()
            and not self.fresh
        )
        split = _read_json(self.training_report)["split"]
        limit = int(split["validation_end_index"])
        if not reused:
            if self.state.exists():
                shutil.rmtree(self.state)
            self._cli(
                "07_backfill",
                [
                    "backfill",
                    "--input",
                    str(self.features),
                    "--output",
                    str(self.state),
                    "--checkpoint",
                    str(self.checkpoint),
                    "--device",
                    self.device,
                    "--limit",
                    str(limit),
                ],
            )
        _require((self.state / "feature_state.json.gz").is_file(), "feature state missing")
        _require((self.state / "tgn_memory.npz").is_file(), "TGN memory missing")
        details: dict[str, Any] = {"replayed_events": limit}
        if manifest.is_file():
            details["manifest"] = _read_json(manifest)
        else:
            for candidate in self.state.glob("*.json"):
                details["manifest"] = _read_json(candidate)
                break
        result.details = details
        return bool(reused)

    # ------------------------------------------------------------ serving
    def _server_env(self) -> dict[str, str]:
        # The service owns its state files: it restores from them and, on
        # request, saves back to them. They are the run's own copy of the
        # backfill output, so a save never rewrites the backfill artefact
        # and a re-run starts from the same warm state.
        db = self.serve_dir / "graphsentinel.db"
        served_state = self.serve_dir / "state"
        # The alert threshold is the one this run's evaluation report derived
        # for the noisy-OR operator on this run's validation partition, at the
        # 25 FP/10k budget -- what an operator deploying this checkpoint would
        # set. The library default is calibrated for the shipped checkpoint.
        threshold = self.operating_threshold()
        return self._env(
            GRAPHSENTINEL_THRESHOLD=f"{threshold:.6f}",
            GRAPHSENTINEL_CHECKPOINT=str(self.checkpoint),
            GRAPHSENTINEL_TRAINED_CHECKPOINT=str(self.checkpoint),
            GRAPHSENTINEL_TRAINING_REPORT=str(self.training_report),
            GRAPHSENTINEL_ID_MAP_DIR=str(self.id_maps),
            GRAPHSENTINEL_TGN_MEMORY=str(served_state / "tgn_memory.npz"),
            GRAPHSENTINEL_FEATURE_STATE=str(served_state / "feature_state.json.gz"),
            GRAPHSENTINEL_DATABASE=str(db),
            GRAPHSENTINEL_DEVICE="cpu",
            GRAPHSENTINEL_FUSION="noisy_or",
            GRAPHSENTINEL_AUTO_RESPONSE="dry_run",
            GRAPHSENTINEL_RESPONSE_BACKEND="dry_run",
            GRAPHSENTINEL_RAW_DIR=str(self.raw_dir),
            GRAPHSENTINEL_INTERIM_DIR=str(self.interim),
            GRAPHSENTINEL_FEATURE_DIR=str(self.features),
            GRAPHSENTINEL_FEATURE_REPORT=str(self.feature_report),
            GRAPHSENTINEL_INGESTION_REPORT=str(self.ingestion_report),
            GRAPHSENTINEL_BASELINE_REPORT=str(self.baseline_report),
            GRAPHSENTINEL_CANDIDATE_CHECKPOINT=str(self.models / "tgn-candidate.pt"),
            GRAPHSENTINEL_PIPELINE_LEASE=str(self.runtime / "model-pipeline.lease.json"),
            GRAPHSENTINEL_PHASE16_STATE=str(self.runtime / "phase16-state.json"),
            GRAPHSENTINEL_SYNTHETIC_STREAM=str(self.serve_dir / "no-synthetic-stream.parquet"),
        )

    def operating_threshold(self) -> float:
        report = _read_json(self.evaluation_report)
        return float(report["detectors"]["noisy_or"]["threshold"])

    def _start_server(self, log_name: str) -> tuple[subprocess.Popen[bytes], Http]:
        log_path = self.logs / log_name
        stream = log_path.open("w", encoding="utf-8")
        process = subprocess.Popen(
            [
                self.python,
                "-m",
                "graphsentinel.api.run",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--log-level",
                "info",
            ],
            cwd=ROOT,
            env=self._server_env(),
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        http = Http(f"http://127.0.0.1:{self.port}")
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stream.close()
                tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]
                raise StageFailure("API process exited during start-up:\n" + "\n".join(tail))
            try:
                status, _payload = http.get("/health", timeout=5)
                if status == 200:
                    return process, http
            except (urllib.error.URLError, OSError, TimeoutError):
                pass
            time.sleep(1)
        process.terminate()
        stream.close()
        raise StageFailure("API did not answer /health within 240 s")

    @staticmethod
    def _stop_server(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=30)
        if process.stdout is not None:
            process.stdout.close()

    def _test_partition_events(self) -> tuple[list[Any], list[dict[str, Any]]]:
        """The run's own test partition as live gateway events, with the truth
        beside each one (never sent)."""
        import polars as pl

        from graphsentinel.api.schemas import LiveAuthEvent
        from graphsentinel.ingestion.id_map import AuthIdMaps

        maps = AuthIdMaps.load(self.id_maps)
        names = {name: mapping.to_dict()["values"] for name, mapping in maps.items()}
        split = _read_json(self.training_report)["split"]
        start = int(split["validation_end_index"])
        frame = (
            pl.concat([pl.read_parquet(f) for f in sorted(self.features.rglob("*.parquet"))])
            .sort("timestamp", "event_id")
            .slice(start, None)
        )
        if self.live_limit is not None:
            frame = frame.head(self.live_limit)

        def name(kind: str, identifier: int) -> str:
            values = names[kind]
            return "?" if identifier == 0 or identifier >= len(values) else str(values[identifier])

        events: list[LiveAuthEvent] = []
        truth: list[dict[str, Any]] = []
        for row in frame.iter_rows(named=True):
            events.append(
                LiveAuthEvent(
                    timestamp=int(row["timestamp"]),
                    user=name("users", int(row["src_user_id"])),
                    destination_user=name("users", int(row["dst_user_id"])),
                    source_host=name("hosts", int(row["src_host_id"])),
                    destination_host=name("hosts", int(row["dst_host_id"])),
                    auth_type=name("auth_types", int(row["auth_type_id"])),
                    logon_type=name("logon_types", int(row["logon_type_id"])),
                    orientation=name("orientations", int(row["orientation_id"])),
                    success=bool(row["success"]),
                    source="e2e",
                )
            )
            truth.append(
                {
                    "event_id": int(row["event_id"]),
                    "timestamp": int(row["timestamp"]),
                    "src_user_id": int(row["src_user_id"]),
                    "src_host_id": int(row["src_host_id"]),
                    "dst_host_id": int(row["dst_host_id"]),
                    "label": int(row["label_redteam"]),
                }
            )
        return events, truth

    def _stream(self, http: Http, events: list[Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Forward through the product's own adapter, keeping every result."""
        from graphsentinel.live_adapter import LiveApiClient, forward_live_events

        results: list[dict[str, Any]] = []

        class Recording(LiveApiClient):
            def detect(self, batch: tuple[Any, ...]) -> Any:
                response = super().detect(batch)
                _require(len(response.results) == len(batch), "result count != batch size")
                for event, scored in zip(batch, response.results, strict=True):
                    results.append(
                        {
                            "timestamp": event.timestamp,
                            "user": event.user,
                            "source_host": event.source_host,
                            "destination_host": event.destination_host,
                            "alert_id": scored.alert_id,
                            "risk": scored.risk,
                            "alerted": scored.alerted,
                            "threshold": scored.threshold,
                            "severity": scored.severity,
                            "rule_floor": scored.rule_floor,
                            "components": dict(scored.components or {}),
                            "technique": scored.tactic.technique_id if scored.tactic else None,
                            "confidence": scored.tactic.confidence if scored.tactic else None,
                        }
                    )
                return response

        client = Recording(http.base, timeout=300)
        stats = forward_live_events(iter(events), client, max_batch_events=self.batch_events)
        return results, stats

    def _compare_with_offline(
        self, results: list[dict[str, Any]], truth: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Like-for-like: the same events, the deployed path against the cache."""
        import numpy as np
        import polars as pl

        from graphsentinel.detection.fusion import (
            NoisyOrConfig,
            RiskComponents,
            apply_rule_floor,
            fuse_risk,
        )
        from graphsentinel.detection.policy import policy_from_environment
        from graphsentinel.evaluation.metrics import average_precision

        # The served process raises a rule-detected chain to its policy's
        # floor (the execution gate under the unattended policy); the
        # comparison applies the same policy, read from the same environment.
        policy = policy_from_environment()

        cache = pl.read_parquet(self.cache).filter(pl.col("partition") == "test")
        if self.live_limit is not None:
            cache = cache.head(self.live_limit)
        _require(
            cache.height == len(results),
            f"cache test rows {cache.height} != streamed {len(results)}",
        )
        offline = cache.to_dicts()
        for mine, theirs in zip(truth, offline, strict=True):
            _require(
                (mine["timestamp"], mine["src_user_id"], mine["src_host_id"], mine["dst_host_id"])
                == (
                    theirs["timestamp"],
                    theirs["src_user_id"],
                    theirs["src_host_id"],
                    theirs["dst_host_id"],
                ),
                "streamed events and cache rows are not the same events in the same order",
            )
        labels = np.array([t["label"] for t in truth], dtype=np.int64)
        live_risk = np.array([r["risk"] for r in results])
        live = {
            c: np.array([r["components"].get(c, np.nan) for r in results])
            for c in ("tgn", "novelty", "burst", "pivot")
        }
        off = {
            c: np.array([float(o[c]) for o in offline])
            for c in ("tgn", "novelty", "burst", "pivot")
        }
        config = NoisyOrConfig()
        # Like for like: the live risk carries the chain-rule floor, so the
        # offline fusion gets the same floor from the cache's ``chain`` column.
        offline_risk = np.array(
            [
                apply_rule_floor(
                    fuse_risk(
                        RiskComponents(
                            tgn=o["tgn"],
                            novelty=o["novelty"],
                            burst=o["burst"],
                            pivot=o["pivot"],
                            corroboration=0.0,
                        ),
                        config,
                    ),
                    chain_detected=bool(o.get("chain", False)),
                    floor=policy.floor,
                ).score
                for o in offline
            ]
        )
        first_timestamp = truth[0]["timestamp"]
        warmup = np.array([t["timestamp"] - first_timestamp < 1_800 for t in truth])
        chain = np.array([r["rule_floor"] is not None for r in results])
        offline_chain = np.array([bool(o.get("chain", False)) for o in offline])

        def agreement(name: str) -> dict[str, Any]:
            delta = np.abs(live[name] - off[name])
            return {
                "max_abs_delta": float(np.nanmax(delta)) if delta.size else 0.0,
                "share_within_1e-6": float(np.mean(delta <= 1e-6)),
                "share_within_1e-3": float(np.mean(delta <= 1e-3)),
                "events": int(delta.size),
            }

        pivot_delta = np.abs(live["pivot"] - off["pivot"]) > 1e-9
        comparison = {
            "events": len(results),
            "attacks": int(labels.sum()),
            "novelty": agreement("novelty"),
            "burst": agreement("burst"),
            "pivot": {
                **agreement("pivot"),
                "differing": int(pivot_delta.sum()),
                "differing_in_first_30_minutes": int((pivot_delta & warmup).sum()),
                "differing_after_warm_up": int((pivot_delta & ~warmup).sum()),
                "note": (
                    "the signal tracker (chain and recent-destination windows) is not part "
                    "of the warm state, so the live path starts it cold; it converges within "
                    "the 30-minute window and must agree exactly after it"
                ),
            },
            "chain_rule": {
                # ``rule_floor`` is set only when the floor raised the score; a
                # chain event already above the floor keeps its own score on
                # both sides, so the like-for-like check is: every event the
                # offline pass flagged as a chain must sit at or above the
                # floor live, once the tracker is warm.
                "live_events_raised_by_floor": int(chain.sum()),
                "offline_events_flagged": int(offline_chain.sum()),
                "policy": policy.name,
                "floor": policy.floor,
                "flagged_but_below_floor_live_after_warm_up": int(
                    (offline_chain & (live_risk < policy.floor - 1e-9) & ~warmup).sum()
                ),
            },
            "tgn": {
                **agreement("tgn"),
                "note": (
                    "the inference session advances memory per timestamp group on both "
                    "paths, so request and block boundaries do not matter; tolerance 1e-5 "
                    "for floating-point nondeterminism"
                ),
            },
            "fused_risk": {
                "max_abs_delta": float(np.max(np.abs(live_risk - offline_risk))),
                "spearman": _spearman(live_risk, offline_risk),
            },
            "pr_auc": {
                "live": float(average_precision(labels, live_risk)) if labels.sum() else None,
                "offline_same_events": float(average_precision(labels, offline_risk))
                if labels.sum()
                else None,
            },
        }
        return comparison

    def stage_serve(self, result: StageResult) -> bool:
        if self.serve_dir.exists():
            shutil.rmtree(self.serve_dir)
        (self.serve_dir / "state").mkdir(parents=True)
        for name in ("feature_state.json.gz", "tgn_memory.npz"):
            shutil.copyfile(self.state / name, self.serve_dir / "state" / name)
        details: dict[str, Any] = {}
        result.details = details  # filled progressively, so a failure keeps what was measured
        process, http = self._start_server("08_serve.log")
        try:
            status, ready = http.get("/ready")
            _require(status == 200, f"/ready returned {status}: {ready}")
            _require(ready.get("model_loaded") is True, "model not loaded")
            _require(
                ready.get("degraded") in ([], None, ()),
                f"service degraded: {ready.get('degraded')}",
            )
            status, live_status = http.get("/api/v1/live/status")
            _require(live_status["mode"] == "temporal_model", f"live mode {live_status['mode']}")
            _require(
                live_status["frozen_entity_dictionary"] is True, "entity dictionary not frozen"
            )
            status, feature_state = http.get("/api/v1/feature-state")
            _require(feature_state.get("warm") is True, f"service started cold: {feature_state}")
            details["start"] = {
                "ready": ready,
                "threshold": self.operating_threshold(),
                "live_mode": live_status["mode"],
                "feature_state_restored": feature_state["features"].get("restored_from_snapshot"),
                "memory_nodes_warm": feature_state["model_memory"].get("nodes_with_memory"),
            }

            # ---- live detection on the run's own test partition
            events, truth = self._test_partition_events()
            _require(events, "no test events to stream")
            started = time.perf_counter()
            results, stats = self._stream(http, events)
            elapsed = time.perf_counter() - started
            status, live_status = http.get("/api/v1/live/status")
            _require(live_status["accepted_events"] == len(events), "gateway accepted != streamed")
            _require(live_status["rejected_batches"] == 0, "the gateway rejected a batch")
            labels = [t["label"] for t in truth]
            alerted = [r["alerted"] for r in results]
            pairs = list(zip(alerted, labels, strict=True))
            tp = sum(1 for hit, attack in pairs if hit and attack)
            fp = sum(1 for hit, attack in pairs if hit and not attack)
            fn = sum(1 for hit, attack in pairs if not hit and attack)
            details["live"] = {
                "streamed": stats,
                "seconds": round(elapsed, 1),
                "events_per_second": round(len(events) / elapsed, 1) if elapsed else None,
                "threshold": results[0]["threshold"],
                "alerts": sum(alerted),
                "alerts_per_10k": round(10_000 * sum(alerted) / len(alerted), 2),
                "attacks": sum(labels),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                "oov_identifiers": live_status["oov_identifiers"],
            }
            details["agreement"] = self._compare_with_offline(results, truth)
            agreement = details["agreement"]
            for channel in ("novelty", "burst"):
                _require(
                    agreement[channel]["max_abs_delta"] <= 1e-6,
                    f"{channel} differs between the live path and the offline cache "
                    f"(max {agreement[channel]['max_abs_delta']})",
                )
            _require(
                agreement["tgn"]["max_abs_delta"] <= 1e-5,
                f"model probability differs live vs offline "
                f"(max {agreement['tgn']['max_abs_delta']})",
            )
            _require(
                agreement["pivot"]["differing_after_warm_up"] == 0,
                f"pivot differs after the warm-up window on "
                f"{agreement['pivot']['differing_after_warm_up']} events",
            )
            _require(
                agreement["chain_rule"]["flagged_but_below_floor_live_after_warm_up"] == 0,
                "an offline chain event scored below the rule floor live after warm-up",
            )
            _require(
                agreement["fused_risk"]["max_abs_delta"] <= 1e-5,
                f"fused risk differs live vs offline "
                f"(max {agreement['fused_risk']['max_abs_delta']})",
            )

            # ---- alerts persisted
            status, alerts = http.get("/api/v1/alerts?limit=500")
            _require(status == 200, f"/api/v1/alerts returned {status}")
            details["alerts_persisted"] = len(alerts)
            _require(len(alerts) == min(500, sum(alerted)), "persisted alerts != live alerts")

            # ---- automatic response
            status, response_status = http.get("/api/v1/response/status")
            _require(status == 200, "response status unavailable")
            _require(response_status["mode"] == "dry_run", "response mode is not dry_run")
            counts = response_status["counts"]
            if sum(alerted):
                _require(counts["dispatched"] > 0, "alerts were raised but nothing was dispatched")
            status, pending = http.get("/api/v1/response/pending")
            pending = pending["pending"]
            status, executions = http.get("/api/v1/response/executions?limit=1000")
            executions = executions["records"]
            auto = [
                e for e in executions if e["outcome"] == "dry_run" and not e["requires_approval"]
            ]
            details["response"] = {
                "status": response_status,
                "pending": len(pending),
                "executions": len(executions),
                "unattended_dry_runs": len(auto),
                "actions": sorted({e["action"] for e in executions}),
                "with_command": sum(1 for e in executions if e.get("command")),
            }
            approval: dict[str, Any] | None = None
            if pending:
                first = pending[0]
                status, record = http.post(
                    "/api/v1/response/approve",
                    {
                        "alert_id": first["alert_id"],
                        "action": first["action"],
                        "approver": "e2e-pipeline",
                        "note": "end-to-end check",
                    },
                )
                _require(status == 200, f"approval returned {status}: {record}")
                _require(
                    record["outcome"] == "dry_run", f"approved action outcome {record['outcome']}"
                )
                _require(record["approved_by"] == "e2e-pipeline", "approver not recorded")
                approval = {
                    "alert_id": first["alert_id"],
                    "action": first["action"],
                    "outcome": record["outcome"],
                }
                status, per_alert = http.get(f"/api/v1/alerts/{first['alert_id']}/response")
                _require(status == 200, "per-alert response view failed")
                details["response"]["per_alert_view_keys"] = sorted(per_alert)
            details["response"]["approval"] = approval
            status, _refused = http.post("/api/v1/response/mode", {"mode": "armed", "actor": "e2e"})
            _require(status == 409, f"arming a dry-run backend must be refused, got {status}")
            details["response"]["arming_refused"] = True

            # ---- console and research surfaces
            probes = [
                "/",
                "/health",
                "/metrics",
                "/api/v1/overview",
                "/api/v1/graph",
                "/api/v1/paths",
                "/api/v1/entity-risk",
                "/api/v1/drift",
                "/api/v1/tactics",
                "/api/v1/research/summary",
                "/api/v1/data/readiness",
                "/api/v1/training/status",
                "/api/v1/threshold-config",
                "/api/v1/response/status",
                "/api/v1/audit",
                "/api/v1/cases",
                "/api/v1/entity-names",
            ]
            if alerts:
                probes.append(f"/api/v1/kill-chain?alert_ids={alerts[0]['alert_id']}")
                probes.append(f"/alerts/{alerts[0]['alert_id']}")
            surface: dict[str, int] = {}
            for path in probes:
                status, _payload = http.get(path)
                surface[path] = status
            failed = {p: s for p, s in surface.items() if s != 200}
            _require(not failed, f"console endpoints failed: {failed}")
            status, index = http.get("/")
            _require(isinstance(index, str) and "GraphSentinel" in index, "console page missing")
            status, research = http.get("/api/v1/research/summary")
            details["console"] = {
                "endpoints": surface,
                "research_keys": sorted(research) if isinstance(research, dict) else None,
            }

            # ---- persist the advanced state (both halves), then restart on it
            status, saved = http.post("/api/v1/feature-state/save", {})
            _require(status == 200, f"state save returned {status}: {saved}")
            _require(
                saved.get("model_memory") is not None, "the save did not persist the model memory"
            )
            _require(saved.get("warning") is None, f"state save warned: {saved.get('warning')}")
            status, state_before = http.get("/api/v1/feature-state")
            details["state_saved"] = {
                "features_bytes": saved.get("bytes"),
                "memory_nodes_warm": saved["model_memory"].get("nodes_with_memory"),
                "memory_stream_timestamp": saved["model_memory"].get("stream_timestamp"),
            }
            before = {
                "alerts": len(alerts),
                "counts": counts,
                "pending_after_approval": len(http.get("/api/v1/response/pending")[1]["pending"]),
                "feature_coverage": state_before["features"],
                "memory_coverage": state_before["model_memory"],
            }
        finally:
            self._stop_server(process)

        process, http = self._start_server("09_restart.log")
        try:
            status, alerts_after = http.get("/api/v1/alerts?limit=500")
            status, status_after = http.get("/api/v1/response/status")
            status, pending_after = http.get("/api/v1/response/pending")
            pending_after = pending_after["pending"]
            _require(len(alerts_after) == before["alerts"], "alerts did not survive the restart")
            _require(
                status_after["counts"]["dispatched"]
                == before["counts"]["dispatched"] + (1 if approval else 0),
                "dispatch records did not survive the restart",
            )
            _require(
                len(pending_after) == before["pending_after_approval"],
                "pending approvals changed across restart",
            )
            if approval:
                status, _refused = http.post(
                    "/api/v1/response/approve",
                    {
                        "alert_id": approval["alert_id"],
                        "action": approval["action"],
                        "approver": "again",
                    },
                )
                _require(
                    status == 404,
                    f"a settled approval must not be re-approvable after restart, got {status}",
                )
            status, state_after = http.get("/api/v1/feature-state")
            _require(state_after.get("warm") is True, "restarted service is not warm")
            for key in ("known_users", "known_pairs", "known_source_hosts"):
                if key in before["feature_coverage"]:
                    _require(
                        state_after["features"].get(key) == before["feature_coverage"].get(key),
                        f"feature coverage {key} changed across the restart",
                    )
            _require(
                state_after["model_memory"].get("nodes_with_memory")
                == before["memory_coverage"].get("nodes_with_memory"),
                "model memory coverage changed across the restart",
            )
            details["restart"] = {
                "alerts": len(alerts_after),
                "dispatched": status_after["counts"]["dispatched"],
                "pending": len(pending_after),
                "replayed_approval_refused": bool(approval),
                "features_restored": state_after["features"].get("restored_from_snapshot"),
                "memory_nodes_warm": state_after["model_memory"].get("nodes_with_memory"),
            }
        finally:
            self._stop_server(process)
        result.details = details
        return False

    # ------------------------------------------------------------ run
    def run(self) -> dict[str, Any]:
        started = time.time()
        try:
            self._stage("verify", self.stage_verify)
            self._stage("ingest", self.stage_ingest)
            self._stage("features", self.stage_features)
            self._stage("baselines", self.stage_baselines)
            self._stage("train", self.stage_train)
            self._stage("score", self.stage_score)
            self._stage("report", self.stage_report)
            self._stage("backfill", self.stage_backfill)
            self._stage("serve", self.stage_serve)
            outcome = "passed"
        except StageFailure:
            outcome = "failed"
        summary = {
            "outcome": outcome,
            "started_at": int(started),
            "seconds": round(time.time() - started, 1),
            "run_dir": str(self.run_dir),
            "raw_dir": str(self.raw_dir),
            "parameters": {
                "source_format": self.source_format,
                "end_timestamp": self.end_timestamp,
                "sample_stride": self.sample_stride,
                "epochs": self.epochs,
                "patience": self.patience,
                "model_config": str(self.model_config),
                "train_fraction": self.train_fraction,
                "validation_fraction": self.validation_fraction,
                "device": self.device,
                "resamples": self.resamples,
                "live_limit": self.live_limit,
                "batch_events": self.batch_events,
            },
            "environment": {
                "python": platform.python_version(),
                "interpreter": self.python,
                "platform": platform.platform(),
                "torch": _torch_version(),
            },
            "stages": [s.to_dict() for s in self.stages],
        }
        _write_json(self.run_dir / "e2e_summary.json", summary)
        (self.run_dir / "E2E_REPORT.md").write_text(render_summary(summary), encoding="utf-8")
        return summary


def _torch_version() -> str | None:
    try:
        import torch

        cuda = "available" if torch.cuda.is_available() else "unavailable"
        return f"{torch.__version__} (cuda {cuda})"
    except Exception:
        return None


def _spearman(a: Any, b: Any) -> float:
    import numpy as np

    def ranks(x: Any) -> Any:
        order = np.argsort(x, kind="mergesort")
        r = np.empty(len(x), dtype=float)
        r[order] = np.arange(len(x), dtype=float)
        # average ties
        _, inverse, counts = np.unique(x, return_inverse=True, return_counts=True)
        sums = np.zeros(len(counts))
        np.add.at(sums, inverse, r)
        return sums[inverse] / counts[inverse]

    if len(a) < 2:
        return 1.0
    ra, rb = ranks(np.asarray(a)), ranks(np.asarray(b))
    if ra.std() == 0 or rb.std() == 0:
        return 1.0
    return float(np.corrcoef(ra, rb)[0, 1])


def render_summary(summary: dict[str, Any]) -> str:
    lines = [
        "# End-to-end pipeline run",
        "",
        f"**Outcome: {summary['outcome']}** in {summary['seconds'] / 60:.1f} min — "
        f"`{summary['run_dir']}` from `{summary['raw_dir']}`.",
        "",
        "Parameters: " + ", ".join(f"{k}={v}" for k, v in summary["parameters"].items()),
        "",
        f"Environment: Python {summary['environment']['python']}, "
        f"torch {summary['environment']['torch']}, "
        f"{summary['environment']['platform']}",
        "",
        "| Stage | Status | Seconds | Key facts |",
        "|---|---|---:|---|",
    ]
    for stage in summary["stages"]:
        lines.append(
            f"| {stage['name']} | {stage['status']} | {stage['seconds']:.0f} | {_facts(stage)} |"
        )
    failed = [s for s in summary["stages"] if s["status"] == "failed"]
    if failed:
        lines += ["", "## Failure", "", "```", failed[0]["error"] or "", "```"]
    serve = next((s for s in summary["stages"] if s["name"] == "serve"), None)
    if serve and serve["status"] != "failed":
        d = serve["details"]
        live, agreement, response = d["live"], d["agreement"], d["response"]
        lines += [
            "",
            "## Live detection on the run's own test partition",
            "",
            f"- streamed {live['streamed']['events']:,} events in {live['streamed']['batches']} "
            f"requests ({live['seconds']}s, {live['events_per_second']} events/s), "
            f"{live['alerts']} alerts ({live['alerts_per_10k']} per 10k) "
            f"at threshold {live['threshold']}",
            f"- {live['attacks']} labelled attacks in the slice: {live['true_positives']} caught, "
            f"{live['false_negatives']} missed, {live['false_positives']} false alerts "
            f"(precision {live['precision']}, recall {live['recall']})",
            f"- PR-AUC on these events: live {agreement['pr_auc']['live']}, "
            f"offline cache {agreement['pr_auc']['offline_same_events']}",
            "",
            "## Deployed path against the offline evaluation, same events",
            "",
            "| Channel | Max abs delta | Within 1e-6 | Note |",
            "|---|---:|---:|---|",
        ]
        for channel in ("novelty", "burst", "pivot", "tgn"):
            entry = agreement[channel]
            note = entry.get("note", "must agree exactly")
            if channel == "pivot":
                note = (
                    f"{entry['differing']} differ, all within the cold 30-minute window "
                    f"({entry['differing_after_warm_up']} after it)"
                )
            lines.append(
                f"| {channel} | {entry['max_abs_delta']:.2e} | "
                f"{entry['share_within_1e-6']:.1%} | {note} |"
            )
        chain_rule = agreement["chain_rule"]
        lines += [
            f"| fused risk (with rule floor) | "
            f"{agreement['fused_risk']['max_abs_delta']:.2e} | — | "
            f"Spearman {agreement['fused_risk']['spearman']:.4f}; chain rule flagged "
            f"{chain_rule['offline_events_flagged']} events offline, raised the score of "
            f"{chain_rule['live_events_raised_by_floor']} live, "
            f"{chain_rule['flagged_but_below_floor_live_after_warm_up']} "
            f"flagged events below the floor live |",
            "",
            "## Automatic response",
            "",
            f"- mode `{response['status']['mode']}`, {response['executions']} dispatch records, "
            f"{response['unattended_dry_runs']} unattended (dry-run), "
            f"{response['pending']} awaiting approval, "
            f"actions {response['actions']}",
            f"- approval exercised: {response.get('approval')}; arming a dry-run backend refused: "
            f"{response.get('arming_refused')}",
            "",
            "## Restart",
            "",
            f"- {d['restart']}",
        ]
    return "\n".join(lines) + "\n"


def _facts(stage: dict[str, Any]) -> str:
    d = stage.get("details") or {}
    name = stage["name"]
    if name == "ingest" and d:
        return (
            f"{d['rows_read']:,} raw rows read, {d['rows_parsed']:,} kept, "
            f"{d['rows_self_loop']:,} local logons dropped, {d['redteam_matches']} red-team"
        )
    if name == "features" and d:
        contract = str(d.get("feature_contract_sha256"))[:12]
        return f"{d['rows']:,} rows, {d['files']} files, contract {contract}"
    if name == "baselines" and d:
        return ", ".join(
            f"{k} {v:.4f}" if isinstance(v, float) else f"{k} {v}"
            for k, v in d["validation_pr_auc"].items()
        )
    if name == "train" and d:
        return (
            f"{d['model_version']}, promoted={d['promoted']}, val PR-AUC {d['validation_pr_auc']}, "
            f"test PR-AUC {d['test_pr_auc']}, {d['epochs_completed']} epochs"
        )
    if name == "score" and d:
        p = d["partitions"]
        return ", ".join(f"{k} {v['events']:,}/{v['attacks']}" for k, v in p.items())
    if name == "report" and d:
        pr = d.get("noisy_or_test_pr_auc") or {}
        return f"noisy_or test PR-AUC {pr.get('point')} {pr.get('ci95')}, best {d.get('headline')}"
    if name == "backfill" and d:
        return f"{d['replayed_events']:,} events replayed"
    if name == "serve" and d:
        live = d.get("live", {})
        events = live.get("streamed", {}).get("events", 0)
        return f"{events:,} live events, {live.get('alerts')} alerts"
    if name == "verify" and d:
        return ", ".join(d.get("files", []))
    return ""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw/lanl"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="write a small synthetic LANL-format corpus into --raw-dir first",
    )
    parser.add_argument("--synthetic-seed", type=int, default=7)
    parser.add_argument(
        "--source-format",
        default="lanl",
        help="lanl, or a source adapter (ssh-auth, windows-json, zeek, tabular); with "
        "--synthetic the corpus is rendered in that format and ingested through it",
    )
    parser.add_argument(
        "--source-input",
        type=Path,
        action="append",
        default=[],
        help="log file(s) for a non-LANL --source-format",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=None,
        help="time,user,src,dst CSV of known attacks for a non-LANL source",
    )
    parser.add_argument("--map", dest="column_map", default=None, help="tabular column map")
    parser.add_argument("--end-timestamp", type=int, default=None)
    parser.add_argument("--sample-stride", type=int, default=1)
    parser.add_argument("--epochs", type=int, default=6)
    parser.add_argument("--patience", type=int, default=3)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--port", type=int, default=0, help="0 picks a free port")
    parser.add_argument("--resamples", type=int, default=500)
    parser.add_argument(
        "--live-limit", type=int, default=None, help="stream only the first N test events"
    )
    parser.add_argument("--batch-events", type=int, default=500)
    parser.add_argument(
        "--model-config",
        type=Path,
        default=Path("configs/model_tgn_v3_high_accuracy.yaml"),
        help="training recipe; its split fractions are replaced by "
        "--train-fraction/--validation-fraction",
    )
    parser.add_argument("--train-fraction", type=float, default=0.70)
    parser.add_argument("--validation-fraction", type=float, default=0.15)
    parser.add_argument("--fresh", action="store_true", help="rebuild every stage")
    args = parser.parse_args(argv)

    raw_dir = args.raw_dir
    source_inputs: list[Path] = list(args.source_input)
    labels_path: Path | None = args.labels
    column_map: str | None = args.column_map
    if args.synthetic:
        from graphsentinel.simulation.rawcorpus import RawCorpusSpec, write_synthetic_lanl_corpus

        raw_dir = args.raw_dir if args.raw_dir != Path("data/raw/lanl") else args.run_dir / "raw"
        manifest = raw_dir / "manifest.json"
        if args.fresh or not manifest.is_file():
            if raw_dir.exists():
                shutil.rmtree(raw_dir)
            summary = write_synthetic_lanl_corpus(raw_dir, RawCorpusSpec(seed=args.synthetic_seed))
            print(
                f"synthetic corpus: {summary.rows:,} rows, {summary.redteam_rows} red-team, "
                f"{summary.self_loops:,} local logons -> {raw_dir}"
            )
            _write_json(raw_dir / "synthetic_corpus.json", summary.to_dict())
            command = [
                sys.executable,
                "-m",
                "graphsentinel",
                "dataset",
                "verify",
                "--require",
                "core",
                "--raw-dir",
                str(raw_dir),
                "--full-scan",
            ]
            completed = subprocess.run(
                command, cwd=ROOT, check=False, capture_output=True, text=True
            )
            if completed.returncode != 0:
                print(completed.stdout + completed.stderr)
                return 2
        if args.source_format != "lanl":
            from graphsentinel.simulation.rawcorpus import TABULAR_MAP, write_corpus_as

            rendered = write_corpus_as(raw_dir, args.source_format, args.run_dir / "raw_source")
            source_inputs = [rendered["log"]]
            labels_path = rendered["labels"]
            if args.source_format == "tabular":
                column_map = TABULAR_MAP
            print(f"rendered the corpus as {args.source_format}: {rendered['log']}")

    pipeline = Pipeline(
        raw_dir=raw_dir,
        run_dir=args.run_dir,
        end_timestamp=args.end_timestamp,
        sample_stride=args.sample_stride,
        epochs=args.epochs,
        patience=args.patience,
        device=args.device,
        port=args.port or _free_port(),
        fresh=args.fresh,
        resamples=args.resamples,
        live_limit=args.live_limit,
        batch_events=args.batch_events,
        model_config=args.model_config,
        train_fraction=args.train_fraction,
        validation_fraction=args.validation_fraction,
        source_format=args.source_format,
        source_inputs=tuple(source_inputs),
        labels_path=labels_path,
        column_map=column_map,
    )
    summary = pipeline.run()
    print()
    print(render_summary(summary))
    return 0 if summary["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
