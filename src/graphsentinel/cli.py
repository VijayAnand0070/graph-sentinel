"""Command-line interface for reproducible GraphSentinel workflows."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from graphsentinel import __version__
from graphsentinel.datasets.catalog import LANL_SOURCE_PAGE
from graphsentinel.datasets.integrity import ValidationResult
from graphsentinel.datasets.registry import (
    RegistrationError,
    execute_registration,
    plan_registration,
    verified_manifest_dataset_sha256,
    verify_registered,
)
from graphsentinel.evaluation.experiments import (
    BaselineExperimentConfig,
    run_baselines_from_dataset,
)
from graphsentinel.features.pipeline import build_feature_dataset
from graphsentinel.ingestion.auth import ingest_auth
from graphsentinel.sources import DESCRIPTIONS as SOURCE_DESCRIPTIONS
from graphsentinel.sources import FORMATS as SOURCE_FORMATS
from graphsentinel.training_status import write_external_training_status

DEFAULT_RAW_DIR = Path("data/raw/lanl")


def _add_validation_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--require", choices=("core", "all"), default="core")
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--full-scan", action="store_true")
    parser.add_argument("--quick-scan-rows", type=int, default=10_000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="graphsentinel")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("doctor", help="Show runtime and project diagnostics")

    dataset = commands.add_parser("dataset", help="Manage raw datasets")
    dataset_commands = dataset.add_subparsers(dest="dataset_command", required=True)

    register = dataset_commands.add_parser("register", help="Register downloaded LANL files")
    register.add_argument("--source", type=Path, required=True)
    register.add_argument(
        "--execute",
        action="store_true",
        help="Perform the copy; without this flag the command is a dry run",
    )
    _add_validation_options(register)

    verify = dataset_commands.add_parser("verify", help="Audit files already in raw storage")
    _add_validation_options(verify)

    hub_push = dataset_commands.add_parser(
        "hub-push", help="Store verified LANL core files in a private Hugging Face dataset"
    )
    hub_push.add_argument("--repo-id", required=True, help="username-or-org/repository-name")
    hub_push.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    hub_push.add_argument("--revision", default="main")

    hub_pull = dataset_commands.add_parser(
        "hub-pull", help="Download and hash-verify LANL core files from private Hub storage"
    )
    hub_pull.add_argument("--repo-id", required=True, help="username-or-org/repository-name")
    hub_pull.add_argument("--destination", type=Path, required=True)
    hub_pull.add_argument("--revision", default="main")

    ingest = commands.add_parser("ingest", help="Create normalized interim datasets")
    ingest_commands = ingest.add_subparsers(dest="ingest_command", required=True)
    ingest_auth_parser = ingest_commands.add_parser(
        "auth", help="Stream LANL authentication records to Parquet"
    )
    ingest_auth_parser.add_argument("--auth", type=Path, default=DEFAULT_RAW_DIR / "auth.txt.gz")
    ingest_auth_parser.add_argument(
        "--redteam", type=Path, default=DEFAULT_RAW_DIR / "redteam.txt.gz"
    )
    ingest_auth_parser.add_argument("--output", type=Path, default=Path("data/interim"))
    ingest_auth_parser.add_argument("--id-maps", type=Path, default=Path("artifacts/id_maps"))
    ingest_auth_parser.add_argument(
        "--report", type=Path, default=Path("artifacts/reports/ingestion_auth.json")
    )
    ingest_auth_parser.add_argument("--chunk-rows", type=int, default=250_000)
    ingest_auth_parser.add_argument(
        "--sample-stride",
        type=int,
        default=1,
        help="Keep every Nth normal event while retaining all red-team events",
    )
    ingest_auth_parser.add_argument(
        "--end-timestamp",
        type=int,
        help="Stop at this inclusive LANL timestamp; input is chronological",
    )
    ingest_auth_parser.add_argument(
        "--keep-self-loops",
        action="store_true",
        help=(
            "Keep events whose source and destination host are the same. The live "
            "gateway refuses them, so keeping them trains on traffic production never "
            "sees; only for reproducing corpora built before they were dropped"
        ),
    )

    ingest_logs_parser = ingest_commands.add_parser(
        "logs",
        help=(
            "Normalize any supported authentication log (Windows JSON, sshd, Zeek, Entra, "
            "Okta, CSV/JSONL) to the same interim dataset"
        ),
    )
    ingest_logs_parser.add_argument(
        "--format",
        required=True,
        help="auto (sniff it) or one of: " + ", ".join(sorted(SOURCE_FORMATS)),
    )
    ingest_logs_parser.add_argument(
        "--input", type=Path, action="append", required=True, help="log file (repeatable; .gz ok)"
    )
    ingest_logs_parser.add_argument("--output", type=Path, default=Path("data/interim"))
    ingest_logs_parser.add_argument("--id-maps", type=Path, default=Path("artifacts/id_maps"))
    ingest_logs_parser.add_argument(
        "--report", type=Path, default=Path("artifacts/reports/ingestion_logs.json")
    )
    ingest_logs_parser.add_argument(
        "--labels", type=Path, default=None,
        help="CSV of known-attack events as time,user,src_host,dst_host (plain or .gz)",
    )
    ingest_logs_parser.add_argument(
        "--map", dest="column_map", default=None,
        help=(
            "tabular format only: field=column,... (see `graphsentinel sources describe tabular`)."
            " With --format auto this overrides the inferred map"
        ),
    )
    ingest_logs_parser.add_argument(
        "--assume-year", type=int, default=None,
        help="year for year-less syslog stamps (ssh-auth, tabular)",
    )
    ingest_logs_parser.add_argument("--chunk-rows", type=int, default=250_000)

    sources = commands.add_parser("sources", help="List or describe supported log formats")
    sources_commands = sources.add_subparsers(dest="sources_command", required=True)
    sources_commands.add_parser("list", help="Formats the ingest and live forwarder accept")
    describe = sources_commands.add_parser("describe", help="Show a sample of one format")
    describe.add_argument("format")
    sniff_parser = sources_commands.add_parser(
        "sniff",
        help="Work out what a log file is, and the column map it would be read with",
    )
    sniff_parser.add_argument("input", type=Path, nargs="+", help="log file(s); .gz ok")
    sniff_parser.add_argument(
        "--lines", type=int, default=200, help="how many lines to sample (default 200)"
    )
    sniff_parser.add_argument("--json", action="store_true", help="machine-readable output")

    soc = commands.add_parser(
        "soc-report",
        help="Write the SOC handover report for one account from a durable store",
    )
    soc.add_argument(
        "--database",
        type=Path,
        required=True,
        help="the alert/response SQLite database (GRAPHSENTINEL_DATABASE)",
    )
    soc.add_argument("--account", help="account to report on; omit to list candidates")
    soc.add_argument(
        "--out", type=Path, default=None, help="write Markdown here instead of stdout"
    )
    soc.add_argument("--json", action="store_true", help="emit the report as JSON")
    soc.add_argument(
        "--agent",
        action="store_true",
        help="write it with the local model (needs Ollama); otherwise deterministic",
    )

    features = commands.add_parser("features", help="Build leakage-safe feature datasets")
    feature_commands = features.add_subparsers(dest="feature_command", required=True)
    feature_build = feature_commands.add_parser(
        "build", help="Build causal features and a security EDA report"
    )
    feature_build.add_argument("--input", type=Path, default=Path("data/interim"))
    feature_build.add_argument("--output", type=Path, default=Path("data/processed/features_v1"))
    feature_build.add_argument(
        "--report", type=Path, default=Path("artifacts/reports/features_v1.json")
    )
    feature_build.add_argument("--chunk-rows", type=int, default=100_000)

    evaluate_report = commands.add_parser(
        "evaluation-report",
        help="Regenerate the evaluation report with bootstrap confidence intervals",
    )
    evaluate_report.add_argument(
        "--cache", type=Path, required=True,
        help="Parquet of per-event channel values and labels",
    )
    evaluate_report.add_argument("--output", type=Path, default=Path("docs"))
    evaluate_report.add_argument("--resamples", type=int, default=2_000)
    evaluate_report.add_argument("--seed", type=int, default=1729)

    backfill = commands.add_parser(
        "backfill",
        help="Build warm deployment state (feature engine + model memory) from historical logs",
    )
    backfill.add_argument(
        "--input", type=Path, required=True,
        help="Processed feature parquet directory or file to replay",
    )
    backfill.add_argument(
        "--output", type=Path, default=Path("artifacts/state"),
        help="Directory to write feature_state.json.gz, tgn_memory.npz and the manifest",
    )
    backfill.add_argument(
        "--checkpoint", type=Path, default=None,
        help="Model checkpoint; omit to build feature state only",
    )
    backfill.add_argument("--device", default="cpu")
    backfill.add_argument(
        "--limit", type=int, default=None,
        help="Replay only the first N events (for a quick dry run)",
    )

    onboard = commands.add_parser(
        "onboard",
        help=(
            "Calibrate the label-free model on a new estate's own historical logs "
            "(no labels): feature scaling, warm memory, alert/action budgets"
        ),
    )
    onboard.add_argument("--features", type=Path, required=True,
                         help="feature parquet built from the estate's logs (ingest logs + features build)")
    onboard.add_argument("--id-maps", type=Path, required=True, help="the estate's id maps from ingest")
    onboard.add_argument("--checkpoint", type=Path, required=True, help="transfer-model checkpoint")
    onboard.add_argument("--output", type=Path, default=Path("artifacts/onboarding"))
    onboard.add_argument("--alert-budget", type=float, default=1e-5,
                         help="share of ordinary events allowed to alert (1e-5 = 10 per million)")
    onboard.add_argument("--action-budget", type=float, default=1e-6,
                         help="share of ordinary events allowed an unattended action")
    onboard.add_argument("--device", default="cpu")
    onboard.add_argument("--limit", type=int, default=None)
    onboard.add_argument("--tgn-only", action="store_true",
                         help="serve the network's score alone instead of mean(tgn, rarity, isolation forest)")

    evaluate = commands.add_parser("evaluate", help="Run reproducible detector experiments")
    evaluate_commands = evaluate.add_subparsers(dest="evaluate_command", required=True)
    baselines = evaluate_commands.add_parser(
        "baselines", help="Run E1/E2 chronological baseline experiments"
    )
    baselines.add_argument("--input", type=Path, default=Path("data/processed/features_v1"))
    baselines.add_argument(
        "--feature-report",
        type=Path,
        default=Path("artifacts/reports/features_v1.json"),
    )
    baselines.add_argument(
        "--output", type=Path, default=Path("artifacts/metrics/baselines_v1.json")
    )
    baselines.add_argument("--max-events", type=int)
    baselines.add_argument("--train-fraction", type=float, default=0.70)
    baselines.add_argument("--validation-fraction", type=float, default=0.15)
    baselines.add_argument("--false-positives-per-10000", type=float, default=25)
    baselines.add_argument("--seed", type=int, default=1729)
    baselines.add_argument("--isolation-forest-estimators", type=int, default=200)

    train = commands.add_parser("train", help="Train deployable temporal graph models")
    train_commands = train.add_subparsers(dest="train_command", required=True)
    train_tgn = train_commands.add_parser("tgn", help="Train and evaluate a TGN checkpoint")
    train_tgn.add_argument("--input", type=Path, default=Path("data/processed/features_v1"))
    train_tgn.add_argument(
        "--feature-report", type=Path, default=Path("artifacts/reports/features_v1.json")
    )
    train_tgn.add_argument(
        "--checkpoint", type=Path, default=Path("artifacts/models/tgn-production.pt")
    )
    train_tgn.add_argument(
        "--report", type=Path, default=Path("artifacts/metrics/tgn_training.json")
    )
    train_tgn.add_argument(
        "--baseline-report",
        type=Path,
        default=Path("artifacts/metrics/baselines_v1.json"),
    )
    train_tgn.add_argument(
        "--raw-manifest-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="Raw directory containing the full-scan provenance manifest",
    )
    train_tgn.add_argument(
        "--ingestion-report",
        type=Path,
        default=None,
        help=(
            "an `ingest logs` report; its dataset_sha256 is the provenance digest, "
            "instead of the LANL raw manifest"
        ),
    )
    train_tgn.add_argument("--epochs", type=int, default=12)
    train_tgn.add_argument("--patience", type=int, default=3)
    train_tgn.add_argument("--max-events", type=int)
    train_tgn.add_argument("--id-maps", type=Path, default=Path("artifacts/id_maps"))
    train_tgn.add_argument("--device", choices=("cpu", "cuda"), default="cpu")

    live = commands.add_parser("live", help="Forward live normalized authentication telemetry")
    live.add_argument("--input", type=Path, required=True, help="Append-only JSONL event source")
    live.add_argument(
        "--format", default="jsonl",
        help=(
            "jsonl (the gateway's own events), auto (sniff it), or any source format "
            "from `sources list`"
        ),
    )
    live.add_argument("--map", dest="column_map", default=None, help="tabular format column map")
    live.add_argument("--assume-year", type=int, default=None)
    live.add_argument("--api-url", default="http://127.0.0.1:8000")
    live.add_argument("--api-key")
    live.add_argument("--max-batch-events", type=int, default=1_000)
    live.add_argument("--follow", action="store_true")
    live.add_argument("--poll-seconds", type=float, default=0.5)
    return parser


def _soc_report(args: argparse.Namespace) -> int:
    """One account, every alert on it, what ran, what waits -- from the store.

    Reads the durable database the API writes, so a report can be produced
    from a shift that has already ended, on a machine that is not serving.
    """
    import sqlite3

    from graphsentinel.api.schemas import AlertRecord
    from graphsentinel.explain.soc_report import (
        DeterministicSocReportProvider,
        build_soc_incident_bundle,
        report_to_json,
    )
    from graphsentinel.response.store import SQLiteResponseStore

    if not args.database.is_file():
        print(f"error: {args.database} does not exist", file=sys.stderr)
        return 2
    connection = sqlite3.connect(f"file:{args.database}?mode=ro", uri=True)
    try:
        rows = connection.execute("SELECT payload_json FROM alerts").fetchall()
    except sqlite3.DatabaseError as error:
        print(f"error: {args.database} is not a GraphSentinel database ({error})", file=sys.stderr)
        return 2
    finally:
        connection.close()
    alerts = [AlertRecord.model_validate_json(row[0]) for row in rows]
    if not alerts:
        print(f"error: no alerts in {args.database}", file=sys.stderr)
        return 2

    by_account: dict[str, list[AlertRecord]] = {}
    for alert in alerts:
        by_account.setdefault(alert.evidence.event.user, []).append(alert)

    if not args.account:
        ranked = sorted(
            by_account.items(), key=lambda kv: max(a.risk for a in kv[1]), reverse=True
        )
        print(f"{len(ranked)} accounts with alerts in {args.database.name}:")
        for account, account_alerts in ranked[:20]:
            print(
                f"  {account:<28} {len(account_alerts):>4} alerts  "
                f"peak risk {max(a.risk for a in account_alerts):.4f}"
            )
        print("\nRe-run with --account to write one account's report.")
        return 0

    mine = by_account.get(args.account)
    if not mine:
        print(f"error: no alerts for {args.account}", file=sys.stderr)
        return 2
    alert_ids = {a.alert_id for a in mine}
    store = SQLiteResponseStore(args.database)
    try:
        records = [r for r in store.all_records() if r.alert_id in alert_ids]
    finally:
        store.close()
    escalation = next(
        (
            r
            for r in records
            if r.action == "lock_account" and r.authority == "escalation"
        ),
        None,
    )
    bundle = build_soc_incident_bundle(
        args.account,
        mine,
        records,
        escalation=(
            argparse.Namespace(
                reason=escalation.output or "the containment did not hold",
                at=escalation.timestamp,
                action=escalation.action,
                revert_at=None,
                kept_by=None,
            )
            if escalation is not None
            else None
        ),
    )
    if args.agent:
        from graphsentinel.explain.soc_report import LangGraphSocReportProvider

        provider: object = LangGraphSocReportProvider()
    else:
        provider = DeterministicSocReportProvider()
    report = provider.generate(bundle)  # type: ignore[attr-defined]
    used_fallback = bool(getattr(provider, "used_fallback", False))
    text = report_to_json(report) if args.json else report.to_markdown()
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"{args.out} ({len(bundle.facts)} facts, severity {bundle.severity})")
    else:
        print(text)
    if args.agent and used_fallback:
        print(
            "note: the model could not ground its output; the deterministic "
            "report was written instead",
            file=sys.stderr,
        )
    return 0


def _results_summary(manifest: Path, results: Sequence[ValidationResult]) -> None:
    print(f"manifest: {manifest}")
    for result in results:
        values = result.to_dict()
        print(
            json.dumps(
                {
                    "file": values["file"],
                    "validation_level": values["validation_level"],
                    "rows_examined": values["rows_examined"],
                    "malformed_rows": values["malformed_rows"],
                    "timestamps_non_decreasing": values["timestamps_non_decreasing"],
                    "sha256": values["sha256"],
                },
                sort_keys=True,
            )
        )


def _dataset_digest(ingestion_report: Path | None, raw_manifest_dir: Path) -> str:
    """The dataset's provenance digest: from an `ingest logs` report when one
    is given (any source format), else from the verified LANL raw manifest."""
    if ingestion_report is None:
        return verified_manifest_dataset_sha256(raw_manifest_dir, "core")
    payload = json.loads(ingestion_report.read_text(encoding="utf-8"))
    digest = payload.get("dataset_sha256") if isinstance(payload, dict) else None
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError(f"{ingestion_report} carries no dataset_sha256; is it an `ingest logs` report?")
    return digest


def _doctor() -> int:
    details = {
        "graphsentinel": __version__,
        "python": platform.python_version(),
        "python_supported": (3, 11) <= sys.version_info[:2] < (3, 14),
        "platform": platform.platform(),
        "working_directory": str(Path.cwd()),
        "raw_directory": str(DEFAULT_RAW_DIR.resolve()),
        "lanl_source": LANL_SOURCE_PAGE,
    }
    print(json.dumps(details, indent=2, sort_keys=True))
    return 0 if details["python_supported"] else 1


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "doctor":
        return _doctor()

    if args.command == "soc-report":
        return _soc_report(args)

    if args.command == "sources":
        from graphsentinel.sources import adapter_for

        if args.sources_command == "list":
            for name in sorted(SOURCE_FORMATS):
                print(f"{name:<15} {SOURCE_DESCRIPTIONS[name]}")
            print(f"{'lanl':<15} the research corpus, through `ingest auth`")
            print(f"{'auto':<15} whichever of these a file turns out to be (`sources sniff`)")
            return 0

        if args.sources_command == "sniff":
            from graphsentinel.sources.detect import UnknownLogFormat, sniff_path

            # Every file is reported, then the exit code: a directory where
            # one file in ten is something else should print the nine.
            detections = {}
            failures = {}
            for path in args.input:
                try:
                    detections[path] = sniff_path(path, sample_lines=args.lines)
                except (OSError, UnknownLogFormat) as error:
                    failures[path] = str(error)
            if args.json:
                print(json.dumps(
                    {
                        **{str(p): d.to_dict() for p, d in detections.items()},
                        **{str(p): {"error": e} for p, e in failures.items()},
                    },
                    indent=2, sort_keys=True,
                ))
                return 2 if failures else 0
            for path, error in failures.items():
                print(f"{path.name}: cannot identify this log", file=sys.stderr)
                print(f"  {error}", file=sys.stderr)
            for path, detection in detections.items():
                print(f"{path.name}: {detection.format} (confidence {detection.confidence:.2f}, "
                      f"{detection.lines_sampled} lines sampled)")
                for reason in detection.reasons:
                    print(f"  + {reason}")
                for warning in detection.warnings:
                    print(f"  ! {warning}")
                if detection.column_map:
                    print(f'  --map "{detection.column_map}"')
                print(f"  ingest: graphsentinel ingest logs --format auto --input {path}")
            return 2 if failures else 0
        from graphsentinel.sources.tabular import TabularAuthLog

        try:
            adapter = adapter_for(
                args.format,
                column_map=TabularAuthLog.sample_map if args.format == "tabular" else None,
            )
        except ValueError as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(f"{adapter.name}: {adapter.description}")
        if args.format == "tabular":
            print(f'--map "{TabularAuthLog.sample_map}"')
        print()
        print(adapter.sample, end="")
        return 0

    if args.command == "ingest" and args.ingest_command == "logs":
        from graphsentinel.ingestion.generic import ingest_logs

        try:
            logs_report = ingest_logs(
                format_name=args.format,
                inputs=args.input,
                output_dir=args.output,
                id_map_dir=args.id_maps,
                report_path=args.report,
                labels_path=args.labels,
                column_map=args.column_map,
                assume_year=args.assume_year,
                chunk_rows=args.chunk_rows,
            )
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(logs_report.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "ingest":
        try:
            report = ingest_auth(
                auth_path=args.auth,
                redteam_path=args.redteam,
                output_dir=args.output,
                id_map_dir=args.id_maps,
                report_path=args.report,
                chunk_rows=args.chunk_rows,
                sample_stride=args.sample_stride,
                end_timestamp=args.end_timestamp,
                drop_self_loops=not args.keep_self_loops,
            )
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "features":
        try:
            feature_report = build_feature_dataset(
                input_dir=args.input,
                output_dir=args.output,
                report_path=args.report,
                chunk_rows=args.chunk_rows,
            )
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(feature_report.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "evaluation-report":
        from graphsentinel.evaluation.report import write_report

        written = write_report(args.cache, args.output,
                               resamples=args.resamples, seed=args.seed)
        for kind, path in written.items():
            print(f"wrote {kind}: {path}")
        return 0

    if args.command == "onboard":
        from graphsentinel.onboarding.backfill import events_from_parquet
        from graphsentinel.onboarding.calibrate import run_onboarding

        def _step(stage: str, count: int) -> None:
            print(f"  {stage}: {count:,} events", flush=True)

        result = run_onboarding(
            events_from_parquet(args.features, limit=args.limit),
            id_maps_dir=args.id_maps,
            checkpoint=args.checkpoint,
            output_dir=args.output,
            alert_budget=args.alert_budget,
            action_budget=args.action_budget,
            device=args.device,
            progress=_step,
            ensemble=not args.tgn_only,
        )
        print(json.dumps(result.to_dict(), indent=2))
        out = result.output_dir
        print()
        print("Start the API with:")
        print(f"  GRAPHSENTINEL_CHECKPOINT={args.checkpoint}")
        print(f"  GRAPHSENTINEL_DEPLOYMENT_PROFILE={result.profile_path}")
        print(f"  GRAPHSENTINEL_FEATURE_STATE={out / 'feature_state.json.gz'}")
        print(f"  GRAPHSENTINEL_TGN_MEMORY={out / 'transfer_memory.pt'}")
        print(f"  GRAPHSENTINEL_ID_MAPS={out / 'id_maps'}")
        return 0

    if args.command == "backfill":
        from graphsentinel.onboarding import run_backfill

        def _progress(count: int) -> None:
            print(f"  replayed {count:,} events", flush=True)

        print(f"replaying {args.input} ...", flush=True)
        result = run_backfill(
            args.input,
            args.output,
            checkpoint=args.checkpoint,
            device=args.device,
            limit=args.limit,
            progress=_progress,
        )
        print(json.dumps(result.to_dict(), indent=2))
        hint = [f"  GRAPHSENTINEL_FEATURE_STATE={result.feature_state_path}"]
        if result.tgn_memory_path:
            hint.append(f"  GRAPHSENTINEL_TGN_MEMORY={result.tgn_memory_path}")
        print()
        print("Restore on start with:")
        for line in hint:
            print(line)
        return 0

    if args.command == "evaluate":
        try:
            experiment_report = run_baselines_from_dataset(
                input_dir=args.input,
                feature_report_path=args.feature_report,
                output_path=args.output,
                max_events=args.max_events,
                config=BaselineExperimentConfig(
                    train_fraction=args.train_fraction,
                    validation_fraction=args.validation_fraction,
                    false_positives_per_10000_budget=(args.false_positives_per_10000),
                    seed=args.seed,
                    isolation_forest_estimators=(args.isolation_forest_estimators),
                ),
            )
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(experiment_report.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "train":
        from graphsentinel.ingestion.id_map import auth_id_map_sha256
        from graphsentinel.models.config import load_tgn_training_config
        from graphsentinel.models.serving import load_inference_session
        from graphsentinel.models.training_pipeline import train_tgn_from_dataset

        run_id = uuid4().hex[:12]
        candidate = args.checkpoint.with_name(
            f"{args.checkpoint.stem}-candidate-{run_id}{args.checkpoint.suffix}"
        )
        candidate_report = args.report.with_name(
            f"{args.report.stem}-candidate-{run_id}{args.report.suffix}"
        )
        train_started_at = int(time.time())
        try:
            dataset_sha256 = _dataset_digest(args.ingestion_report, args.raw_manifest_dir)
            write_external_training_status(
                state="running",
                epoch=0,
                total_epochs=args.epochs,
                message="Loading chronological feature dataset",
                started_at=train_started_at,
                checkpoint_path=str(candidate),
                report_path=str(candidate_report),
            )

            def _progress(
                epoch: int, epochs: int, loss: float, pr_auc: float | None
            ) -> None:
                metric = "n/a" if pr_auc is None else f"{pr_auc:.6f}"
                print(
                    f"epoch {epoch}/{epochs} train_loss={loss:.6f} validation_pr_auc={metric}",
                    flush=True,
                )
                write_external_training_status(
                    state="running",
                    epoch=epoch,
                    total_epochs=epochs,
                    train_loss=loss,
                    validation_pr_auc=pr_auc,
                    message=f"Training epoch {epoch} of {epochs}",
                    started_at=train_started_at,
                    checkpoint_path=str(candidate),
                    report_path=str(candidate_report),
                )

            training_report = train_tgn_from_dataset(
                input_dir=args.input,
                feature_report_path=args.feature_report,
                checkpoint_path=candidate,
                report_path=candidate_report,
                max_events=args.max_events,
                id_map_dir=args.id_maps,
                baseline_report_path=args.baseline_report,
                dataset_sha256=dataset_sha256,
                config=load_tgn_training_config(epochs=args.epochs, patience=args.patience),
                device=args.device,
                progress=_progress,
            )
            if not bool(training_report.promotion["eligible"]):
                print(json.dumps(training_report.to_dict(), indent=2, sort_keys=True))
                print(
                    "error: candidate did not pass the baseline-improvement promotion gate; "
                    f"retained at {candidate}",
                    file=sys.stderr,
                )
                write_external_training_status(
                    state="rejected",
                    epoch=training_report.epochs_completed,
                    total_epochs=args.epochs,
                    message="Candidate retained but not promoted: did not beat declared baselines",
                    started_at=train_started_at,
                    completed_at=int(time.time()),
                    checkpoint_path=str(candidate),
                    report_path=str(candidate_report),
                )
                return 3
            session = load_inference_session(candidate, device=args.device)
            if session.provenance.entity_dictionary_sha256 != auth_id_map_sha256(args.id_maps):
                raise ValueError("candidate entity dictionary does not match the current ID maps")
            args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.checkpoint.with_name(f".{args.checkpoint.name}.tmp")
            rollback = args.checkpoint.with_name(f".{args.checkpoint.name}.rollback")
            had_previous = args.checkpoint.is_file()
            if had_previous:
                shutil.copyfile(args.checkpoint, rollback)
            try:
                shutil.copyfile(candidate, temporary)
                os.replace(temporary, args.checkpoint)
                load_inference_session(args.checkpoint, device=args.device)
            except Exception:
                if had_previous:
                    os.replace(rollback, args.checkpoint)
                else:
                    args.checkpoint.unlink(missing_ok=True)
                raise
            finally:
                temporary.unlink(missing_ok=True)
            rollback.unlink(missing_ok=True)
            published_report = training_report.to_dict()
            published_report["deployment_checkpoint_path"] = str(args.checkpoint.resolve())
            published_report["candidate_report_path"] = str(candidate_report.resolve())
            args.report.parent.mkdir(parents=True, exist_ok=True)
            report_temporary = args.report.with_name(f".{args.report.name}.tmp")
            report_temporary.write_text(
                json.dumps(published_report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(report_temporary, args.report)
            write_external_training_status(
                state="completed",
                epoch=training_report.epochs_completed,
                total_epochs=args.epochs,
                validation_pr_auc=training_report.validation_metrics.get("pr_auc"),
                message=f"Model promoted; test PR-AUC {training_report.test_metrics.get('pr_auc')}",
                started_at=train_started_at,
                completed_at=int(time.time()),
                checkpoint_path=str(args.checkpoint),
                report_path=str(args.report),
            )
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            write_external_training_status(
                state="failed",
                epoch=0,
                total_epochs=args.epochs,
                message=str(error)[:500],
                started_at=train_started_at,
                completed_at=int(time.time()),
            )
            return 2
        print(json.dumps(training_report.to_dict(), indent=2, sort_keys=True))
        return 0

    if args.command == "live":
        from graphsentinel.live_adapter import (
            LiveApiClient,
            follow_live_jsonl,
            forward_live_events,
            read_live_jsonl,
        )

        client = LiveApiClient(args.api_url, api_key=args.api_key)
        try:
            if args.follow:
                if args.format != "jsonl":
                    raise ValueError("--follow reads the gateway's JSONL; convert other formats first")
                follow_live_jsonl(args.input, client, poll_seconds=args.poll_seconds)
                return 0
            if args.format == "jsonl":
                events = read_live_jsonl(args.input)
            else:
                from graphsentinel.live_adapter import read_source_events

                events = read_source_events(
                    args.input, args.format, column_map=args.column_map,
                    assume_year=args.assume_year,
                )
            stats = forward_live_events(events, client, max_batch_events=args.max_batch_events)
        except (OSError, ValueError, RuntimeError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0

    if args.dataset_command in {"hub-push", "hub-pull"}:
        from graphsentinel.datasets.hub_storage import (
            HubStorageError,
            pull_registered_core,
            push_registered_core,
        )

        try:
            if args.dataset_command == "hub-push":
                receipt = push_registered_core(
                    args.raw_dir,
                    args.repo_id,
                    revision=args.revision,
                )
            else:
                receipt = pull_registered_core(
                    args.repo_id,
                    args.destination,
                    revision=args.revision,
                )
        except (OSError, ValueError, HubStorageError) as error:
            print(f"error: {error}", file=sys.stderr)
            return 2
        print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
        return 0

    try:
        if args.dataset_command == "register":
            plan = plan_registration(args.source, args.raw_dir, args.require)
            if not args.execute:
                print("DRY RUN: no files will be copied")
                print(f"source: {plan.source_dir}")
                print(f"raw_dir: {plan.raw_dir}")
                print(f"files: {', '.join(plan.files)}")
                print("Re-run with --execute after checking these paths.")
                return 0
            manifest, results = execute_registration(
                plan,
                full_scan=args.full_scan,
                quick_scan_rows=args.quick_scan_rows,
            )
        else:
            manifest, results = verify_registered(
                args.raw_dir,
                args.require,
                full_scan=args.full_scan,
                quick_scan_rows=args.quick_scan_rows,
            )
    except (OSError, ValueError, RegistrationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    _results_summary(manifest, results)
    return 0


def main() -> None:
    raise SystemExit(run())
