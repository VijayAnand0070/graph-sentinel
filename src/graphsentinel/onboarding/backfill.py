"""Build deployment state from historical logs.

Why this exists
---------------
Two halves of the detection path carry cumulative state that a fresh process
cannot reconstruct from forward traffic:

* ``CausalFeatureEngine`` — twelve of the 27 features answer "has this *ever*
  happened". Measured against a full-history reference, ``is_new_pair`` was
  still 42% divergent after 200,000 events of warm-up, and only 0.3% of events
  received fully correct features.
* ``TGNInferenceSession`` — every node's memory vector starts at zero, which
  asserts "nothing is known about this entity" for all 63,397 entities at
  once.

A live stream only moves forward, so neither recovers on its own. Onboarding a
deployment is therefore not "point it at the log stream and wait" — it is:

1. **backfill** (this tool): replay historical logs once to build the state
2. **snapshot**: persist it as an artifact beside the checkpoint
3. **restore**: load it on every process start

The replay is deliberately identical to production: the same
``CausalFeatureEngine``, the same ``InferenceSession``, chronological order,
score-before-update. Building state a different way than it will be used is
how a warm start becomes its own source of skew.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

from graphsentinel.features.causal import (MODEL_FEATURE_NAMES,
                                           CausalFeatureEngine, FeatureRecord)
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.models.serving import InferenceEvent, load_inference_session

SECONDS_PER_DAY = 86_400

#: Feature-engine state is JSON, so it is inert on load. The TGN memory is a
#: dense float array in npz with ``allow_pickle=False``. Neither is a pickle,
#: which matters for a file a security product loads at startup.
FEATURE_STATE_NAME = "feature_state.json.gz"
TGN_MEMORY_NAME = "tgn_memory.npz"
MANIFEST_NAME = "backfill_manifest.json"


@dataclass(frozen=True, slots=True)
class BackfillResult:
    events: int
    feature_state_path: Path | None
    tgn_memory_path: Path | None
    manifest_path: Path | None
    feature_coverage: dict[str, int]
    memory_coverage: dict[str, object]
    duration_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "events": self.events,
            "feature_state": str(self.feature_state_path) if self.feature_state_path else None,
            "tgn_memory": str(self.tgn_memory_path) if self.tgn_memory_path else None,
            "manifest": str(self.manifest_path) if self.manifest_path else None,
            "feature_coverage": self.feature_coverage,
            "memory_coverage": self.memory_coverage,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class BackfillRunner:
    """Replays historical events to build warm feature and model state."""

    checkpoint: Path | None = None
    device: str = "cpu"
    batch_size: int = 4096
    progress: Callable[[int], None] | None = None
    _engine: CausalFeatureEngine = field(default_factory=CausalFeatureEngine)

    def run(self, events: Iterable[NormalizedAuthEvent], output_dir: Path) -> BackfillResult:
        started = time.perf_counter()
        output_dir.mkdir(parents=True, exist_ok=True)

        session = None
        if self.checkpoint is not None:
            session = load_inference_session(self.checkpoint, device=self.device)

        processed = 0
        batch: list[FeatureRecord] = []
        # transform() is a generator over a generator: events are never all
        # held in memory, so a multi-million-event backfill stays bounded.
        for record in self._engine.transform(events):
            processed += 1
            if session is not None:
                batch.append(record)
                if len(batch) >= self.batch_size:
                    _advance_memory(session, batch)
                    batch = []
            if self.progress and processed % 50_000 == 0:
                self.progress(processed)
        if session is not None and batch:
            _advance_memory(session, batch)

        if processed == 0:
            raise ValueError("backfill received no events; nothing to build")

        feature_path = output_dir / FEATURE_STATE_NAME
        _write_feature_state(self._engine, feature_path)

        memory_path = None
        memory_coverage: dict[str, object] = {}
        if session is not None:
            memory_path = output_dir / TGN_MEMORY_NAME
            session.save_memory(memory_path)
            memory_coverage = session.memory_coverage()

        coverage = self._engine.coverage()
        manifest_path = output_dir / MANIFEST_NAME
        manifest = {
            "schema_version": 1,
            "built_at": int(time.time()),
            "events": processed,
            "feature_version": "auth-causal-v1",
            "feature_names": list(MODEL_FEATURE_NAMES),
            "feature_coverage": coverage,
            "memory_coverage": memory_coverage,
            "checkpoint": str(self.checkpoint) if self.checkpoint else None,
            "model_version": session.provenance.model_version if session else None,
            "artifacts": {
                FEATURE_STATE_NAME: _digest(feature_path),
                **({TGN_MEMORY_NAME: _digest(memory_path)} if memory_path else {}),
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return BackfillResult(
            events=processed,
            feature_state_path=feature_path,
            tgn_memory_path=memory_path,
            manifest_path=manifest_path,
            feature_coverage=coverage,
            memory_coverage=memory_coverage,
            duration_seconds=time.perf_counter() - started,
        )


def _advance_memory(session, records: list[FeatureRecord]) -> None:
    """Push one batch through the model so node memory advances.

    Probabilities are discarded: backfill is building state, not scoring. The
    events still go through preview/commit rather than a shortcut so the state
    is produced by exactly the code path that will consume it.
    """
    inference_events = [
        InferenceEvent(
            event_id=int(record.event_id),
            timestamp=int(record.timestamp),
            user_id=int(record.src_user_id),
            source_host_id=int(record.src_host_id),
            destination_host_id=int(record.dst_host_id),
            message=tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES),
        )
        for record in records
    ]
    session.commit(session.preview(inference_events))


def _write_feature_state(engine: CausalFeatureEngine, path: Path) -> None:
    # Staged then renamed: a crash mid-write must not leave a truncated
    # snapshot that would restore as partial history and look like it worked.
    staging = path.with_name(path.name + ".tmp")
    with gzip.open(staging, "wt", encoding="utf-8") as handle:
        json.dump(engine.snapshot(), handle)
    staging.replace(path)


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Input adapters
# ---------------------------------------------------------------------------

#: Columns a processed feature parquet must provide to be replayable.
REQUIRED_COLUMNS = (
    "event_id", "timestamp", "src_user_id", "dst_user_id", "src_host_id",
    "dst_host_id", "auth_type_id", "logon_type_id", "orientation_id", "success",
)


def events_from_parquet(
    source: Path, *, limit: int | None = None
) -> Iterator[NormalizedAuthEvent]:
    """Stream normalized events from a processed feature directory or file.

    Yields in strict chronological order, which the feature engine requires --
    replaying out of order would silently produce different state than
    production ever sees.
    """
    import polars as pl

    files = sorted(source.glob("**/*.parquet")) if source.is_dir() else [source]
    if not files:
        raise FileNotFoundError(f"no parquet files under {source}")

    frames = []
    for file in files:
        available = set(pl.read_parquet_schema(file))
        missing = [c for c in REQUIRED_COLUMNS if c not in available]
        if missing:
            raise ValueError(f"{file.name} is missing required columns: {missing}")
        columns = list(REQUIRED_COLUMNS)
        if "label_redteam" in available:
            columns.append("label_redteam")
        frames.append(pl.read_parquet(file, columns=columns))

    frame = pl.concat(frames, how="diagonal").sort("timestamp", "event_id")
    if limit is not None:
        frame = frame.head(limit)

    for row in frame.iter_rows(named=True):
        timestamp = int(row["timestamp"])
        yield NormalizedAuthEvent(
            event_id=int(row["event_id"]),
            timestamp=timestamp,
            src_user_id=int(row["src_user_id"]),
            dst_user_id=int(row["dst_user_id"]),
            src_host_id=int(row["src_host_id"]),
            dst_host_id=int(row["dst_host_id"]),
            auth_type_id=int(row["auth_type_id"]),
            logon_type_id=int(row["logon_type_id"]),
            orientation_id=int(row["orientation_id"]),
            success=int(row["success"]),
            label_redteam=int(row.get("label_redteam", 0) or 0),
            day=timestamp // SECONDS_PER_DAY,
            hour=(timestamp % SECONDS_PER_DAY) // 3_600,
        )


def run_backfill(
    source: Path,
    output_dir: Path,
    *,
    checkpoint: Path | None = None,
    device: str = "cpu",
    limit: int | None = None,
    progress: Callable[[int], None] | None = None,
) -> BackfillResult:
    """Convenience entry point: parquet in, deployment state out."""
    runner = BackfillRunner(checkpoint=checkpoint, device=device, progress=progress)
    return runner.run(events_from_parquet(source, limit=limit), output_dir)
