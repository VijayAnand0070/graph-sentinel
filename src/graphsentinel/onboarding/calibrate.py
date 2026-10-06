"""Onboard a new estate for the label-free transfer model, from its own logs.

A model trained in one organisation carries nothing into the next one but how
authentication behaves. What it cannot bring is the new estate's scale -- how
many hosts an ordinary account reaches, how busy its servers are -- or what an
ordinary day's scores look like there. Onboarding learns both from the estate's
own historical logs, **without labels**:

1. replay the history through the causal feature engine (the live engine's
   state is the result, as with :mod:`graphsentinel.onboarding.backfill`);
2. fit the feature standardisation on the estate's own events;
3. replay the history through the model, score before update, to warm every
   entity's memory and collect the anomaly score of every event;
4. keep the score distribution as the estate's reference: an alert budget of
   ``b`` becomes the ``1 - b`` percentile of ordinary traffic, whatever the
   estate's size or habits.

Attacks in the history do not need to be removed: they are a vanishing share of
it, and a percentile moves by at most that share.

Outputs (in one directory, beside the checkpoint): ``deployment_profile.json``,
``feature_state.json.gz``, ``transfer_memory.pt``, the estate's id maps and a
manifest. The API reads them through ``GRAPHSENTINEL_DEPLOYMENT_PROFILE``,
``GRAPHSENTINEL_FEATURE_STATE``, ``GRAPHSENTINEL_TGN_MEMORY`` and
``GRAPHSENTINEL_ID_MAPS``.
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from graphsentinel.features.canonical import category_index
from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.models.serving import InferenceEvent
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler
from graphsentinel.models.transfer_serving import DeploymentProfile, load_transfer_session
from graphsentinel.onboarding.backfill import FEATURE_STATE_NAME, _digest, _write_feature_state

PROFILE_NAME = "deployment_profile.json"
MEMORY_NAME = "transfer_memory.pt"
MANIFEST_NAME = "onboarding_manifest.json"
FOREST_NAME = "isolation_forest.joblib"
#: Largest reference distribution kept (a uniform, sorted sample).
REFERENCE_MAX = 1_000_000


@dataclass(frozen=True)
class OnboardingResult:
    events: int
    profile_path: Path
    output_dir: Path
    alert_threshold_percentile: float
    action_threshold_percentile: float
    duration_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "events": self.events,
            "profile": str(self.profile_path),
            "output_dir": str(self.output_dir),
            "alert_percentile": self.alert_threshold_percentile,
            "action_percentile": self.action_threshold_percentile,
            "duration_seconds": round(self.duration_seconds, 1),
        }


def run_onboarding(
    events: Iterable[NormalizedAuthEvent],
    *,
    id_maps_dir: Path,
    checkpoint: Path,
    output_dir: Path,
    alert_budget: float = 1e-5,
    action_budget: float = 1e-6,
    device: str = "cpu",
    batch_size: int = 20_000,
    seed: int = 1729,
    progress: Callable[[str, int], None] | None = None,
    ensemble: bool = True,
) -> OnboardingResult:
    started = time.perf_counter()
    output_dir.mkdir(parents=True, exist_ok=True)
    maps = AuthIdMaps.load(id_maps_dir)

    def values(mapping) -> list[str]:  # type: ignore[no-untyped-def]
        return list(mapping.to_dict()["values"])

    names = {"users": values(maps.users), "hosts": values(maps.hosts)}
    categories = {
        "auth": category_index(values(maps.auth_types), "auth"),
        "logon": category_index(values(maps.logon_types), "logon"),
        "orientation": category_index(values(maps.orientations), "orientation"),
    }

    # 1. features, exactly as the live engine computes them (its state is kept)
    engine = CausalFeatureEngine()
    ids: list[tuple[int, int, int, int, int, int, int, int, int]] = []
    numeric: list[tuple[float, ...]] = []
    for count, record in enumerate(engine.transform(events), start=1):
        ids.append((
            int(record.event_id), int(record.timestamp), int(record.src_user_id), int(record.src_host_id),
            int(record.dst_host_id), int(record.auth_type_id), int(record.logon_type_id),
            int(record.orientation_id), int(record.success),
        ))
        numeric.append(tuple(float(getattr(record, n)) for n in NUMERIC_FEATURES))
        if progress and count % 100_000 == 0:
            progress("features", count)
    if not ids:
        raise ValueError("onboarding received no events")
    table = np.asarray(ids, dtype=np.int64)
    x = np.asarray(numeric, dtype=np.float32)
    del ids, numeric

    # 2. the estate's own standardisation
    rng = np.random.default_rng(seed)
    sample = x if len(x) <= 2_000_000 else x[rng.choice(len(x), 2_000_000, replace=False)]
    scaler = FeatureScaler.fit({n: sample[:, k] for k, n in enumerate(NUMERIC_FEATURES)})

    # 3. warm memory and score every event, score before update
    session = load_transfer_session(checkpoint, device=device)
    provisional = DeploymentProfile(scaler=scaler, reference=np.array([0.0, 1.0]), warmup_events=0,
                                    alert_budget=alert_budget, action_budget=action_budget)
    session.profile = provisional
    codes = np.stack(
        [categories["auth"][table[:, 5]], categories["logon"][table[:, 6]],
         categories["orientation"][table[:, 7]], table[:, 8]], axis=1,
    )
    anomalies = np.empty(len(table), dtype=np.float64)
    for lo in range(0, len(table), batch_size):
        hi = min(lo + batch_size, len(table))
        batch = [
            InferenceEvent(
                event_id=int(table[i, 0]), timestamp=int(table[i, 1]), user_id=int(table[i, 2]),
                source_host_id=int(table[i, 3]), destination_host_id=int(table[i, 4]),
                message=tuple(x[i].tolist()) + tuple(float(c) for c in codes[i]),
                user_name=names["users"][table[i, 2]], source_name=names["hosts"][table[i, 3]],
                destination_name=names["hosts"][table[i, 4]],
            )
            for i in range(lo, hi)
        ]
        preview = session.preview(batch)
        session.commit(preview)
        anomalies[lo:hi] = preview.anomalies
        if progress:
            progress("scoring", hi)

    # 4. the estate's reference distributions
    keep = np.arange(len(table)) if len(table) <= REFERENCE_MAX else np.sort(
        rng.choice(len(table), REFERENCE_MAX, replace=False))
    reference = np.sort(anomalies[keep])
    extra: dict[str, object] = {}
    forest = None
    if ensemble:
        # 5. label-free companions, fitted on the estate's own traffic
        from graphsentinel.features.canonical import one_hot
        from graphsentinel.models.companions import (
            combine,
            fit_isolation_forest,
            isolation_score,
            rarity_score,
            save_forest,
        )

        def model_matrix(rows: np.ndarray) -> np.ndarray:
            scaled = scaler.transform({n: x[rows, k] for k, n in enumerate(NUMERIC_FEATURES)})
            c = codes[rows]
            return np.concatenate([scaled, one_hot(c[:, 0], c[:, 1], c[:, 2], c[:, 3])], axis=1)

        fit_rows = keep if len(keep) <= 200_000 else np.sort(rng.choice(keep, 200_000, replace=False))
        forest = fit_isolation_forest(model_matrix(fit_rows), seed=seed)
        rarity = rarity_score({n: x[keep, k].astype(np.float64) for k, n in enumerate(NUMERIC_FEATURES)})
        iso = np.concatenate([
            isolation_score(forest, model_matrix(keep[lo: lo + 200_000])) for lo in range(0, len(keep), 200_000)])
        refs = {"rarity": np.sort(rarity), "iforest": np.sort(iso)}
        pct = {
            "tgn": np.searchsorted(reference, anomalies[keep], "right") / len(reference),
            "rarity": np.searchsorted(refs["rarity"], rarity, "right") / len(rarity),
            "iforest": np.searchsorted(refs["iforest"], iso, "right") / len(iso),
        }
        forest_sha = save_forest(forest, output_dir / FOREST_NAME)
        extra = {"companion_references": refs, "combined_reference": np.sort(combine(pct)),
                 "forest_file": FOREST_NAME, "forest_sha256": forest_sha}
        if progress:
            progress("companions", len(keep))
    profile = DeploymentProfile(
        scaler=scaler, reference=reference, warmup_events=len(table),
        description=f"onboarded from {len(table):,} events", alert_budget=alert_budget, action_budget=action_budget,
        **extra,  # type: ignore[arg-type]
    )
    profile_path = output_dir / PROFILE_NAME
    profile.save(profile_path)
    session.profile = profile
    session.forest = forest
    session.save_memory(output_dir / MEMORY_NAME)
    _write_feature_state(engine, output_dir / FEATURE_STATE_NAME)
    maps_out = output_dir / "id_maps"
    if maps_out.exists():
        shutil.rmtree(maps_out)
    shutil.copytree(id_maps_dir, maps_out)
    manifest = {
        "schema_version": 1,
        "built_at": int(time.time()),
        "events": len(table),
        "checkpoint": str(checkpoint),
        "model_version": session.provenance.model_version,
        "labels_used": False,
        "score": "mean of percentiles: tgn, rarity, isolation forest" if ensemble else "tgn",
        "alert_budget": alert_budget,
        "action_budget": action_budget,
        "alerts_per_day_expected": _per_day(table[:, 1], alert_budget),
        "actions_per_day_expected": _per_day(table[:, 1], action_budget),
        "feature_coverage": engine.coverage(),
        "memory_coverage": session.memory_coverage(),
        "artifacts": {
            PROFILE_NAME: _digest(profile_path),
            MEMORY_NAME: _digest(output_dir / MEMORY_NAME),
            FEATURE_STATE_NAME: _digest(output_dir / FEATURE_STATE_NAME),
            **({FOREST_NAME: _digest(output_dir / FOREST_NAME)} if ensemble else {}),
        },
    }
    (output_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return OnboardingResult(
        events=len(table), profile_path=profile_path, output_dir=output_dir,
        alert_threshold_percentile=1 - alert_budget, action_threshold_percentile=1 - action_budget,
        duration_seconds=time.perf_counter() - started,
    )


def _per_day(timestamps: np.ndarray, budget: float) -> float:
    span_days = max(1.0, (int(timestamps.max()) - int(timestamps.min())) / 86_400)
    return round(budget * len(timestamps) / span_days, 2)
