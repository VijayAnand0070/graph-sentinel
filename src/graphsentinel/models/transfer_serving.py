"""Serving the label-free transfer model in a live stream, in any estate.

Three things differ from serving the first model (:mod:`graphsentinel.models.serving`).

**Entities.** The first model read a frozen LANL dictionary; a name it had never
seen was hashed into one of a few thousand shared buckets, so in a new estate
every account and host shared memory with strangers. Here node memory is state,
indexed by a table that grows as entities appear -- a new estate simply starts
with an empty table.

**Time.** Training and evaluation fold memory updates in fixed time buckets
(60 s). The session scores every event the moment it arrives, against memory as
it stood at the start of the event's bucket, and defers the bucket's updates
until the bucket closes. A served score is therefore the evaluated score,
exactly, without buffering any event.

**Calibration.** A raw anomaly score means nothing across estates. A
:class:`DeploymentProfile`, fitted by onboarding on the estate's own unlabelled
history, standardises the features with the estate's statistics and turns each
anomaly into its percentile among the estate's warm-up traffic. Budgets are
then percentiles: an alert budget of 5 per 10,000 is the 99.95th percentile,
whatever the estate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

import numpy as np
import torch

from graphsentinel.features.canonical import (
    AUTH_CATEGORIES,
    LOGON_CATEGORIES,
    ORIENTATION_CATEGORIES,
    canonical_auth,
    canonical_logon,
    canonical_orientation,
    one_hot,
)
from graphsentinel.detection.fusion import NoisyOrConfig
from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
from graphsentinel.models.serving import CheckpointError, InferenceEvent
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler, MemoryState, TransferTGN

#: Width of an :class:`InferenceEvent` message for this model: the numeric
#: features, unscaled, then canonical auth / logon / orientation codes and success.
MESSAGE_WIDTH = len(NUMERIC_FEATURES) + 4
FEATURE_VERSION = "auth-causal-v2"


def transfer_message(record: Any, *, auth_type: str, logon_type: str, orientation: str) -> tuple[float, ...]:
    """The inference message for one featurised event (a ``FeatureRecord``)."""
    numeric = tuple(float(getattr(record, name)) for name in NUMERIC_FEATURES)
    codes = (
        AUTH_CATEGORIES.index(canonical_auth(auth_type)),
        LOGON_CATEGORIES.index(canonical_logon(logon_type)),
        ORIENTATION_CATEGORIES.index(canonical_orientation(orientation)),
        int(record.success),
    )
    return numeric + tuple(float(c) for c in codes)


#: The product's alert threshold on its risk scale; a calibrated percentile is
#: mapped so that the alert budget lands exactly here.
ALERT_RISK = NoisyOrConfig().calibrated_threshold
#: Noisy-OR in which only the model channel speaks: the calibrated risk passes
#: through unchanged. Label-free deployments use it, because every other
#: channel's reliability was fitted on one estate's labels.
PASS_THROUGH_FUSION = NoisyOrConfig(tgn=1.0, novelty=0.0, burst=0.0, pivot=0.0, corroboration=0.0)


@dataclass(frozen=True)
class DeploymentProfile:
    """What onboarding learned about one estate from its own unlabelled logs.

    ``alert_budget`` and ``action_budget`` are fractions of the estate's
    authentications: the share of ordinary traffic the estate accepts as
    alerts, and as unattended actions. They become percentiles of the warm-up
    scores, and :meth:`risk` maps those percentiles onto the product's fixed
    risk scale (alert threshold, execution gate), so every downstream rule,
    floor and screen keeps its meaning in every estate.
    """

    scaler: FeatureScaler
    #: sorted anomaly scores of the estate's warm-up events (a uniform sample)
    reference: np.ndarray
    warmup_events: int
    description: str = ""
    alert_budget: float = 1e-5
    action_budget: float = 1e-6
    #: Served combination (``models/companions.py``): sorted warm-up scores of
    #: each label-free companion detector, and of the mean of the members'
    #: percentiles, on which the budgets are read. Empty: the network alone.
    companion_references: dict[str, np.ndarray] = field(default_factory=dict)
    combined_reference: np.ndarray | None = None
    #: the onboarding isolation forest, beside the profile, and its digest
    forest_file: str = ""
    forest_sha256: str = ""

    @property
    def ensemble(self) -> bool:
        return self.combined_reference is not None and bool(self.companion_references)

    def companion_percentile(self, name: str, raw: np.ndarray) -> np.ndarray:
        ref = self.companion_references[name]
        return np.searchsorted(ref, raw, "right") / len(ref)

    def combined_percentile(self, tgn_anomaly: np.ndarray, companions: dict[str, np.ndarray]) -> np.ndarray:
        """Percentile, among warm-up traffic, of the mean of the members' percentiles."""
        from graphsentinel.models.companions import combine

        assert self.combined_reference is not None
        pct = {"tgn": self.percentile(tgn_anomaly)}
        pct.update({k: self.companion_percentile(k, v) for k, v in companions.items()})
        combined = combine(pct)
        return np.searchsorted(self.combined_reference, combined, "right") / len(self.combined_reference)

    def __post_init__(self) -> None:
        if not 0 < self.action_budget < self.alert_budget < 1:
            raise ValueError("budgets must satisfy 0 < action < alert < 1")

    def percentile(self, anomaly: np.ndarray) -> np.ndarray:
        return np.searchsorted(self.reference, anomaly, "right") / len(self.reference)

    def risk(self, percentile: np.ndarray) -> np.ndarray:
        """Percentile among the estate's traffic -> the product's risk scale."""
        return np.interp(
            percentile,
            [0.0, 1.0 - self.alert_budget, 1.0 - self.action_budget, 1.0],
            [0.0, ALERT_RISK, AUTO_EXECUTE_THRESHOLD, 1.0],
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema_version": 2 if self.ensemble else 1,
            "scaler": self.scaler.to_dict(),
            "reference": self.reference.astype(float).tolist(),
            "warmup_events": self.warmup_events,
            "description": self.description,
            "alert_budget": self.alert_budget,
            "action_budget": self.action_budget,
        }
        if self.ensemble:
            assert self.combined_reference is not None
            out["score"] = "mean of percentiles: tgn, rarity, isolation forest"
            out["companion_references"] = {
                k: v.astype(float).tolist() for k, v in self.companion_references.items()}
            out["combined_reference"] = self.combined_reference.astype(float).tolist()
            out["forest_file"] = self.forest_file
            out["forest_sha256"] = self.forest_sha256
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeploymentProfile:
        if data.get("schema_version") not in (1, 2):
            raise ValueError("unsupported deployment profile")
        reference = np.sort(np.asarray(data["reference"], dtype=np.float64))
        if len(reference) == 0:
            raise ValueError("deployment profile has no reference scores")
        return cls(
            scaler=FeatureScaler.from_dict(data["scaler"]),
            reference=reference,
            warmup_events=int(data["warmup_events"]),
            description=str(data.get("description", "")),
            alert_budget=float(data.get("alert_budget", 1e-5)),
            action_budget=float(data.get("action_budget", 1e-6)),
            companion_references={
                k: np.sort(np.asarray(v, dtype=np.float64))
                for k, v in (data.get("companion_references") or {}).items()},
            combined_reference=(
                np.sort(np.asarray(data["combined_reference"], dtype=np.float64))
                if data.get("combined_reference") else None),
            forest_file=str(data.get("forest_file", "")),
            forest_sha256=str(data.get("forest_sha256", "")),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict()), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> DeploymentProfile:
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))


@dataclass(frozen=True)
class TransferProvenance:
    """The parts of a checkpoint's provenance the product displays and checks."""

    model_version: str
    checkpoint_sha256: str
    feature_version: str = FEATURE_VERSION
    labels_used: bool = False
    training: dict[str, Any] = field(default_factory=dict)
    feature_names: tuple[str, ...] = NUMERIC_FEATURES

    def to_dict(self) -> dict[str, object]:
        return {
            "model": "TransferTGN",
            "model_version": self.model_version,
            "checkpoint_sha256": self.checkpoint_sha256,
            "feature_version": self.feature_version,
            "labels_used": self.labels_used,
            "training": self.training,
            "feature_names": list(self.feature_names),
            "entity_dictionary": "grows with the estate (no frozen dictionary)",
        }


@dataclass(frozen=True)
class _Pending:
    bucket: int | None
    user: tuple[int, ...] = ()
    src: tuple[int, ...] = ()
    dst: tuple[int, ...] = ()
    t: tuple[int, ...] = ()
    codes: tuple[tuple[int, int, int, int], ...] = ()

    def extend(self, user, src, dst, t, codes) -> _Pending:  # type: ignore[no-untyped-def]
        return _Pending(self.bucket, self.user + tuple(user), self.src + tuple(src), self.dst + tuple(dst),
                        self.t + tuple(t), self.codes + tuple(codes))


@dataclass(frozen=True)
class TransferPreview:
    state_version: int
    probabilities: tuple[float, ...]
    anomalies: tuple[float, ...]
    next_state: MemoryState
    next_pending: _Pending
    new_nodes: dict[tuple[str, int | str], int]
    final_timestamp: int


class TransferInferenceSession:
    """One ordered inference stream with compare-and-swap state publication.

    ``probabilities`` in a preview are risks on the product scale -- the
    anomaly's percentile among the estate's warm-up traffic, mapped through the
    profile's budgets -- when a :class:`DeploymentProfile` is set, and raw
    anomalies (``calibrated`` false) before onboarding has fitted one.
    """

    requires_frozen_dictionary = False
    message_width = MESSAGE_WIDTH

    def __init__(
        self,
        *,
        model: TransferTGN,
        scaler: FeatureScaler,
        bucket_seconds: int,
        provenance: TransferProvenance,
        profile: DeploymentProfile | None = None,
        device: torch.device | str = "cpu",
        forest: Any | None = None,
    ) -> None:
        if bucket_seconds <= 0:
            raise ValueError("bucket_seconds must be positive")
        self.model = model.to(device).eval()
        self.training_scaler = scaler
        self.profile = profile
        #: onboarding isolation forest; with an ensemble profile the served
        #: risk is the combined score (``models/companions.py``)
        self.forest = forest
        self.bucket_seconds = bucket_seconds
        self.provenance = provenance
        self.device = torch.device(device)
        self._lock = RLock()
        self.reset()

    # ------------------------------------------------------------------ state
    def reset(self) -> int:
        with self._lock:
            self._state = MemoryState.initial(1024, self.model.memory_dim, self.device)
            self._pending = _Pending(bucket=None)
            self._nodes: dict[tuple[str, int | str], int] = {}
            self._state_version = getattr(self, "_state_version", 0) + 1
            self._last_timestamp: int | None = None
            self._folded_events = 0
            return self._state_version

    @property
    def calibrated(self) -> bool:
        return self.profile is not None

    @property
    def state_version(self) -> int:
        with self._lock:
            return self._state_version

    @property
    def stream_timestamp(self) -> int | None:
        with self._lock:
            return self._last_timestamp

    @property
    def scaler(self) -> FeatureScaler:
        return self.profile.scaler if self.profile is not None else self.training_scaler

    def _fold(self, state: MemoryState, pending: _Pending) -> MemoryState:
        if not pending.t:
            return state
        dev = self.device
        codes = np.asarray(pending.codes, dtype=np.int64)
        cats = torch.from_numpy(one_hot(codes[:, 0], codes[:, 1], codes[:, 2], codes[:, 3])).to(dev)
        return self.model.update(
            state,
            torch.tensor(pending.user, device=dev),
            torch.tensor(pending.src, device=dev),
            torch.tensor(pending.dst, device=dev),
            torch.tensor(pending.t, device=dev),
            cats,
        ).detach()

    # ------------------------------------------------------------------ scoring
    def preview(self, events: Sequence[InferenceEvent]) -> TransferPreview:
        """Score a chronological batch and compute the candidate state, unpublished."""
        if not events:
            raise ValueError("inference batch cannot be empty")
        if any(b.timestamp < a.timestamp for a, b in zip(events, events[1:], strict=False)):
            raise ValueError("inference events must be chronological")
        if any(len(e.message) != MESSAGE_WIDTH for e in events):
            raise ValueError(f"all inference messages must contain {MESSAGE_WIDTH} values")
        with self._lock, torch.inference_mode():
            if self._last_timestamp is not None and events[0].timestamp < self._last_timestamp:
                raise ValueError("inference batch goes back in time")
            version = self._state_version
            state, pending = self._state, self._pending
            new_nodes: dict[tuple[str, int | str], int] = {}

            def node(kind: str, ident: int | str) -> int:
                key = (kind, ident)
                found = self._nodes.get(key)
                if found is None:
                    found = new_nodes.get(key)
                if found is None:
                    found = len(self._nodes) + len(new_nodes)
                    new_nodes[key] = found
                return found

            anomalies: list[float] = []
            raw_rows: list[np.ndarray] = []
            model_rows: list[np.ndarray] = []
            i = 0
            while i < len(events):
                bucket = events[i].timestamp // self.bucket_seconds
                j = i
                while j < len(events) and events[j].timestamp // self.bucket_seconds == bucket:
                    j += 1
                run = events[i:j]
                if pending.bucket is not None and pending.bucket != bucket:
                    state = self._fold(state.ensure(len(self._nodes) + len(new_nodes)), pending)
                    pending = _Pending(bucket=bucket)
                elif pending.bucket is None:
                    pending = _Pending(bucket=bucket)
                users = [node("u", e.user_name if e.user_name is not None else int(e.user_id)) for e in run]
                srcs = [node("h", e.source_name if e.source_name is not None else int(e.source_host_id)) for e in run]
                dsts = [
                    node("h", e.destination_name if e.destination_name is not None else int(e.destination_host_id))
                    for e in run
                ]
                state = state.ensure(len(self._nodes) + len(new_nodes))
                msg = np.asarray([e.message for e in run], dtype=np.float64)
                numeric = {name: msg[:, k] for k, name in enumerate(NUMERIC_FEATURES)}
                x = torch.from_numpy(self.scaler.transform(numeric)).to(self.device)
                codes = msg[:, len(NUMERIC_FEATURES):].astype(np.int64)
                cats = torch.from_numpy(one_hot(codes[:, 0], codes[:, 1], codes[:, 2], codes[:, 3])).to(self.device)
                t = torch.tensor([e.timestamp for e in run], device=self.device)
                logits = self.model.score(
                    state,
                    torch.tensor(users, device=self.device),
                    torch.tensor(srcs, device=self.device),
                    torch.tensor(dsts, device=self.device),
                    t,
                    x,
                    cats,
                )
                anomalies.extend(torch.sigmoid(-logits).cpu().tolist())
                raw_rows.append(msg[:, : len(NUMERIC_FEATURES)])
                model_rows.append(np.concatenate([x.cpu().numpy(), cats.cpu().numpy()], axis=1))
                pending = pending.extend(users, srcs, dsts, [e.timestamp for e in run], [tuple(c) for c in codes.tolist()])
                i = j
            anomaly = np.asarray(anomalies)
            probs = self._risk(anomaly, raw_rows, model_rows)
            return TransferPreview(
                state_version=version,
                probabilities=tuple(float(p) for p in probs),
                anomalies=tuple(float(a) for a in anomaly),
                next_state=state,
                next_pending=pending,
                new_nodes=new_nodes,
                final_timestamp=events[-1].timestamp,
            )

    def _risk(self, anomaly: np.ndarray, raw_rows: list[np.ndarray], model_rows: list[np.ndarray]) -> np.ndarray:
        if self.profile is None:
            return anomaly
        if not (self.profile.ensemble and self.forest is not None):
            return self.profile.risk(self.profile.percentile(anomaly))
        from graphsentinel.models.companions import isolation_score, rarity_score

        raw = np.concatenate(raw_rows)
        companions = {
            "rarity": rarity_score({n: raw[:, k] for k, n in enumerate(NUMERIC_FEATURES)}),
            "iforest": isolation_score(self.forest, np.concatenate(model_rows)),
        }
        return self.profile.risk(self.profile.combined_percentile(anomaly, companions))

    def commit(self, preview: TransferPreview) -> int:
        with self._lock:
            if preview.state_version != self._state_version:
                raise RuntimeError("stale inference preview cannot update temporal state")
            folded = len(self._pending.t) if preview.next_pending.bucket != self._pending.bucket else 0
            self._state = preview.next_state
            self._pending = preview.next_pending
            self._nodes.update(preview.new_nodes)
            self._last_timestamp = preview.final_timestamp
            self._folded_events += folded
            self._state_version += 1
            return self._state_version

    # ------------------------------------------------------------------ persistence
    def save_memory(self, path: Path) -> dict[str, object]:
        with self._lock:
            payload = {
                "schema_version": 1,
                "model": "TransferTGN",
                "checkpoint_sha256": self.provenance.checkpoint_sha256,
                "memory": self._state.memory.cpu(),
                "last_update": self._state.last_update.cpu(),
                "nodes": [[k[0], k[1], v] for k, v in self._nodes.items()],
                "pending": {
                    "bucket": self._pending.bucket, "user": list(self._pending.user), "src": list(self._pending.src),
                    "dst": list(self._pending.dst), "t": list(self._pending.t), "codes": [list(c) for c in self._pending.codes],
                },
                "last_timestamp": self._last_timestamp,
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f".{path.name}.tmp")
            torch.save(payload, tmp)
            tmp.replace(path)
            return self.memory_coverage()

    def load_memory(self, path: Path) -> dict[str, object]:
        payload = torch.load(path, map_location=self.device, weights_only=True)
        if payload.get("model") != "TransferTGN" or payload.get("schema_version") != 1:
            raise CheckpointError("not a transfer-model memory snapshot")
        if payload.get("checkpoint_sha256") != self.provenance.checkpoint_sha256:
            raise CheckpointError("memory snapshot was written by a different checkpoint")
        with self._lock:
            self._state = MemoryState(payload["memory"].to(self.device), payload["last_update"].to(self.device))
            self._nodes = {(k, i if isinstance(i, str) else int(i)): int(v) for k, i, v in payload["nodes"]}
            p = payload["pending"]
            self._pending = _Pending(
                bucket=p["bucket"], user=tuple(p["user"]), src=tuple(p["src"]), dst=tuple(p["dst"]),
                t=tuple(p["t"]), codes=tuple(tuple(c) for c in p["codes"]),
            )
            self._last_timestamp = payload["last_timestamp"]
            self._state_version += 1
            return self.memory_coverage()

    def memory_coverage(self) -> dict[str, object]:
        with self._lock:
            seen = int((self._state.last_update >= 0).sum().item())
            return {
                "model": "TransferTGN",
                "entities_known": len(self._nodes),
                "entities_with_memory": seen,
                "calibrated": self.calibrated,
                "warmup_events": self.profile.warmup_events if self.profile else 0,
                "last_timestamp": self._last_timestamp,
            }

    def memory_snapshot(self) -> tuple[tuple[float, ...], ...]:
        with self._lock:
            return tuple(tuple(float(v) for v in row) for row in self._state.memory[: len(self._nodes)].cpu().tolist())


def is_transfer_checkpoint(path: Path) -> bool:
    """Whether a checkpoint file holds the label-free transfer model."""
    try:
        # restricted unpickling, as for every file the product loads at startup
        payload = torch.load(path, map_location="cpu", weights_only=True)
    except Exception:
        return False
    return isinstance(payload, dict) and payload.get("model") == "TransferTGN"


def load_transfer_session(
    path: Path, *, profile_path: Path | None = None, device: torch.device | str = "cpu"
) -> TransferInferenceSession:
    """Load a transfer checkpoint (and, when onboarding has run, the estate's profile)."""
    if not path.is_file():
        raise FileNotFoundError(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    actual = "cuda" if str(device).startswith("cuda") and torch.cuda.is_available() else "cpu"
    try:
        payload = torch.load(path, map_location=actual, weights_only=True)
    except Exception as error:  # pragma: no cover - corrupt file
        raise CheckpointError(f"cannot load checkpoint: {error}") from error
    if payload.get("model") != "TransferTGN":
        raise CheckpointError("not a transfer-model checkpoint")
    if payload.get("labels_used", True):
        raise CheckpointError("transfer checkpoints must be trained without attack labels")
    model = TransferTGN(**payload["configuration"])
    model.load_state_dict(payload["state_dict"], strict=True)
    scaler = FeatureScaler.from_dict(payload["scaler"])
    provenance = TransferProvenance(
        model_version=f"transfer-tgn-{digest[:12]}",
        checkpoint_sha256=digest,
        training={k: payload.get(k) for k in ("train_days", "val_day", "seed", "epoch", "val_auc", "bucket_seconds")},
    )
    profile = DeploymentProfile.load(profile_path) if profile_path and profile_path.is_file() else None
    forest = None
    if profile is not None and profile.ensemble and profile_path is not None:
        from graphsentinel.models.companions import load_forest

        if not profile.forest_file:
            raise CheckpointError("ensemble profile names no isolation forest")
        forest = load_forest(profile_path.parent / profile.forest_file, profile.forest_sha256)
    return TransferInferenceSession(
        model=model, scaler=scaler, bucket_seconds=int(payload["bucket_seconds"]),
        provenance=provenance, profile=profile, device=actual, forest=forest,
    )
