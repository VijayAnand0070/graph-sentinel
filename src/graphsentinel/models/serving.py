"""Validated checkpoint loading and transactional temporal inference."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import groupby, pairwise
from pathlib import Path
from threading import RLock
from typing import Any, TypeGuard, cast

import torch

from graphsentinel.features.causal import MODEL_FEATURE_NAMES
from graphsentinel.graph.temporal import NodeIdSpace, TemporalGraphEvent
from graphsentinel.models.tgn import TemporalBatch, TemporalGraphNetwork, TGNState


class CheckpointError(ValueError):
    """Raised when a model artifact violates the serving contract."""


@dataclass(frozen=True, slots=True)
class CheckpointProvenance:
    path: str
    sha256: str
    feature_version: str
    model_version: str
    user_capacity: int
    host_capacity: int
    configuration: dict[str, int | float]
    user_dictionary_capacity: int = 0
    host_dictionary_capacity: int = 0
    oov_user_buckets: int = 0
    oov_host_buckets: int = 0
    feature_names: tuple[str, ...] = ()
    feature_center: tuple[float, ...] = ()
    feature_scale: tuple[float, ...] = ()
    decision_threshold: float | None = None
    entity_dictionary_sha256: str | None = None
    feature_contract_sha256: str | None = None
    dataset_sha256: str | None = None
    training_run_sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "feature_version": self.feature_version,
            "model_version": self.model_version,
            "user_capacity": self.user_capacity,
            "host_capacity": self.host_capacity,
            "configuration": self.configuration,
            "user_dictionary_capacity": self.user_dictionary_capacity,
            "host_dictionary_capacity": self.host_dictionary_capacity,
            "oov_user_buckets": self.oov_user_buckets,
            "oov_host_buckets": self.oov_host_buckets,
            "feature_names": self.feature_names,
            "feature_center": self.feature_center,
            "feature_scale": self.feature_scale,
            "decision_threshold": self.decision_threshold,
            "entity_dictionary_sha256": self.entity_dictionary_sha256,
            "feature_contract_sha256": self.feature_contract_sha256,
            "dataset_sha256": self.dataset_sha256,
            "training_run_sha256": self.training_run_sha256,
        }


@dataclass(frozen=True, slots=True)
class InferenceEvent:
    event_id: int
    timestamp: int
    user_id: int
    source_host_id: int
    destination_host_id: int
    message: tuple[float, ...]
    #: Entity names, when the caller has them. The transfer model keys node
    #: memory by name, so memory survives any renumbering of the id maps.
    user_name: str | None = None
    source_name: str | None = None
    destination_name: str | None = None


@dataclass(frozen=True, slots=True)
class InferencePreview:
    state_version: int
    probabilities: tuple[float, ...]
    next_state: TGNState
    final_timestamp: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(8 * 1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_sha256(value: object) -> TypeGuard[str]:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _required_mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CheckpointError(f"checkpoint {name} must be a mapping")
    return cast(Mapping[str, Any], value)


class TGNInferenceSession:
    """One ordered inference stream with compare-and-swap state publication."""

    def __init__(
        self,
        *,
        model: TemporalGraphNetwork,
        id_space: NodeIdSpace,
        provenance: CheckpointProvenance,
        device: torch.device | str = "cpu",
    ) -> None:
        if model.num_nodes != id_space.node_count:
            raise ValueError("model node count does not match typed ID space")
        self.model = model.to(device).eval()
        self.id_space = id_space
        self.provenance = provenance
        self.device = torch.device(device)
        self._state = model.initial_state(device=self.device)
        self._state_version = 0
        self._lock = RLock()

    @property
    def state_version(self) -> int:
        with self._lock:
            return self._state_version

    @property
    def stream_timestamp(self) -> int | None:
        with self._lock:
            return self._state.stream_timestamp

    def preview(self, events: Sequence[InferenceEvent]) -> InferencePreview:
        """Compute probabilities and a candidate state without publishing it."""

        if not events:
            raise ValueError("inference batch cannot be empty")
        if any(current.timestamp < previous.timestamp for previous, current in pairwise(events)):
            raise ValueError("inference events must be chronological")
        if any(len(event.message) != self.model.message_dim for event in events):
            raise ValueError(
                f"all inference messages must contain {self.model.message_dim} features"
            )
        with self._lock, torch.inference_mode():
            version = self._state_version
            state = self._state
            probabilities: list[float] = []
            for _timestamp, grouped in groupby(events, key=lambda event: event.timestamp):
                group = [self._normalized(event) for event in grouped]
                temporal_events = [self._to_temporal(event) for event in group]
                batch = TemporalBatch.from_events(temporal_events, device=self.device)
                logits, state = self.model.step(batch, state)
                probabilities.extend(torch.sigmoid(logits).cpu().tolist())
            return InferencePreview(
                state_version=version,
                probabilities=tuple(float(value) for value in probabilities),
                next_state=state.detach(),
                final_timestamp=events[-1].timestamp,
            )

    def _normalized(self, event: InferenceEvent) -> InferenceEvent:
        center = self.provenance.feature_center
        scale = self.provenance.feature_scale
        if not center and not scale:
            return event
        if len(center) != len(event.message) or len(scale) != len(event.message):
            raise ValueError("checkpoint normalizer width does not match inference message")
        normalized = tuple(
            max(-10.0, min(10.0, (value - offset) / divisor))
            for value, offset, divisor in zip(event.message, center, scale, strict=True)
        )
        return InferenceEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            user_id=event.user_id,
            source_host_id=event.source_host_id,
            destination_host_id=event.destination_host_id,
            message=normalized,
        )

    def commit(self, preview: InferencePreview) -> int:
        """Publish a preview only if no other request advanced the stream meanwhile."""

        with self._lock:
            if preview.state_version != self._state_version:
                raise RuntimeError("stale inference preview cannot update temporal state")
            self._state = preview.next_state
            self._state_version += 1
            return self._state_version

    def reset(self) -> int:
        with self._lock:
            self._state = self.model.initial_state(device=self.device)
            self._state_version += 1
            return self._state_version

    # ------------------------------------------------------------------
    # Node-memory persistence
    #
    # TGNState.initial() zeroes a (num_nodes, memory_dim) tensor on every
    # load, so a restarted process begins with every entity's memory at zero.
    # The model's whole premise is that memory summarises an entity's history,
    # and zero memory asserts "nothing is known about this entity" for every
    # entity at once -- exactly the state the network was never trained to see
    # outside the first moments of a stream.
    #
    # This is the same defect as the cumulative feature state (see
    # CausalFeatureEngine.snapshot) applied to the learned half of the system,
    # and it needs the same answer: build it once from history, persist it,
    # restore it on start.
    #
    # Serialised through numpy rather than torch.save because torch.save is
    # pickle-backed, and a state file that executes code on load is not
    # something a security product should carry.
    # ------------------------------------------------------------------
    STATE_VERSION = 1

    def save_memory(self, path: Path) -> dict[str, object]:
        """Persist node memory, per-node update times, and the stream clock."""
        import numpy as np

        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            memory = self._state.memory.detach().cpu().numpy()
            last_update = self._state.last_update.detach().cpu().numpy()
            stream_timestamp = self._state.stream_timestamp
        # Written through an open handle, not a path: np.savez_compressed
        # appends ".npz" to any filename lacking it, which would silently
        # redirect the staging write to "<name>.npz.tmp.npz" and leave the
        # rename pointing at a file that was never created.
        staging = path.with_name(path.name + ".tmp")
        with staging.open("wb") as handle:
            np.savez_compressed(
                handle,
                version=np.asarray(self.STATE_VERSION),
                memory=memory.astype("float32"),
                last_update=last_update.astype("int64"),
                # -1 encodes "no events seen yet"; npz cannot hold None.
                stream_timestamp=np.asarray(
                    -1 if stream_timestamp is None else int(stream_timestamp), dtype="int64"
                ),
                model_version=np.asarray(self.provenance.model_version),
            )
        staging.replace(path)
        warm = int((memory != 0).any(axis=1).sum())
        return {
            "path": str(path),
            "bytes": path.stat().st_size,
            "nodes": int(memory.shape[0]),
            "nodes_with_memory": warm,
            "stream_timestamp": stream_timestamp,
        }

    def load_memory(self, path: Path) -> dict[str, object]:
        """Restore node memory written by :meth:`save_memory`.

        Refuses a snapshot from a different checkpoint: memory vectors are
        only meaningful to the network that produced them, and silently
        loading another model's memory would be worse than starting cold.
        """
        import numpy as np

        with np.load(path, allow_pickle=False) as data:
            version = int(data["version"])
            if version != self.STATE_VERSION:
                raise ValueError(
                    f"memory snapshot version {version} is not supported "
                    f"(expected {self.STATE_VERSION})"
                )
            model_version = str(data["model_version"])
            if model_version != self.provenance.model_version:
                raise ValueError(
                    f"memory snapshot belongs to model {model_version!r}, but this "
                    f"session loaded {self.provenance.model_version!r}"
                )
            memory = torch.tensor(data["memory"], dtype=torch.float32, device=self.device)
            last_update = torch.tensor(data["last_update"], dtype=torch.long, device=self.device)
            stream_timestamp = int(data["stream_timestamp"])

        with self._lock:
            if memory.shape != self._state.memory.shape:
                raise ValueError(
                    f"memory snapshot shape {tuple(memory.shape)} does not match "
                    f"model state {tuple(self._state.memory.shape)}"
                )
            self._state = TGNState(
                memory=memory,
                last_update=last_update,
                stream_timestamp=None if stream_timestamp < 0 else stream_timestamp,
            )
            self._state_version += 1
        warm = int((memory != 0).any(dim=1).sum())
        return {
            "nodes": int(memory.shape[0]),
            "nodes_with_memory": warm,
            "stream_timestamp": self._state.stream_timestamp,
        }

    def memory_coverage(self) -> dict[str, object]:
        """How many entities this session actually knows anything about."""
        with self._lock:
            memory = self._state.memory
            warm = int((memory != 0).any(dim=1).sum())
            total = int(memory.shape[0])
            return {
                "nodes": total,
                "nodes_with_memory": warm,
                "warm_fraction": round(warm / max(1, total), 6),
                "stream_timestamp": self._state.stream_timestamp,
            }

    def memory_snapshot(self) -> tuple[tuple[float, ...], ...]:
        """Read-only snapshot of every node's current temporal memory vector.

        Indexed by the unified ``NodeIdSpace`` global node ID (users first,
        then hosts) — the same layout ``embedding_search`` expects.
        """

        with self._lock:
            return tuple(tuple(row) for row in self._state.memory.detach().cpu().tolist())

    def _to_temporal(self, event: InferenceEvent) -> TemporalGraphEvent:
        return TemporalGraphEvent(
            event_id=event.event_id,
            timestamp=event.timestamp,
            source_node=self.id_space.user(event.user_id),
            destination_node=self.id_space.host(event.destination_host_id),
            origin_host_node=self.id_space.host(event.source_host_id),
            message=event.message,
            label_redteam=0,
        )


def load_inference_session(
    path: Path,
    *,
    expected_feature_version: str = "auth-causal-v1",
    device: torch.device | str = "cpu",
) -> TGNInferenceSession:
    """Load tensors with restricted unpickling and enforce artifact compatibility."""

    if not path.is_file():
        raise FileNotFoundError(path)
    actual_device = "cuda" if str(device).startswith("cuda") and torch.cuda.is_available() else "cpu"
    try:
        payload = torch.load(path, map_location=actual_device, weights_only=True)
    except Exception as error:
        raise CheckpointError(f"cannot safely load checkpoint: {error}") from error
    root = _required_mapping(payload, "root")
    if root.get("schema_version") != 1 or root.get("model") != "TemporalGraphNetwork":
        raise CheckpointError("unsupported checkpoint schema or model type")
    configuration = dict(_required_mapping(root.get("configuration"), "configuration"))
    required_configuration = {
        "num_nodes",
        "message_dim",
        "memory_dim",
        "time_dim",
        "hidden_dim",
        "dropout",
    }
    # ``use_memory`` was added for the memory-ablation experiments. Checkpoints
    # written before it exist without the key and must keep loading -- the
    # model defaults it to True, which is exactly how they were trained. A
    # checkpoint that carries it must carry a boolean, since a memoryless
    # model served as if it read memory would score every event differently.
    optional_configuration = {"use_memory"}
    fields = set(configuration)
    if not required_configuration <= fields or not fields <= (
        required_configuration | optional_configuration
    ):
        raise CheckpointError("checkpoint configuration fields do not match serving contract")
    if "use_memory" in configuration and not isinstance(configuration["use_memory"], bool):
        raise CheckpointError("checkpoint use_memory must be a boolean")
    metadata = _required_mapping(root.get("metadata"), "metadata")
    feature_version = metadata.get("feature_version")
    if feature_version != expected_feature_version:
        raise CheckpointError(
            f"feature version mismatch: expected {expected_feature_version!r}, "
            f"found {feature_version!r}"
        )
    try:
        user_capacity = int(metadata["user_capacity"])
        host_capacity = int(metadata["host_capacity"])
        user_dictionary_capacity = int(metadata.get("user_dictionary_capacity", user_capacity))
        host_dictionary_capacity = int(metadata.get("host_dictionary_capacity", host_capacity))
        oov_user_buckets = int(metadata.get("oov_user_buckets", 0))
        oov_host_buckets = int(metadata.get("oov_host_buckets", 0))
        model_version = str(metadata["model_version"])
        model = TemporalGraphNetwork(**configuration)
        state_dict = _required_mapping(root.get("state_dict"), "state_dict")
        model.load_state_dict(state_dict, strict=True)
        id_space = NodeIdSpace(
            user_capacity=user_capacity,
            host_capacity=host_capacity,
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        raise CheckpointError(f"invalid checkpoint contents: {error}") from error
    feature_names_value = metadata.get("feature_names", ())
    center_value = metadata.get("feature_center", ())
    scale_value = metadata.get("feature_scale", ())
    if not isinstance(feature_names_value, (list, tuple)) or not all(
        isinstance(name, str) for name in feature_names_value
    ):
        raise CheckpointError("checkpoint feature names must be strings")
    if feature_names_value and tuple(feature_names_value) != MODEL_FEATURE_NAMES:
        raise CheckpointError("checkpoint feature names do not match the serving contract")
    try:
        feature_center = tuple(float(value) for value in center_value)
        feature_scale = tuple(float(value) for value in scale_value)
    except (TypeError, ValueError) as error:
        raise CheckpointError("checkpoint feature normalization is invalid") from error
    if bool(feature_center) != bool(feature_scale) or (
        feature_center and len(feature_center) != model.message_dim
    ):
        raise CheckpointError("checkpoint feature normalization width is invalid")
    if any(value <= 0 for value in feature_scale):
        raise CheckpointError("checkpoint feature scales must be positive")
    decision_threshold_value = metadata.get("decision_threshold")
    decision_threshold = (
        float(decision_threshold_value) if decision_threshold_value is not None else None
    )
    if decision_threshold is not None and not 0 <= decision_threshold <= 1:
        raise CheckpointError("checkpoint decision threshold must be in [0, 1]")
    dictionary_hash_value = metadata.get("entity_dictionary_sha256")
    if dictionary_hash_value is not None and not _valid_sha256(dictionary_hash_value):
        raise CheckpointError("checkpoint entity dictionary hash is invalid")
    feature_contract_hash_value = metadata.get("feature_contract_sha256")
    if feature_contract_hash_value is not None and not _valid_sha256(feature_contract_hash_value):
        raise CheckpointError("checkpoint feature contract hash is invalid")
    dataset_hash_value = metadata.get("dataset_sha256")
    if dataset_hash_value is not None and not _valid_sha256(dataset_hash_value):
        raise CheckpointError("checkpoint dataset hash is invalid")
    training_run_hash_value = metadata.get("training_run_sha256")
    if training_run_hash_value is not None and not _valid_sha256(training_run_hash_value):
        raise CheckpointError("checkpoint training run hash is invalid")
    if model.num_nodes != id_space.node_count:
        raise CheckpointError("checkpoint node capacities do not sum to model num_nodes")
    if (
        user_dictionary_capacity <= 0
        or host_dictionary_capacity <= 0
        or oov_user_buckets < 0
        or oov_host_buckets < 0
        or user_dictionary_capacity + oov_user_buckets != user_capacity
        or host_dictionary_capacity + oov_host_buckets != host_capacity
    ):
        raise CheckpointError("checkpoint dictionary and OOV capacities are inconsistent")
    provenance = CheckpointProvenance(
        path=str(path.resolve()),
        sha256=_sha256(path),
        feature_version=str(feature_version),
        model_version=model_version,
        user_capacity=user_capacity,
        host_capacity=host_capacity,
        configuration=cast(dict[str, int | float], configuration),
        user_dictionary_capacity=user_dictionary_capacity,
        host_dictionary_capacity=host_dictionary_capacity,
        oov_user_buckets=oov_user_buckets,
        oov_host_buckets=oov_host_buckets,
        feature_names=tuple(feature_names_value),
        feature_center=feature_center,
        feature_scale=feature_scale,
        decision_threshold=decision_threshold,
        entity_dictionary_sha256=dictionary_hash_value,
        feature_contract_sha256=feature_contract_hash_value,
        dataset_sha256=dataset_hash_value,
        training_run_sha256=training_run_hash_value,
    )
    return TGNInferenceSession(
        model=model,
        id_space=id_space,
        provenance=provenance,
        device=actual_device,
    )
