"""Transactional live authentication normalization and detection gateway."""

from __future__ import annotations

import gzip
import hashlib
import json as _json
import logging
import os
from collections import Counter, OrderedDict
from itertools import groupby
from pathlib import Path
from threading import RLock
from typing import Literal

from graphsentinel.api.schemas import (
    LiveAuthBatch,
    LiveAuthEvent,
    LiveDetectionStatus,
    RiskComponentInput,
    ScoreBatchRequest,
    ScoreBatchResponse,
    ScoreEventRequest,
    TacticVerdict,
)
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.policy import (
    CORROBORATED,
    DEFAULT_CHAIN_RULE,
    DEFAULT_POLICY,
    ChainRuleConfig,
    ChainRulePolicy,
)

logger = logging.getLogger(__name__)

from graphsentinel.detection.tactics import TacticClassification, TacticEngine
from graphsentinel.features.causal import MODEL_FEATURE_NAMES, CausalFeatureEngine, FeatureRecord
from graphsentinel.ingestion.auth import SECONDS_PER_DAY, NormalizedAuthEvent
from graphsentinel.ingestion.id_map import AuthIdMaps, StableIdMap, auth_id_map_sha256
from graphsentinel.models.serving import TGNInferenceSession
from graphsentinel.models.transfer_serving import TransferInferenceSession, transfer_message


def _provenance_int(provenance: dict[str, object] | None, name: str) -> int:
    value = provenance.get(name) if provenance else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _tactic_verdict(classification: TacticClassification) -> TacticVerdict | None:
    """Translate the detection-layer verdict into the API schema.

    Returns None when nothing was indicated, rather than a zero-score entry:
    an empty technique id in a report reads as "unclassified attack" when the
    truth is "no technique matched".
    """
    if classification.primary is None:
        return None
    primary = classification.primary
    return TacticVerdict(
        technique_id=primary.technique_id,
        name=primary.name,
        tactic=primary.tactic,
        score=primary.score,
        confidence=classification.confidence,
        evidence=primary.evidence,
        alternatives=tuple(
            item.technique_id for item in classification.scores[1:]
        ),
    )


def _feature_state_path() -> Path | None:
    raw = os.getenv("GRAPHSENTINEL_FEATURE_STATE", "").strip()
    return Path(raw) if raw else None


class LiveDetectionEngine:
    """Apply the offline causal feature contract to a chronological live stream."""

    def __init__(
        self,
        detection: DetectionService,
        *,
        id_map_dir: Path | None = None,
        idempotency_capacity: int = 10_000,
        policy: ChainRulePolicy = DEFAULT_POLICY,
        chain_rule: ChainRuleConfig = DEFAULT_CHAIN_RULE,
    ) -> None:
        if idempotency_capacity <= 0:
            raise ValueError("idempotency_capacity must be positive")
        self.detection = detection
        self._id_map_dir = id_map_dir
        if detection.model_kind == "transfer" and policy is DEFAULT_POLICY:
            # Priced at full rate on LANL, the chain rule alone flags ~536
            # ordinary authentications a day and the fan-out rule ~7: far above
            # an unattended-action budget. With the label-free model, a rule
            # therefore raises an event to the execution gate only when the
            # estate-calibrated model already put it over the alert budget.
            policy = CORROBORATED
        # What a rule-detected chain may do, and the rule's shape. One policy
        # governs both halves: this engine builds the tracker from the rule
        # and lets the tactic engine assert T1021 only when the policy says
        # so, and the detection service raises the fused risk to the policy's
        # floor -- set here so the two cannot be configured apart.
        self.policy = policy
        self.chain_rule = chain_rule
        detection.chain_rule_floor = policy.floor
        detection.chain_rule_requires_alert = policy.requires_model_alert
        self._idempotency_capacity = idempotency_capacity
        self._lock = RLock()
        self._features = CausalFeatureEngine()
        # Twelve of the 27 features are cumulative and no amount of warm-up
        # rebuilds them, so a process restart used to permanently degrade
        # detection with no signal that anything had changed. Restore the
        # engine's state if a snapshot was built at onboarding.
        self._feature_state_path = _feature_state_path()
        self._feature_state_loaded = self._load_feature_state()
        # The pivot channel and the chain rule read one shared, windowed
        # signal state -- the same class the offline scorer advances, so the
        # evaluation and the deployment cannot compute different channels.
        self._signals = chain_rule.tracker()
        self._accepted_events = 0
        self._rejected_batches = 0
        self._duplicate_batches = 0
        self._last_timestamp: int | None = None
        self._sources: Counter[str] = Counter()
        self._receipts: OrderedDict[str, tuple[str, ScoreBatchResponse]] = OrderedDict()
        has_maps = bool(id_map_dir and (id_map_dir / "users.json").is_file())
        # The first model reads the frozen dictionary it was trained with. The
        # transfer model has no dictionary: the maps it is given (onboarding's)
        # keep growing as the estate shows new accounts and hosts.
        self._frozen_maps = has_maps and detection.requires_frozen_dictionary
        self._maps = AuthIdMaps.load(id_map_dir) if has_maps and id_map_dir else AuthIdMaps()
        self._dictionary_hash = (
            auth_id_map_sha256(id_map_dir) if has_maps and id_map_dir else None
        )
        self._model_generation = int(detection.model_loaded)
        self._state_reset_count = 0
        self._oov_identifiers: Counter[str] = Counter()
        # Tactic attribution runs on the same FeatureRecord the risk
        # channels are derived from, so it costs one pass and cannot
        # disagree with the score about what the event looked like.
        self._tactics = TacticEngine()
        provenance = detection.model_provenance()
        self._user_dictionary_capacity = _provenance_int(provenance, "user_dictionary_capacity")
        self._host_dictionary_capacity = _provenance_int(provenance, "host_dictionary_capacity")
        self._oov_user_buckets = _provenance_int(provenance, "oov_user_buckets")
        self._oov_host_buckets = _provenance_int(provenance, "oov_host_buckets")
        expected_dictionary = provenance.get("entity_dictionary_sha256") if provenance else None
        if expected_dictionary:
            assert provenance is not None
            required_lineage = (
                "feature_contract_sha256",
                "dataset_sha256",
                "training_run_sha256",
                "decision_threshold",
            )
            if any(provenance.get(name) is None for name in required_lineage):
                raise ValueError("trained model is missing required serving lineage")
            if not provenance.get("feature_names") or not provenance.get("feature_center"):
                raise ValueError("trained model is missing its feature and normalization contract")
            if not self._frozen_maps or id_map_dir is None:
                raise ValueError("trained model requires its frozen entity dictionary")
            if self._dictionary_hash != expected_dictionary:
                raise ValueError("entity dictionary hash does not match trained model")
            if (
                len(self._maps.users) != self._user_dictionary_capacity
                or len(self._maps.hosts) != self._host_dictionary_capacity
            ):
                raise ValueError("entity dictionary capacities do not match trained model")

    def entity_names(self) -> dict[str, tuple[str, ...]]:
        """Expose the loaded ID-map value lists for read-only ID-to-name resolution."""
        with self._lock:
            return {
                "users": tuple(self._maps.users.to_dict()["values"]),
                "hosts": tuple(self._maps.hosts.to_dict()["values"]),
            }

    def _load_feature_state(self) -> bool:
        """Restore cumulative feature state from disk, if a snapshot exists.

        A missing or unreadable snapshot is not fatal -- the engine simply
        starts cold, which is the previous behaviour -- but it IS reported
        through ``status()`` so a cold start is visible rather than inferred
        from degraded detection weeks later.
        """
        path = self._feature_state_path
        if path is None or not path.is_file():
            return False
        try:
            opener = gzip.open if path.suffix == ".gz" else open
            with opener(path, "rt", encoding="utf-8") as handle:
                self._features.restore(_json.load(handle))
            return True
        except (OSError, ValueError, KeyError) as error:
            logger.warning("feature state snapshot could not be restored: %s", error)
            return False

    def save_feature_state(self, path: Path | None = None) -> dict[str, object]:
        """Write the current cumulative state so a restart can resume from it."""
        target = path or self._feature_state_path
        if target is None:
            raise ValueError(
                "no feature state path configured; set GRAPHSENTINEL_FEATURE_STATE"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            snapshot = self._features.snapshot()
            coverage = self._features.coverage()
        # Written to a sibling then renamed, so a crash mid-write cannot leave
        # a truncated snapshot that would restore as partial history.
        staging = target.with_suffix(target.suffix + ".tmp")
        opener = gzip.open if target.suffix == ".gz" else open
        with opener(staging, "wt", encoding="utf-8") as handle:
            _json.dump(snapshot, handle)
        staging.replace(target)
        return {"path": str(target), "bytes": target.stat().st_size, "coverage": coverage}

    def save_state(self, *, memory_path: Path | None) -> dict[str, object]:
        """Persist both halves of the cumulative state under one lock.

        The feature snapshot and the model's node memory are written while no
        batch can commit between them, so what a restart restores is a state
        the stream actually passed through. A loaded model with no memory
        path is reported, not silently skipped.
        """
        with self._lock:
            saved = self.save_feature_state()
            memory = (
                self.detection.save_memory(memory_path)
                if memory_path is not None and self.detection.model_loaded
                else None
            )
        warning = None
        if self.detection.model_loaded and memory_path is None:
            warning = (
                "GRAPHSENTINEL_TGN_MEMORY is not set: node memory was not persisted, so a "
                "restart would restore features newer than the memory"
            )
        return {**saved, "model_memory": memory, "warning": warning}

    def feature_coverage(self) -> dict[str, object]:
        with self._lock:
            coverage = dict(self._features.coverage())
        coverage["restored_from_snapshot"] = self._feature_state_loaded
        coverage["snapshot_path"] = (
            str(self._feature_state_path) if self._feature_state_path else None
        )
        return coverage

    def status(self) -> LiveDetectionStatus:
        with self._lock:
            return LiveDetectionStatus(
                mode=(
                    "temporal_model"
                    if self.detection.model_loaded and self._frozen_maps
                    else "configuration_error"
                    if self.detection.model_loaded
                    else "explainable_fallback"
                ),
                accepted_events=self._accepted_events,
                rejected_batches=self._rejected_batches,
                duplicate_batches=self._duplicate_batches,
                last_timestamp=self._last_timestamp,
                sources=dict(self._sources),
                oov_identifiers=dict(self._oov_identifiers),
                frozen_entity_dictionary=self._frozen_maps,
                model_contract_ready=not self.detection.requires_frozen_dictionary or self._frozen_maps,
                entity_dictionary_sha256=self._dictionary_hash,
                model_generation=self._model_generation,
                state_reset_count=self._state_reset_count,
                idempotency_capacity=self._idempotency_capacity,
            )

    def _message(self, record: FeatureRecord, raw: LiveAuthEvent) -> tuple[float, ...]:
        """The model's input for one event, in the loaded model's contract."""
        if self.detection.model_kind == "transfer":
            return transfer_message(
                record, auth_type=raw.auth_type, logon_type=raw.logon_type, orientation=raw.orientation
            )
        return tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES)

    def _validated_model_maps(
        self, session: TGNInferenceSession | TransferInferenceSession
    ) -> tuple[AuthIdMaps, str | None, bool]:
        """Resolve and validate the entity namespace required by a model candidate."""

        if isinstance(session, TransferInferenceSession):
            # no dictionary to match: keep the growing maps as they are
            return self._maps, self._dictionary_hash, False

        expected_dictionary = session.provenance.entity_dictionary_sha256
        if expected_dictionary is None:
            raise ValueError("live model promotion requires a frozen entity dictionary hash")
        if (
            session.provenance.feature_contract_sha256 is None
            or session.provenance.dataset_sha256 is None
            or session.provenance.training_run_sha256 is None
            or session.provenance.decision_threshold is None
            or not session.provenance.feature_names
            or not session.provenance.feature_center
        ):
            raise ValueError("live model promotion requires complete training lineage")
        maps = self._maps
        dictionary_hash = self._dictionary_hash
        frozen = self._frozen_maps
        if expected_dictionary is not None:
            if self._id_map_dir is None:
                raise ValueError("promoted model requires an entity dictionary directory")
            maps = AuthIdMaps.load(self._id_map_dir)
            dictionary_hash = auth_id_map_sha256(self._id_map_dir)
            if dictionary_hash != expected_dictionary:
                raise ValueError("promoted model entity dictionary hash does not match")
            if (
                len(maps.users) != session.provenance.user_dictionary_capacity
                or len(maps.hosts) != session.provenance.host_dictionary_capacity
            ):
                raise ValueError("promoted model capacities do not match its entity dictionary")
            frozen = True
        return maps, dictionary_hash, frozen

    def validate_model(self, session: TGNInferenceSession | TransferInferenceSession) -> None:
        """Preflight a candidate without changing live inference state."""

        self._validated_model_maps(session)

    def promote_model(self, session: TGNInferenceSession | TransferInferenceSession, *, threshold: float) -> None:
        """Install a model and its exact entity dictionary under the live-stream lock."""

        maps, dictionary_hash, frozen = self._validated_model_maps(session)
        with self._lock:
            self.detection.install_model(session, threshold=threshold)
            self._maps = maps
            self._dictionary_hash = dictionary_hash
            self._frozen_maps = frozen
            legacy = not isinstance(session, TransferInferenceSession)
            self._user_dictionary_capacity = session.provenance.user_dictionary_capacity if legacy else None
            self._host_dictionary_capacity = session.provenance.host_dictionary_capacity if legacy else None
            self._oov_user_buckets = session.provenance.oov_user_buckets if legacy else 0
            self._oov_host_buckets = session.provenance.oov_host_buckets if legacy else 0
            # A new model begins with fresh temporal memory. Reset causal graph state at the
            # same boundary so no feature or entity state crosses incompatible generations.
            self._features = CausalFeatureEngine()
            self._signals = self.chain_rule.tracker()
            self._model_generation += 1
            self._state_reset_count += 1

    def _identifier(
        self,
        mapping: StableIdMap,
        value: str,
        field: str,
        kind: Literal["user", "host", "category"],
        oov_identifiers: Counter[str],
    ) -> int:
        if not self._frozen_maps:
            return mapping.encode(value)
        identifier = mapping.lookup(value)
        if identifier is None:
            if self.detection.model_loaded:
                oov_identifiers[field] += 1
                if kind == "category":
                    return 0
                bucket_count = self._oov_user_buckets if kind == "user" else self._oov_host_buckets
                dictionary_capacity = (
                    self._user_dictionary_capacity
                    if kind == "user"
                    else self._host_dictionary_capacity
                )
                if bucket_count <= 0:
                    raise ValueError(
                        f"unknown {field} {value!r}; this legacy model has no OOV buckets"
                    )
                digest = hashlib.sha256(f"{kind}\0{value}".encode()).digest()
                return dictionary_capacity + int.from_bytes(digest[:8], "big") % bucket_count
            return mapping.encode(value)
        return identifier

    def detect(self, batch: LiveAuthBatch) -> ScoreBatchResponse:
        with self._lock:
            if self.detection.requires_frozen_dictionary and not self._frozen_maps:
                self._rejected_batches += 1
                raise ValueError(
                    "live model scoring requires the frozen entity dictionary used in training"
                )
            fingerprint = hashlib.sha256(
                LiveAuthBatch(events=batch.events).model_dump_json().encode()
            ).hexdigest()
            if batch.batch_id is not None and batch.batch_id in self._receipts:
                prior_fingerprint, response = self._receipts[batch.batch_id]
                if prior_fingerprint != fingerprint:
                    self._rejected_batches += 1
                    raise ValueError("batch_id was already used for different live events")
                self._duplicate_batches += 1
                self._receipts.move_to_end(batch.batch_id)
                return response
            try:
                response = self._detect_locked(batch)
            except Exception:
                self._rejected_batches += 1
                raise
            if batch.batch_id is not None:
                self._receipts[batch.batch_id] = (fingerprint, response)
                self._receipts.move_to_end(batch.batch_id)
                while len(self._receipts) > self._idempotency_capacity:
                    self._receipts.popitem(last=False)
            return response

    def _detect_locked(self, batch: LiveAuthBatch) -> ScoreBatchResponse:
        if self._last_timestamp is not None and batch.events[0].timestamp <= self._last_timestamp:
            raise ValueError(
                "live batches must advance beyond the prior timestamp; combine equal timestamps"
            )
        # Transactional, but scoped. This used to deep-copy the entity
        # dictionaries and the whole feature engine per batch and swap them in
        # on success. With the warm state a deployment must run with, that
        # copy took minutes and, from an async handler, froze every other
        # request including /health. Now the dictionaries take a mark and the
        # engine checkpoints only the entries this batch can reach; on any
        # failure below, both are rolled back and the exception propagates.
        maps = self._maps
        marks = [(m, m.mark()) for _name, m in maps.items()]
        features = self._features
        try:
            return self._detect_transactional(batch, maps, features)
        except BaseException:
            for mapping, mark in marks:
                mapping.rollback(mark)
            raise

    def _detect_transactional(
        self, batch: LiveAuthBatch, maps: AuthIdMaps, features: CausalFeatureEngine
    ) -> ScoreBatchResponse:
        tracker = self._signals
        oov_identifiers = Counter(self._oov_identifiers)
        normalized: list[NormalizedAuthEvent] = []
        raw_by_event: dict[int, LiveAuthEvent] = {}
        for ordinal, raw in enumerate(batch.events):
            source_id = self._identifier(
                maps.hosts,
                raw.source_host,
                "source host",
                "host",
                oov_identifiers,
            )
            destination_id = self._identifier(
                maps.hosts,
                raw.destination_host,
                "destination host",
                "host",
                oov_identifiers,
            )
            if source_id == destination_id:
                raise ValueError("source and destination hosts must resolve to different entities")
            event = NormalizedAuthEvent(
                event_id=raw.timestamp * 1_000_000 + ordinal,
                timestamp=raw.timestamp,
                src_user_id=self._identifier(maps.users, raw.user, "user", "user", oov_identifiers),
                dst_user_id=self._identifier(
                    maps.users,
                    raw.destination_user or raw.user,
                    "destination user",
                    "user",
                    oov_identifiers,
                ),
                src_host_id=source_id,
                dst_host_id=destination_id,
                auth_type_id=self._identifier(
                    maps.auth_types,
                    raw.auth_type,
                    "auth type",
                    "category",
                    oov_identifiers,
                ),
                logon_type_id=self._identifier(
                    maps.logon_types,
                    raw.logon_type,
                    "logon type",
                    "category",
                    oov_identifiers,
                ),
                orientation_id=self._identifier(
                    maps.orientations,
                    raw.orientation,
                    "orientation",
                    "category",
                    oov_identifiers,
                ),
                success=int(raw.success),
                label_redteam=0,
                day=raw.timestamp // SECONDS_PER_DAY,
                hour=(raw.timestamp % SECONDS_PER_DAY) // 3_600,
            )
            normalized.append(event)
            raw_by_event[event.event_id] = raw
        checkpoint = features.checkpoint(normalized)
        try:
            feature_records = tuple(features.transform(normalized))
        except BaseException:
            features.rollback(checkpoint)
            raise
        requests: list[ScoreEventRequest] = []
        for _timestamp, grouped in groupby(feature_records, key=lambda record: record.timestamp):
            group = tuple(grouped)
            for record in group:
                raw = raw_by_event[record.event_id]
                signals, chain_detected = tracker.signals(record)
                # Pass the RAW category names, not the dictionary indices.
                # Indices are per-dictionary; a deployment that builds its own
                # would silently break every category-keyed rule.
                verdict = self._tactics.classify_event(
                    record,
                    signals,
                    user_name=raw.user,
                    logon_type_name=raw.logon_type,
                    auth_type_name=raw.auth_type,
                    orientation_name=raw.orientation,
                    chain_detected=chain_detected and self.policy.asserts_technique,
                )
                self._tactics.observe(
                    record,
                    auth_type_name=raw.auth_type,
                    orientation_name=raw.orientation,
                )
                message = self._message(record, raw)
                fanout_detected = tracker.fanout_hop(record)
                components = RiskComponentInput(
                    tgn=None
                    if self.detection.model_loaded
                    else min(
                        1.0,
                        0.40 * signals.novelty + 0.35 * signals.burst + 0.25 * signals.pivot,
                    ),
                    novelty=signals.novelty,
                    burst=signals.burst,
                    pivot=signals.pivot,
                    corroboration=raw.corroboration,
                )
                requests.append(
                    ScoreEventRequest(
                        event_id=record.event_id,
                        timestamp=record.timestamp,
                        user_id=record.src_user_id,
                        source_host_id=record.src_host_id,
                        destination_host_id=record.dst_host_id,
                        user=raw.user,
                        source_host=raw.source_host,
                        destination_host=raw.destination_host,
                        is_new_pair=bool(record.is_new_pair),
                        user_fanout_5m=record.user_unique_dst_5m,
                        recent_failures=record.failures_before_success_15m,
                        evidence_support=raw.corroboration,
                        message=message if self.detection.model_loaded else None,
                        components=components,
                        tactic=_tactic_verdict(verdict),
                        chain_detected=chain_detected,
                        fanout_detected=fanout_detected,
                    )
                )
            tracker.observe_group(group)
        try:
            response = self.detection.score_batch(ScoreBatchRequest(events=tuple(requests)))
        except BaseException:
            # The model refused the batch (typically a timestamp regression);
            # the features it was computed from must not outlive it, or the
            # engine and the model's memory would disagree about what happened.
            features.rollback(checkpoint)
            raise
        self._oov_identifiers = oov_identifiers
        self._accepted_events += len(batch.events)
        self._last_timestamp = batch.events[-1].timestamp
        self._sources.update(raw.source for raw in batch.events)
        return response
