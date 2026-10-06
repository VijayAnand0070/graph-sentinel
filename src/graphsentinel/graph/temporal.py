"""Framework-neutral temporal graph stream with score-before-update semantics."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass

from graphsentinel.features.causal import MODEL_FEATURE_NAMES, FeatureRecord


@dataclass(frozen=True, slots=True)
class NodeIdSpace:
    """Map typed local IDs into one collision-free homogeneous tensor ID space."""

    user_capacity: int
    host_capacity: int

    def __post_init__(self) -> None:
        if self.user_capacity <= 0 or self.host_capacity <= 0:
            raise ValueError("node capacities must be positive and include unknown ID zero")

    @property
    def node_count(self) -> int:
        return self.user_capacity + self.host_capacity

    def user(self, local_id: int) -> int:
        if not 0 <= local_id < self.user_capacity:
            raise ValueError(f"user ID {local_id} exceeds capacity")
        return local_id

    def host(self, local_id: int) -> int:
        if not 0 <= local_id < self.host_capacity:
            raise ValueError(f"host ID {local_id} exceeds capacity")
        return self.user_capacity + local_id

    def type_of(self, node_id: int) -> str:
        if not 0 <= node_id < self.node_count:
            raise ValueError(f"global node ID {node_id} exceeds capacity")
        return "user" if node_id < self.user_capacity else "host"


@dataclass(frozen=True, slots=True)
class TemporalGraphEvent:
    event_id: int
    timestamp: int
    source_node: int
    destination_node: int
    origin_host_node: int
    message: tuple[float, ...]
    label_redteam: int
    #: Contribution to the training loss. 1.0 is an ordinary labelled event;
    #: 0.0 keeps the event in the stream (memory still sees it, exactly as an
    #: unlabelled event would be seen in deployment) but gives the model no
    #: gradient from its label. Used to hold an attacker entity out of training
    #: without disturbing the chronological split or the replay.
    loss_weight: float = 1.0

    @classmethod
    def from_feature_record(
        cls, record: FeatureRecord, id_space: NodeIdSpace
    ) -> TemporalGraphEvent:
        return cls(
            event_id=record.event_id,
            timestamp=record.timestamp,
            source_node=id_space.user(record.src_user_id),
            destination_node=id_space.host(record.dst_host_id),
            origin_host_node=id_space.host(record.src_host_id),
            message=tuple(float(getattr(record, name)) for name in MODEL_FEATURE_NAMES),
            label_redteam=record.label_redteam,
        )


@dataclass(frozen=True, slots=True)
class NeighborInteraction:
    event_id: int
    timestamp: int
    neighbor_node: int
    outgoing: bool


@dataclass(frozen=True, slots=True)
class TemporalContext:
    event: TemporalGraphEvent
    source_neighbors: tuple[NeighborInteraction, ...]
    destination_neighbors: tuple[NeighborInteraction, ...]


class RecentNeighborStore:
    """Bounded temporal neighborhoods updated only after a timestamp group is queried."""

    def __init__(self, *, max_neighbors: int = 20, window_seconds: int | None = None) -> None:
        if max_neighbors <= 0:
            raise ValueError("max_neighbors must be positive")
        if window_seconds is not None and window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_neighbors = max_neighbors
        self.window_seconds = window_seconds
        self._neighbors: dict[int, deque[NeighborInteraction]] = defaultdict(deque)
        self._last_timestamp: int | None = None

    def neighbors_before(self, node_id: int, timestamp: int) -> tuple[NeighborInteraction, ...]:
        history = self._neighbors[node_id]
        if self.window_seconds is not None:
            cutoff = timestamp - self.window_seconds
            while history and history[0].timestamp <= cutoff:
                history.popleft()
        return tuple(interaction for interaction in history if interaction.timestamp < timestamp)

    def contextualize_group(
        self, events: Sequence[TemporalGraphEvent]
    ) -> tuple[TemporalContext, ...]:
        """Fetch all contexts first, then publish the group's interactions."""

        if not events:
            return ()
        timestamp = events[0].timestamp
        if any(event.timestamp != timestamp for event in events):
            raise ValueError("contextualize_group requires one shared timestamp")
        if self._last_timestamp is not None and timestamp <= self._last_timestamp:
            raise ValueError("timestamp groups must strictly increase; combine equal timestamps")
        contexts = tuple(
            TemporalContext(
                event=event,
                source_neighbors=self.neighbors_before(event.source_node, timestamp),
                destination_neighbors=self.neighbors_before(event.destination_node, timestamp),
            )
            for event in events
        )
        for event in events:
            self._append(
                event.source_node,
                NeighborInteraction(
                    event_id=event.event_id,
                    timestamp=timestamp,
                    neighbor_node=event.destination_node,
                    outgoing=True,
                ),
            )
            self._append(
                event.destination_node,
                NeighborInteraction(
                    event_id=event.event_id,
                    timestamp=timestamp,
                    neighbor_node=event.source_node,
                    outgoing=False,
                ),
            )
        self._last_timestamp = timestamp
        return contexts

    def _append(self, node_id: int, interaction: NeighborInteraction) -> None:
        history = self._neighbors[node_id]
        history.append(interaction)
        while len(history) > self.max_neighbors:
            history.popleft()
