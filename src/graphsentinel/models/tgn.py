"""Trainable temporal-memory detector with explicit immutable stream state.

Architecture highlights:
- Attention-weighted message aggregation (replaces uniform mean)
- LayerNorm gating before GRU update for stable gradients
- Residual projection in the edge classifier
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any, cast

import torch
from torch import Tensor, nn

from graphsentinel.graph.temporal import TemporalGraphEvent


@dataclass(frozen=True, slots=True)
class TemporalBatch:
    """A tensor batch containing events from exactly one timestamp (or, with
    ``allow_time_window``, one bounded time window — see ``from_events``)."""

    source: Tensor
    destination: Tensor
    origin_host: Tensor
    timestamp: int
    message: Tensor
    labels: Tensor
    event_ids: Tensor
    #: Per-event loss weights; ``None`` means every event weighs 1.0.
    loss_weight: Tensor | None = None

    @classmethod
    def from_events(
        cls,
        events: list[TemporalGraphEvent],
        *,
        device: torch.device | str = "cpu",
        allow_time_window: bool = False,
    ) -> TemporalBatch:
        if not events:
            raise ValueError("a temporal batch cannot be empty")
        if allow_time_window:
            # Widened batches (see training.time_window_groups): the caller
            # has already bounded the spread to a deliberately small window.
            # Use the window's latest timestamp for the elapsed-time feature
            # computed in TemporalGraphNetwork._time_context — this makes
            # early-window events look slightly *older* than they truly are
            # (a conservative bias) rather than risking the reverse.
            if any(current.timestamp < previous.timestamp for previous, current in pairwise(events)):
                raise ValueError("windowed batch events must be non-decreasing")
            timestamp = events[-1].timestamp
        else:
            timestamp = events[0].timestamp
            if any(event.timestamp != timestamp for event in events):
                raise ValueError("a temporal batch must contain one shared timestamp")
        message_dim = len(events[0].message)
        if message_dim == 0 or any(len(event.message) != message_dim for event in events):
            raise ValueError("event messages must have one shared, non-zero width")
        return cls(
            source=torch.tensor([event.source_node for event in events], device=device),
            destination=torch.tensor([event.destination_node for event in events], device=device),
            origin_host=torch.tensor([event.origin_host_node for event in events], device=device),
            timestamp=timestamp,
            message=torch.tensor(
                [event.message for event in events], dtype=torch.float32, device=device
            ),
            labels=torch.tensor(
                [event.label_redteam for event in events],
                dtype=torch.float32,
                device=device,
            ),
            event_ids=torch.tensor([event.event_id for event in events], device=device),
            loss_weight=(
                None
                if all(event.loss_weight == 1.0 for event in events)
                else torch.tensor(
                    [event.loss_weight for event in events],
                    dtype=torch.float32,
                    device=device,
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class TGNState:
    """Evolving node state, deliberately separate from learned model parameters."""

    memory: Tensor
    last_update: Tensor
    stream_timestamp: int | None = None

    @classmethod
    def initial(
        cls,
        *,
        num_nodes: int,
        memory_dim: int,
        device: torch.device | str = "cpu",
    ) -> TGNState:
        if num_nodes <= 0 or memory_dim <= 0:
            raise ValueError("num_nodes and memory_dim must be positive")
        return cls(
            memory=torch.zeros(num_nodes, memory_dim, device=device),
            last_update=torch.zeros(num_nodes, dtype=torch.long, device=device),
        )

    def detach(self) -> TGNState:
        """Truncate backpropagation while preserving chronological memory values."""

        return TGNState(
            memory=self.memory.detach(),
            last_update=self.last_update.detach(),
            stream_timestamp=self.stream_timestamp,
        )


class HarmonicTimeEncoder(nn.Module):
    """Learnable harmonic encoding for non-negative time deltas."""

    def __init__(self, dimension: int) -> None:
        super().__init__()
        if dimension <= 0:
            raise ValueError("time dimension must be positive")
        frequencies = torch.logspace(0, -6, dimension)
        self.log_frequency = nn.Parameter(frequencies.log())
        self.phase = nn.Parameter(torch.zeros(dimension))

    def forward(self, delta_seconds: Tensor) -> Tensor:
        delta = torch.log1p(delta_seconds.clamp_min(0).float()).unsqueeze(-1)
        return torch.cos(delta * self.log_frequency.exp() + self.phase)


class AttentionMessageAggregator(nn.Module):
    """Attention-weighted aggregation over per-node incoming messages.

    Replaces the previous uniform mean with a learned scalar gate so nodes
    that have seen fewer, more anomalous interactions receive proportionally
    stronger signal updates.
    """

    def __init__(self, message_dim: int, memory_dim: int) -> None:
        super().__init__()
        self.attn = nn.Linear(message_dim + memory_dim, 1, bias=False)

    def forward(
        self,
        unique_nodes: Tensor,
        inverse: Tensor,
        messages: Tensor,
        current_memory: Tensor,
    ) -> Tensor:
        """Vectorized scatter-softmax: one pass over messages, no per-node Python loop.

        A Python loop over ``unique_nodes`` here would launch a handful of tiny CUDA
        kernels per node per timestamp group; across the many small groups a
        chronological event stream produces, that overhead dominates wall-clock
        time. This computes the same per-node softmax with a fixed number of
        vectorized ops regardless of how many groups or nodes are involved.
        """

        node_memory_for_msgs = current_memory[unique_nodes][inverse]
        raw_attn = self.attn(torch.cat((messages, node_memory_for_msgs), dim=-1)).squeeze(-1)
        n = len(unique_nodes)
        group_max = torch.full((n,), float("-inf"), device=messages.device, dtype=raw_attn.dtype)
        group_max = group_max.scatter_reduce(0, inverse, raw_attn, reduce="amax", include_self=False)
        shifted = (raw_attn - group_max[inverse]).exp()
        group_sum = torch.zeros(n, device=messages.device, dtype=shifted.dtype)
        group_sum = group_sum.index_add(0, inverse, shifted)
        attn_weights = shifted / group_sum[inverse].clamp_min(1e-12)
        aggregated = torch.zeros(n, messages.shape[-1], device=messages.device, dtype=messages.dtype)
        aggregated = aggregated.index_add(0, inverse, attn_weights.unsqueeze(-1) * messages)
        return aggregated


class TemporalGraphNetwork(nn.Module):
    """TGN-style event scorer with attention-weighted node memory.

    Improvements over the baseline:
    - Attention aggregation instead of uniform mean: each incoming message
      is weighted by its relevance to the current node memory, allowing the
      model to suppress noisy edges and amplify anomalous ones.
    - Pre-GRU LayerNorm stabilises gradient flow during TBPTT.
    - Residual projection in the edge classifier keeps gradient paths short.

    ``score`` never mutates state. ``update`` returns a new state and aggregates
    all messages at the shared timestamp before updating each affected node once.
    """

    def __init__(
        self,
        *,
        num_nodes: int,
        message_dim: int,
        memory_dim: int = 128,
        time_dim: int = 32,
        hidden_dim: int = 128,
        dropout: float = 0.1,
        use_memory: bool = True,
    ) -> None:
        super().__init__()
        if num_nodes <= 0 or message_dim <= 0 or memory_dim <= 0 or hidden_dim <= 0:
            raise ValueError("model dimensions must be positive")
        if not 0 <= dropout < 1:
            raise ValueError("dropout must be in [0, 1)")
        self.num_nodes = num_nodes
        self.message_dim = message_dim
        self.memory_dim = memory_dim
        self.time_dim = time_dim
        self.hidden_dim = hidden_dim
        self.dropout = dropout
        #: Ablation switch. When False the scorer reads zeros in place of every
        #: node memory, so the prediction depends only on the message features
        #: and the elapsed-time context. Memory is still *updated*, because the
        #: time context needs ``last_update`` to be real. This is the control
        #: that says what the graph memory adds over the hand-built features --
        #: without it, a strong result cannot be attributed to the "TGN" part.
        self.use_memory = use_memory
        self.time_encoder = HarmonicTimeEncoder(time_dim)
        update_input = 2 * memory_dim + message_dim + 2 * time_dim
        self.message_function = nn.Sequential(
            nn.Linear(update_input, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, memory_dim),
        )
        self.message_aggregator = AttentionMessageAggregator(memory_dim, memory_dim)
        self.pre_gru_norm = nn.LayerNorm(memory_dim)
        self.memory_updater = nn.GRUCell(memory_dim, memory_dim)
        score_input = 3 * memory_dim + message_dim + 2 * time_dim
        # Residual projection: project score_input → hidden_dim in a skip path,
        # then add to the main branch before the final linear.
        self.score_proj = nn.Linear(score_input, hidden_dim, bias=False)
        self.edge_classifier = nn.Sequential(
            nn.Linear(score_input, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
        )
        self.score_head = nn.Linear(hidden_dim, 1)

    def initial_state(self, *, device: torch.device | str = "cpu") -> TGNState:
        return TGNState.initial(num_nodes=self.num_nodes, memory_dim=self.memory_dim, device=device)

    def _validate(self, batch: TemporalBatch, state: TGNState) -> None:
        if state.memory.shape != (self.num_nodes, self.memory_dim):
            raise ValueError("state memory shape does not match model configuration")
        if batch.message.ndim != 2 or batch.message.shape[1] != self.message_dim:
            raise ValueError("batch message width does not match model configuration")
        if state.stream_timestamp is not None and batch.timestamp <= state.stream_timestamp:
            raise ValueError("temporal batches must have strictly increasing timestamps")
        nodes = torch.cat((batch.source, batch.destination, batch.origin_host))
        if bool((nodes < 0).any()) or bool((nodes >= self.num_nodes).any()):
            raise ValueError("batch contains a node outside the configured ID space")

    def _time_context(self, node_ids: Tensor, timestamp: int, state: TGNState) -> Tensor:
        current = torch.full_like(node_ids, timestamp)
        delta = current - state.last_update[node_ids]
        return cast(Tensor, self.time_encoder(delta))

    def score(self, batch: TemporalBatch, state: TGNState) -> Tensor:
        """Return pre-update logits for one timestamp group without mutating state."""

        self._validate(batch, state)
        source_memory = state.memory[batch.source]
        destination_memory = state.memory[batch.destination]
        origin_memory = state.memory[batch.origin_host]
        if not self.use_memory:
            source_memory = torch.zeros_like(source_memory)
            destination_memory = torch.zeros_like(destination_memory)
            origin_memory = torch.zeros_like(origin_memory)
        source_time = self._time_context(batch.source, batch.timestamp, state)
        destination_time = self._time_context(batch.destination, batch.timestamp, state)
        inputs = torch.cat(
            (
                source_memory,
                destination_memory,
                origin_memory,
                batch.message,
                source_time,
                destination_time,
            ),
            dim=1,
        )
        residual = self.score_proj(inputs)
        hidden = self.edge_classifier(inputs)
        return cast(Tensor, self.score_head(hidden + residual).squeeze(-1))

    def update(self, batch: TemporalBatch, state: TGNState) -> TGNState:
        """Aggregate endpoint messages with attention and return the post-event state."""

        self._validate(batch, state)
        source_memory = state.memory[batch.source]
        destination_memory = state.memory[batch.destination]
        source_time = self._time_context(batch.source, batch.timestamp, state)
        destination_time = self._time_context(batch.destination, batch.timestamp, state)
        source_messages = self.message_function(
            torch.cat(
                (
                    source_memory,
                    destination_memory,
                    batch.message,
                    source_time,
                    destination_time,
                ),
                dim=1,
            )
        )
        destination_messages = self.message_function(
            torch.cat(
                (
                    destination_memory,
                    source_memory,
                    batch.message,
                    destination_time,
                    source_time,
                ),
                dim=1,
            )
        )
        affected = torch.cat((batch.source, batch.destination))
        messages = torch.cat((source_messages, destination_messages))
        unique_nodes, inverse = torch.unique(affected, sorted=True, return_inverse=True)
        aggregated = self.message_aggregator(unique_nodes, inverse, messages, state.memory)
        normed = self.pre_gru_norm(aggregated)
        updated = self.memory_updater(normed, state.memory[unique_nodes])
        memory = state.memory.index_copy(0, unique_nodes, updated)
        last_update = state.last_update.index_fill(0, unique_nodes, batch.timestamp)
        return TGNState(
            memory=memory,
            last_update=last_update,
            stream_timestamp=batch.timestamp,
        )

    def step(self, batch: TemporalBatch, state: TGNState) -> tuple[Tensor, TGNState]:
        """Score first, then produce the updated state."""

        logits = self.score(batch, state)
        return logits, self.update(batch, state)

    def configuration(self) -> dict[str, int | float]:
        return {
            "num_nodes": self.num_nodes,
            "message_dim": self.message_dim,
            "memory_dim": self.memory_dim,
            "time_dim": self.time_dim,
            "hidden_dim": self.hidden_dim,
            "dropout": self.dropout,
            "use_memory": self.use_memory,
        }

    def save_checkpoint(self, path: Path, *, metadata: dict[str, Any]) -> None:
        """Atomically persist weights, architecture, and caller-supplied provenance."""

        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        torch.save(
            {
                "schema_version": 1,
                "model": "TemporalGraphNetwork",
                "configuration": self.configuration(),
                "state_dict": self.state_dict(),
                "metadata": metadata,
            },
            temporary,
        )
        temporary.replace(path)


def to_pyg_temporal_data(
    events: list[TemporalGraphEvent], *, device: torch.device | str = "cpu"
) -> Any:
    """Convert ordered events to PyG TemporalData without changing the core graph contract."""

    if not events:
        raise ValueError("cannot convert an empty temporal stream")
    try:
        from torch_geometric.data import TemporalData  # type: ignore[import-untyped]
    except ImportError as error:
        raise RuntimeError('Install graph dependencies with: pip install -e ".[ml]"') from error
    message_dim = len(events[0].message)
    if any(len(event.message) != message_dim for event in events):
        raise ValueError("all event messages must have one width")
    data = TemporalData(
        src=torch.tensor([event.source_node for event in events], device=device),
        dst=torch.tensor([event.destination_node for event in events], device=device),
        t=torch.tensor([event.timestamp for event in events], device=device),
        msg=torch.tensor([event.message for event in events], dtype=torch.float32, device=device),
        y=torch.tensor(
            [event.label_redteam for event in events], dtype=torch.float32, device=device
        ),
    )
    data.origin_host = torch.tensor([event.origin_host_node for event in events], device=device)
    data.event_id = torch.tensor([event.event_id for event in events], device=device)
    return data
