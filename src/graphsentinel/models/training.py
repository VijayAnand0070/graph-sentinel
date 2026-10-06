"""Chronological training utilities for temporal-memory models."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from itertools import groupby

import torch
from torch import Tensor
from torch.nn import functional as functional

from graphsentinel.graph.temporal import TemporalGraphEvent
from graphsentinel.models.tgn import TemporalBatch, TemporalGraphNetwork, TGNState


@dataclass(frozen=True, slots=True)
class TrainingEpochResult:
    loss: float
    events: int
    positives: int
    optimizer_steps: int
    final_state: TGNState


def timestamp_groups(
    events: Iterable[TemporalGraphEvent],
) -> Iterator[list[TemporalGraphEvent]]:
    previous: int | None = None
    for timestamp, grouped in groupby(events, key=lambda event: event.timestamp):
        if previous is not None and timestamp < previous:
            raise ValueError("training events must be non-decreasing")
        yield list(grouped)
        previous = timestamp


def time_window_groups(
    events: Iterable[TemporalGraphEvent], *, window_seconds: int
) -> Iterator[list[TemporalGraphEvent]]:
    """Group chronologically-sorted events into fixed-width, non-overlapping windows.

    ``timestamp_groups`` requires exact timestamp equality, which for
    real-world auth-log granularity usually yields 1-3 events per group —
    starving the GPU of real batch work and making training almost entirely
    CPU/dispatch-bound (one tiny kernel launch after another). Widening the
    grouping to a time window trades a small amount of temporal precision —
    events sharing a window share one memory-read timestamp for the elapsed-
    time feature in ``TemporalBatch`` — for dramatically fewer, larger
    forward-pass calls. Windows are still strictly non-overlapping and
    increasing, so the model's "strictly increasing batch timestamps"
    invariant holds exactly as it does for exact-timestamp batches.
    """

    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    bucket: list[TemporalGraphEvent] = []
    bucket_start: int | None = None
    previous: int | None = None
    for event in events:
        if previous is not None and event.timestamp < previous:
            raise ValueError("training events must be non-decreasing")
        previous = event.timestamp
        if bucket_start is None:
            bucket_start = event.timestamp
        elif event.timestamp - bucket_start >= window_seconds:
            yield bucket
            bucket = []
            bucket_start = event.timestamp
        bucket.append(event)
    if bucket:
        yield bucket


def weighted_event_loss(
    logits: Tensor,
    labels: Tensor,
    *,
    positive_weight: float,
    event_weights: Tensor | None = None,
) -> Tensor:
    """Class-weighted BCE, optionally weighted per event.

    ``event_weights`` lets an event sit in the stream without teaching the
    model anything: a weight of zero removes it from the loss while its message
    still updates memory. A batch whose weights are all zero contributes a zero
    loss rather than a division by zero.
    """
    if positive_weight <= 0:
        raise ValueError("positive_weight must be positive")
    weight = torch.tensor(positive_weight, dtype=logits.dtype, device=logits.device)
    if event_weights is None:
        return functional.binary_cross_entropy_with_logits(logits, labels, pos_weight=weight)
    if event_weights.shape != logits.shape:
        raise ValueError("event_weights must match logits in shape")
    if bool((event_weights < 0).any()):
        raise ValueError("event_weights must be non-negative")
    per_event = functional.binary_cross_entropy_with_logits(
        logits, labels, pos_weight=weight, reduction="none"
    )
    total = event_weights.sum()
    if float(total) == 0.0:
        return per_event.sum() * 0.0
    return (per_event * event_weights).sum() / total


def train_epoch(
    model: TemporalGraphNetwork,
    events: Iterable[TemporalGraphEvent],
    optimizer: torch.optim.Optimizer,
    *,
    positive_weight: float,
    truncate_after_events: int = 2_048,
    device: torch.device | str = "cpu",
    window_seconds: int = 0,
) -> TrainingEpochResult:
    """Train chronologically and detach memory only at declared truncation boundaries.

    ``window_seconds`` of 0 (the default) preserves exact-timestamp batching
    via ``timestamp_groups``. A positive value switches to coarser
    ``time_window_groups`` batches to cut down the number of tiny sequential
    forward passes on hardware where per-call dispatch overhead dominates.
    """

    if truncate_after_events <= 0:
        raise ValueError("truncate_after_events must be positive")
    if window_seconds < 0:
        raise ValueError("window_seconds must not be negative")
    model.train()
    state = model.initial_state(device=device)
    optimizer.zero_grad(set_to_none=True)
    pending_losses: list[Tensor] = []
    pending_events = 0
    total_loss = 0.0
    total_events = 0
    positives = 0
    optimizer_steps = 0

    def optimize_pending(current_state: TGNState) -> TGNState:
        nonlocal pending_events, optimizer_steps
        if not pending_losses:
            return current_state
        loss = torch.stack(pending_losses).sum() / pending_events
        loss.backward()  # type: ignore[no-untyped-call]
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
        optimizer.step()
        optimizer.zero_grad(set_to_none=True)
        pending_losses.clear()
        pending_events = 0
        optimizer_steps += 1
        return current_state.detach()

    groups = (
        timestamp_groups(events)
        if window_seconds == 0
        else time_window_groups(events, window_seconds=window_seconds)
    )
    for group in groups:
        batch = TemporalBatch.from_events(
            group, device=device, allow_time_window=window_seconds > 0
        )
        logits, state = model.step(batch, state)
        loss = weighted_event_loss(
            logits, batch.labels,
            positive_weight=positive_weight,
            event_weights=batch.loss_weight,
        )
        pending_losses.append(loss * len(group))
        pending_events += len(group)
        total_loss += float(loss.detach()) * len(group)
        total_events += len(group)
        # Count only the positives the model was allowed to learn from.
        if batch.loss_weight is None:
            positives += int(batch.labels.sum().item())
        else:
            positives += int((batch.labels * (batch.loss_weight > 0)).sum().item())
        if pending_events >= truncate_after_events:
            state = optimize_pending(state)
    state = optimize_pending(state)
    if total_events == 0:
        raise ValueError("cannot train on an empty stream")
    return TrainingEpochResult(
        loss=total_loss / total_events,
        events=total_events,
        positives=positives,
        optimizer_steps=optimizer_steps,
        final_state=state,
    )
