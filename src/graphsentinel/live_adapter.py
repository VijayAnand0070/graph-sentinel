"""Forward vendor-normalized JSONL authentication telemetry to the live API."""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator
from itertools import groupby
from pathlib import Path

from pydantic import ValidationError

from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent, ScoreBatchResponse


def read_live_jsonl(path: Path) -> Iterator[LiveAuthEvent]:
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                yield LiveAuthEvent.model_validate_json(line)
            except ValidationError as error:
                raise ValueError(f"invalid live event on line {line_number}: {error}") from error


def read_source_events(
    path: Path,
    format_name: str,
    *,
    column_map: str | None = None,
    assume_year: int | None = None,
) -> Iterator[LiveAuthEvent]:
    """Any supported log format as gateway events, in chronological order.

    Adapters yield in file order; the gateway needs time order and refuses
    local logons, so the file is sorted in memory (file order breaks ties)
    and self-loops are left out. Fine for a log file; a continuous feed
    should be converted upstream into the gateway's JSONL and followed.
    """
    from graphsentinel.sources import ParseStats, adapter_for, read_lines, resolve_format

    format_name, column_map, _detection = resolve_format(
        format_name, [path], column_map=column_map
    )
    adapter = adapter_for(format_name, column_map=column_map, assume_year=assume_year)
    stats = ParseStats()
    events = [e for e in adapter.parse(read_lines([path]), stats) if not e.is_self_loop]
    if not events:
        raise ValueError(
            f"{format_name}: no authentication events in {path} ({dict(stats.skipped)})"
        )
    ordered = sorted(enumerate(events), key=lambda item: (item[1].timestamp, item[0]))
    for _index, event in ordered:
        yield LiveAuthEvent(**event.to_payload())


class LiveApiClient:
    def __init__(self, base_url: str, *, api_key: str | None = None, timeout: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def detect(self, events: tuple[LiveAuthEvent, ...]) -> ScoreBatchResponse:
        event_json = LiveAuthBatch(events=events).model_dump_json()
        batch_id = "jsonl-" + hashlib.sha256(event_json.encode()).hexdigest()
        payload = LiveAuthBatch(batch_id=batch_id, events=events).model_dump_json().encode()
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        request = urllib.request.Request(
            f"{self.base_url}/api/v1/live/events",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return ScoreBatchResponse.model_validate_json(response.read())
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:1_000]
            raise RuntimeError(f"live API rejected batch ({error.code}): {detail}") from error


def forward_live_events(
    events: Iterable[LiveAuthEvent],
    client: LiveApiClient,
    *,
    max_batch_events: int = 1_000,
) -> dict[str, int]:
    """Forward chronological batches without ever splitting equal-time events.

    Consecutive timestamp groups are packed into one request while the batch
    stays within ``max_batch_events``; a group is never split across two
    requests, because the gateway treats the events of one timestamp as
    simultaneous and a split would let the second half see state the first
    half had already changed. One request per timestamp, the previous
    behaviour, is ``max_batch_events`` equal to the largest group.
    """

    if max_batch_events <= 0:
        raise ValueError("max_batch_events must be positive")
    event_count = 0
    alert_count = 0
    path_count = 0
    batches = 0
    previous_timestamp: int | None = None
    pending: list[LiveAuthEvent] = []

    def flush() -> None:
        nonlocal event_count, alert_count, path_count, batches
        if not pending:
            return
        response = client.detect(tuple(pending))
        event_count += len(pending)
        alert_count += sum(result.alerted for result in response.results)
        path_count += response.paths_created
        batches += 1
        pending.clear()

    for timestamp, grouped in groupby(events, key=lambda event: event.timestamp):
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise ValueError("live JSONL events must be chronological")
        group = tuple(grouped)
        if len(group) > max_batch_events:
            raise ValueError("one timestamp group exceeds max_batch_events; refusing to split it")
        if len(pending) + len(group) > max_batch_events:
            flush()
        pending.extend(group)
        previous_timestamp = timestamp
    flush()
    return {"events": event_count, "alerts": alert_count, "paths": path_count, "batches": batches}


def follow_live_jsonl(
    path: Path,
    client: LiveApiClient,
    *,
    poll_seconds: float = 0.5,
) -> None:
    """Follow JSONL and publish a timestamp only after a later timestamp is the watermark."""

    if poll_seconds <= 0:
        raise ValueError("poll_seconds must be positive")
    with path.open("r", encoding="utf-8") as stream:
        pending: list[LiveAuthEvent] = []
        while True:
            line = stream.readline()
            if not line:
                time.sleep(poll_seconds)
                continue
            if line.strip():
                event = LiveAuthEvent.model_validate_json(line)
                if pending and event.timestamp < pending[-1].timestamp:
                    raise ValueError("followed live events must be chronological")
                if pending and event.timestamp > pending[-1].timestamp:
                    client.detect(tuple(pending))
                    pending.clear()
                pending.append(event)
