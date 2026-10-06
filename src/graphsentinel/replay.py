"""Deterministic chronological replay into the GraphSentinel scoring API."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from dataclasses import asdict, dataclass
from itertools import groupby, pairwise
from pathlib import Path
from typing import Protocol

from graphsentinel.api.schemas import ScoreBatchRequest, ScoreBatchResponse, ScoreEventRequest


@dataclass(frozen=True, slots=True)
class ReplayConfig:
    acceleration: float = 1_000.0
    max_group_events: int = 10_000
    max_sleep_seconds: float = 2.0

    def __post_init__(self) -> None:
        if self.acceleration < 0:
            raise ValueError("acceleration cannot be negative")
        if not 1 <= self.max_group_events <= 10_000:
            raise ValueError("max_group_events must be in [1, 10000]")
        if self.max_sleep_seconds < 0:
            raise ValueError("max_sleep_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class ReplayStats:
    events: int
    timestamp_groups: int
    alerts: int
    paths_created: int
    first_timestamp: int
    last_timestamp: int
    elapsed_wall_seconds: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


class ApiReplayClient:
    def __init__(self, base_url: str, *, timeout_seconds: float = 30) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def score_batch(self, batch: ScoreBatchRequest) -> ScoreBatchResponse:
        request = urllib.request.Request(
            f"{self.base_url}/score-batch",
            data=batch.model_dump_json().encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:2_000]
            raise RuntimeError(f"scoring API returned HTTP {error.code}: {detail}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"cannot reach scoring API: {error.reason}") from error
        return ScoreBatchResponse.model_validate_json(payload)


class ReplayClient(Protocol):
    def score_batch(self, batch: ScoreBatchRequest) -> ScoreBatchResponse: ...


def read_jsonl_events(path: Path) -> Iterator[ScoreEventRequest]:
    """Validate bounded JSONL records without loading the replay into memory."""

    with path.open("rt", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if len(line) > 2_000_000:
                raise ValueError(f"line {line_number} exceeds the 2 MB safety limit")
            if not line.strip():
                continue
            try:
                yield ScoreEventRequest.model_validate_json(line)
            except ValueError as error:
                raise ValueError(f"invalid replay event on line {line_number}: {error}") from error


DEFAULT_REPLAY_CONFIG = ReplayConfig()


def replay(
    events: Sequence[ScoreEventRequest],
    client: ReplayClient,
    *,
    config: ReplayConfig = DEFAULT_REPLAY_CONFIG,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.perf_counter,
) -> ReplayStats:
    """Replay complete timestamp groups so temporal state cannot leak within a second."""

    if not events:
        raise ValueError("replay requires at least one event")
    if any(current.timestamp < previous.timestamp for previous, current in pairwise(events)):
        raise ValueError("replay events must be chronological")
    started = clock()
    alerts = 0
    paths = 0
    groups = 0
    previous_timestamp: int | None = None
    for timestamp, grouped in groupby(events, key=lambda event: event.timestamp):
        group = tuple(grouped)
        if len(group) > config.max_group_events:
            raise ValueError(
                f"timestamp {timestamp} contains {len(group)} events; refusing to split "
                "one causal timestamp group"
            )
        if previous_timestamp is not None and config.acceleration > 0:
            delay = (timestamp - previous_timestamp) / config.acceleration
            sleep(min(delay, config.max_sleep_seconds))
        response = client.score_batch(ScoreBatchRequest(events=group))
        alerts += sum(result.alerted for result in response.results)
        paths += response.paths_created
        groups += 1
        previous_timestamp = timestamp
    return ReplayStats(
        events=len(events),
        timestamp_groups=groups,
        alerts=alerts,
        paths_created=paths,
        first_timestamp=events[0].timestamp,
        last_timestamp=events[-1].timestamp,
        elapsed_wall_seconds=clock() - started,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="graphsentinel-replay")
    parser.add_argument("input", type=Path, help="JSONL file of ScoreEventRequest objects")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--acceleration", type=float, default=1_000)
    parser.add_argument("--max-sleep", type=float, default=2)
    parser.add_argument("--timeout", type=float, default=30)
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    events = list(read_jsonl_events(args.input))
    stats = replay(
        events,
        ApiReplayClient(args.api_url, timeout_seconds=args.timeout),
        config=ReplayConfig(
            acceleration=args.acceleration,
            max_sleep_seconds=args.max_sleep,
        ),
    )
    print(json.dumps(stats.to_dict(), indent=2, sort_keys=True))
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
