from pathlib import Path

import pytest

from graphsentinel.api.schemas import (
    ScoreBatchRequest,
    ScoreBatchResponse,
    ScoreEventRequest,
    ScoreEventResponse,
)
from graphsentinel.replay import ReplayConfig, read_jsonl_events, replay


def _event(event_id: int, timestamp: int) -> ScoreEventRequest:
    return ScoreEventRequest.model_validate(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "user_id": 1,
            "source_host_id": 1,
            "destination_host_id": 2,
            "user": "U1",
            "source_host": "C1",
            "destination_host": "C2",
            "is_new_pair": True,
            "user_fanout_5m": 1,
            "recent_failures": 0,
            "components": {
                "tgn": 0.9,
                "novelty": 0.8,
                "burst": 0.7,
                "pivot": 0.6,
                "corroboration": 0.5,
            },
        }
    )


class FakeClient:
    def __init__(self) -> None:
        self.groups: list[tuple[int, ...]] = []

    def score_batch(self, batch: ScoreBatchRequest) -> ScoreBatchResponse:
        self.groups.append(tuple(event.event_id for event in batch.events))
        return ScoreBatchResponse(
            results=tuple(
                ScoreEventResponse(
                    alert_id=f"GS-{event.event_id}",
                    event_id=event.event_id,
                    risk=0.8,
                    alerted=True,
                    threshold=0.7,
                )
                for event in batch.events
            ),
            paths_created=max(0, len(batch.events) - 1),
        )


def test_replay_preserves_timestamp_groups_and_accelerates_time() -> None:
    events = [_event(1, 10), _event(2, 10), _event(3, 20)]
    client = FakeClient()
    delays: list[float] = []
    clock_values = iter((1.0, 2.5))

    stats = replay(
        events,
        client,
        config=ReplayConfig(acceleration=10, max_sleep_seconds=2),
        sleep=delays.append,
        clock=lambda: next(clock_values),
    )

    assert client.groups == [(1, 2), (3,)]
    assert delays == [1.0]
    assert stats.events == 3
    assert stats.timestamp_groups == 2
    assert stats.alerts == 3
    assert stats.elapsed_wall_seconds == 1.5


def test_replay_refuses_to_split_oversized_timestamp_group() -> None:
    events = [_event(1, 10), _event(2, 10)]

    with pytest.raises(ValueError, match="refusing to split"):
        replay(
            events,
            FakeClient(),
            config=ReplayConfig(max_group_events=1, acceleration=0),
        )


def test_jsonl_reader_reports_line_number(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(_event(1, 10).model_dump_json() + "\n{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        list(read_jsonl_events(path))
