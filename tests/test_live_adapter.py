from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from graphsentinel.api.schemas import LiveAuthEvent, ScoreBatchResponse, ScoreEventResponse
from graphsentinel.live_adapter import LiveApiClient, forward_live_events, read_live_jsonl


def _event(timestamp: int, destination: str = "server") -> LiveAuthEvent:
    return LiveAuthEvent(
        timestamp=timestamp,
        user="alice",
        source_host="workstation",
        destination_host=destination,
        success=True,
    )


class _Client:
    def __init__(self) -> None:
        self.groups: list[tuple[int, ...]] = []

    def detect(self, events: tuple[LiveAuthEvent, ...]) -> ScoreBatchResponse:
        self.groups.append(tuple(event.timestamp for event in events))
        return ScoreBatchResponse(
            results=tuple(
                ScoreEventResponse(
                    alert_id=f"GS-{index}",
                    event_id=index,
                    risk=0.8,
                    alerted=True,
                    threshold=0.7,
                )
                for index, _event_value in enumerate(events)
            ),
            paths_created=0,
        )


def test_live_adapter_preserves_timestamp_groups(tmp_path: Path) -> None:
    path = tmp_path / "live.jsonl"
    path.write_text(
        "\n".join(
            (
                _event(1).model_dump_json(),
                _event(1, "server-2").model_dump_json(),
                _event(2).model_dump_json(),
            )
        ),
        encoding="utf-8",
    )
    client = _Client()

    stats = forward_live_events(read_live_jsonl(path), client, max_batch_events=2)

    assert client.groups == [(1, 1), (2,)]
    assert stats == {"events": 3, "alerts": 3, "paths": 0, "batches": 2}


def test_live_adapter_packs_whole_timestamp_groups_into_one_request() -> None:
    """Groups are packed up to the limit and never split at a group boundary."""
    events = (_event(1), _event(1, "server-2"), _event(2), _event(3), _event(3, "server-2"))
    client = _Client()

    stats = forward_live_events(events, client, max_batch_events=4)

    # (1,1,2) fills three of four slots; the (3,3) group does not fit and
    # starts the next request intact.
    assert client.groups == [(1, 1, 2), (3, 3)]
    assert stats == {"events": 5, "alerts": 5, "paths": 0, "batches": 2}


def test_live_adapter_default_packs_everything_that_fits() -> None:
    client = _Client()
    forward_live_events((_event(1), _event(2), _event(3)), client)
    assert client.groups == [(1, 2, 3)]


def test_live_adapter_rejects_oversized_equal_time_group() -> None:
    with pytest.raises(ValueError, match="refusing to split"):
        forward_live_events((_event(1), _event(1, "server-2")), _Client(), max_batch_events=1)


def test_live_api_client_uses_deterministic_retry_batch_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[urllib.request.Request] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        @staticmethod
        def read() -> bytes:
            return b'{"results":[],"paths_created":0}'

    def open_request(request: urllib.request.Request, *, timeout: float) -> Response:
        assert timeout == 7
        requests.append(request)
        return Response()

    monkeypatch.setattr(urllib.request, "urlopen", open_request)
    client = LiveApiClient("http://detector.example/", api_key="secret", timeout=7)

    client.detect((_event(100),))
    client.detect((_event(100),))

    payloads = [json.loads(request.data or b"{}") for request in requests]
    assert payloads[0] == payloads[1]
    assert payloads[0]["batch_id"].startswith("jsonl-")
    assert len(payloads[0]["batch_id"]) == len("jsonl-") + 64
    assert requests[0].get_header("X-api-key") == "secret"
