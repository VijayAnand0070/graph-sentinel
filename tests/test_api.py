from pathlib import Path

import pytest
import torch
from fastapi.testclient import TestClient

from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.models.serving import load_inference_session
from graphsentinel.models.tgn import TemporalGraphNetwork


def _request(event_id: int, timestamp: int, source: int, destination: int) -> dict[str, object]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "user_id": 10 + event_id,
        "source_host_id": source,
        "destination_host_id": destination,
        "user": f"U{10 + event_id}",
        "source_host": f"C{source}",
        "destination_host": f"C{destination}",
        "is_new_pair": True,
        "user_fanout_5m": 8,
        "recent_failures": 2,
        "evidence_support": 0.8,
        "components": {
            "tgn": 0.95,
            "novelty": 0.9,
            "burst": 0.8,
            "pivot": 0.8,
            "corroboration": 0.8,
        },
    }


def test_batch_alert_path_and_triage_workflow() -> None:
    client = TestClient(create_app(DetectionService(threshold=0.7)))
    response = client.post(
        "/score-batch",
        json={"events": [_request(1, 10, 1, 2), _request(2, 20, 2, 3)]},
    )

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]
    payload = response.json()
    assert payload["paths_created"] == 1
    assert all(result["alerted"] for result in payload["results"])
    alerts = client.get("/alerts").json()
    assert len(alerts) == 2
    assert alerts[0]["evidence"]["path_id"] == "GS-P-1-2"
    path = client.get("/paths/GS-P-1-2")
    assert path.status_code == 200
    assert path.json()["host_ids"] == [1, 2, 3]
    triage = client.post("/triage/GS-00000001")
    assert triage.status_code == 200
    assert triage.json()["triage"]["uncertainty"]
    metrics = client.get("/metrics").json()
    assert metrics["repository"] == {
        "scored_events": 2,
        "alerts": 2,
        "paths": 1,
        "alert_rate": 1.0,
    }
    assert metrics["runtime"]["requests"] == 1
    assert metrics["runtime"]["scored_events"] == 2

    engineering = client.get("/api/v1/detection-engineering")
    assert engineering.status_code == 200
    engineering_payload = engineering.json()
    coverage = {item["technique_id"]: item for item in engineering_payload["techniques"]}
    assert coverage["T1021"]["state"] == "evidence_backed"
    assert coverage["T1021"]["observed_alerts"] == 2
    assert coverage["T1078"]["state"] == "behavioral_signal"
    assert coverage["T1550"]["state"] == "telemetry_gap"
    hunts = {item["hunt_id"]: item for item in engineering_payload["hunts"]}
    assert hunts["new-remote-relationship"]["matched_alerts"] == 2
    assert hunts["time-respecting-pivots"]["matched_alerts"] == 2

    context = client.get("/api/v1/alerts/GS-00000001/context")
    assert context.status_code == 200
    context_payload = context.json()
    assert context_payload["related_alert_ids"] == ["GS-00000002"]
    assert len(context_payload["timeline"]) == 2
    assessments = {item["technique_id"]: item for item in context_payload["techniques"]}
    assert assessments["T1021"]["disposition"] == "evidence_backed"
    assert assessments["T1078"]["disposition"] == "hypothesis"
    assert assessments["T1110"]["disposition"] == "hypothesis"
    assert assessments["T1550"]["disposition"] == "telemetry_gap"
    assert "before any containment" in context_payload["response_guardrail"]
    assert client.get("/api/v1/alerts/missing/context").status_code == 404


def test_api_rejects_invalid_and_duplicate_events() -> None:
    client = TestClient(create_app())
    invalid = _request(1, 10, 1, 1)
    assert client.post("/score-event", json=invalid).status_code == 422
    valid = _request(2, 20, 1, 2)
    assert client.post("/score-event", json=valid).status_code == 200
    assert client.post("/score-event", json=valid).status_code == 409
    metrics = client.get("/metrics").json()
    assert metrics["repository"]["scored_events"] == 1
    assert metrics["runtime"]["failed_requests"] == 1


def test_api_returns_404_for_unknown_entities() -> None:
    client = TestClient(create_app())
    assert client.get("/alerts/GS-MISSING").status_code == 404
    assert client.get("/paths/GS-P-MISSING").status_code == 404
    assert client.post("/triage/GS-MISSING").status_code == 404


def test_paths_are_completed_across_separate_streaming_requests() -> None:
    client = TestClient(create_app(DetectionService(threshold=0.7)))

    first = client.post("/score-event", json=_request(101, 10, 1, 2))
    second = client.post("/score-event", json=_request(102, 20, 2, 3))

    assert first.json()["alerted"] is True
    assert second.status_code == 200
    metrics = client.get("/metrics").json()
    assert metrics["repository"]["paths"] == 1
    assert client.get("/paths/GS-P-101-102").status_code == 200


def test_api_can_compute_tgn_component_from_frozen_checkpoint(tmp_path: Path) -> None:
    checkpoint = tmp_path / "tgn.pt"
    torch.manual_seed(9)
    model = TemporalGraphNetwork(
        num_nodes=40,
        message_dim=3,
        memory_dim=6,
        time_dim=4,
        hidden_dim=8,
        dropout=0,
    )
    model.save_checkpoint(
        checkpoint,
        metadata={
            "feature_version": "auth-causal-v1",
            "model_version": "api-test",
            "user_capacity": 20,
            "host_capacity": 20,
        },
    )
    service = DetectionService(
        threshold=0,
        model_session=load_inference_session(checkpoint),
    )
    client = TestClient(create_app(service))
    request = _request(1, 10, 1, 2)
    components = request["components"]
    assert isinstance(components, dict)
    components.pop("tgn")
    request["message"] = [1.0, 0.5, 0.0]

    response = client.post("/score-event", json=request)

    assert response.status_code == 200
    assert response.json()["alerted"] is True
    assert client.get("/health").json()["model_loaded"] is True
    provenance = client.get("/model")
    assert provenance.status_code == 200
    assert provenance.json()["model_version"] == "api-test"
    assert client.get("/api/v1/live/status").json()["mode"] == "configuration_error"
    assert client.get("/ready").status_code == 503
    live_response = client.post(
        "/api/v1/live/events",
        json={
            "events": [
                {
                    "timestamp": 11,
                    "user": "unknown-live-user",
                    "source_host": "host-a",
                    "destination_host": "host-b",
                    "success": True,
                }
            ]
        },
    )
    assert live_response.status_code == 409
    assert "frozen entity dictionary" in live_response.json()["detail"]


def test_product_console_graph_overview_status_and_metrics() -> None:
    client = TestClient(create_app(DetectionService(threshold=0.7)))
    response = client.post(
        "/score-batch",
        json={"events": [_request(201, 10, 1, 2), _request(202, 20, 2, 3)]},
    )
    assert response.status_code == 200
    scored = response.json()["results"][0]
    assert scored["severity"] in {"high", "critical"}
    assert 0 <= scored["confidence"] <= 1
    assert scored["dominant_signals"]

    overview = client.get("/api/v1/overview").json()
    assert overview["alerts"] == 2
    assert overview["open_alerts"] == 2
    assert overview["paths"] == 1
    assert overview["top_entities"]

    graph = client.get("/api/v1/graph").json()
    assert len(graph["nodes"]) >= 4
    assert len(graph["edges"]) == 4
    assert {edge["relationship"] for edge in graph["edges"]} == {
        "session",
        "authentication",
    }
    assert client.get("/api/v1/paths").json()[0]["path_id"] == "GS-P-201-202"

    updated = client.patch("/api/v1/alerts/GS-00000201/status", json={"status": "reviewed"})
    assert updated.status_code == 200
    assert updated.json()["status"] == "reviewed"
    assert len(client.get("/api/v1/alerts?status=reviewed").json()) == 1
    assert client.get("/metrics/prometheus").text.endswith("\n")
    assert client.get("/ready").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/").headers["x-frame-options"] == "DENY"


def test_product_mutations_can_require_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_API_KEY", "test-secret")
    client = TestClient(create_app())

    unauthorized = client.post("/score-event", json=_request(301, 10, 1, 2))
    unauthorized_read = client.get("/api/v1/overview")
    authorized = client.post(
        "/score-event",
        json=_request(301, 10, 1, 2),
        headers={"X-API-Key": "test-secret"},
    )

    assert unauthorized.status_code == 401
    assert unauthorized.json()["detail"] == "API key required"
    assert unauthorized.headers["x-content-type-options"] == "nosniff"
    assert unauthorized.headers["x-frame-options"] == "DENY"
    assert unauthorized.headers["cache-control"] == "no-store"
    assert unauthorized_read.status_code == 401
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/overview", headers={"X-API-Key": "test-secret"}).status_code == 200
    assert authorized.status_code == 200


def test_live_gateway_builds_causal_features_and_scores_timestamp_groups() -> None:
    client = TestClient(create_app(DetectionService(threshold=0.35)))
    payload = {
        "events": [
            {
                "timestamp": 1_000,
                "user": "alice",
                "source_host": "workstation-1",
                "destination_host": "server-1",
                "auth_type": "Kerberos",
                "logon_type": "Network",
                "orientation": "LogOn",
                "success": True,
                "source": "windows-security",
            },
            {
                "timestamp": 1_000,
                "user": "alice",
                "source_host": "workstation-1",
                "destination_host": "server-2",
                "success": True,
                "corroboration": 0.8,
                "source": "windows-security",
            },
        ]
    }

    response = client.post("/api/v1/live/events", json=payload)

    assert response.status_code == 200
    assert len(response.json()["results"]) == 2
    status = client.get("/api/v1/live/status").json()
    assert status["mode"] == "explainable_fallback"
    assert status["accepted_events"] == 2
    assert status["sources"] == {"windows-security": 2}
    assert client.post("/api/v1/live/events", json=payload).status_code == 409


def test_live_gateway_returns_cached_result_for_idempotent_retry() -> None:
    client = TestClient(create_app(DetectionService(threshold=0.35)))
    payload = {
        "batch_id": "collector-a:partition-2:offset-901",
        "events": [
            {
                "timestamp": 2_000,
                "user": "alice",
                "source_host": "workstation-1",
                "destination_host": "server-1",
                "success": True,
                "source": "siem",
            }
        ],
    }

    first = client.post("/api/v1/live/events", json=payload)
    second = client.post("/api/v1/live/events", json=payload)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert client.get("/metrics").json()["repository"]["scored_events"] == 1
    status = client.get("/api/v1/live/status").json()
    assert status["accepted_events"] == 1
    assert status["duplicate_batches"] == 1

    payload["events"][0]["destination_host"] = "different-server"
    conflict = client.post("/api/v1/live/events", json=payload)
    assert conflict.status_code == 409
    assert "different live events" in conflict.json()["detail"]


def test_training_api_reports_missing_processed_dataset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_FEATURE_DIR", str(tmp_path / "missing"))
    monkeypatch.setenv("GRAPHSENTINEL_FEATURE_REPORT", str(tmp_path / "missing.json"))
    # Isolated so a real, concurrently-running CLI training job (which writes
    # to the real default path) can never leak its "running" status in here.
    monkeypatch.setenv(
        "GRAPHSENTINEL_TRAINING_STATUS_PATH", str(tmp_path / "external-training-status.json")
    )
    client = TestClient(create_app())

    assert client.get("/api/v1/training/status").json()["state"] == "idle"
    response = client.post("/api/v1/training/start", json={"epochs": 1})

    assert response.status_code == 409
    assert "register, ingest, and build features" in response.json()["detail"]


def test_security_posture_reports_write_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_API_KEY", "test-secret")
    monkeypatch.setenv("GRAPHSENTINEL_WORKERS", "1")
    client = TestClient(create_app())

    posture = client.get("/api/v1/security/posture", headers={"X-API-Key": "test-secret"}).json()

    assert posture["write_authentication"] == "api_key"
    assert posture["authentication_scope"] == "all_requests"
    assert posture["api_key_required"] is True
    assert posture["cors_restricted"] is True
    assert posture["allowed_origins"] == ["same-origin"]
    assert posture["ordered_stream_safe"] is True


def test_write_only_authentication_scope_is_explicit_compatibility_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_API_KEY", "test-secret")
    monkeypatch.setenv("GRAPHSENTINEL_AUTH_SCOPE", "write")
    client = TestClient(create_app())

    assert client.get("/api/v1/overview").status_code == 200
    assert client.post("/score-event", json=_request(401, 10, 1, 2)).status_code == 401
    posture = client.get("/api/v1/security/posture").json()
    assert posture["authentication_scope"] == "write_requests"


def test_invalid_authentication_scope_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAPHSENTINEL_AUTH_SCOPE", "sometimes")

    with pytest.raises(ValueError, match="AUTH_SCOPE"):
        create_app()
