import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from graphsentinel.api.integrations import WebhookConfigStore, send_webhook
from graphsentinel.integrations.alert_summary import WebhookAlertSummary


def _summary(**overrides) -> WebhookAlertSummary:
    defaults = dict(
        alert_id="GS-00000001",
        risk=0.9,
        user="U66@DOM1",
        source_host="C1823",
        destination_host="C457",
        timestamp=1_700_000_000,
        severity="critical",
    )
    defaults.update(overrides)
    return WebhookAlertSummary(**defaults)


class _RecordingHandler(BaseHTTPRequestHandler):
    received_bodies: list[bytes] = []

    def do_POST(self) -> None:  # noqa: N802 — stdlib-mandated method name
        length = int(self.headers["Content-Length"])
        self.received_bodies.append(self.rfile.read(length))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: object) -> None:  # silence test noise
        pass


@pytest.fixture
def local_webhook_server():
    _RecordingHandler.received_bodies = []
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", _RecordingHandler
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_send_webhook_delivers_slack_payload(local_webhook_server) -> None:
    url, handler = local_webhook_server
    result = send_webhook(url, _summary(), format="slack")
    assert result.success is True
    assert result.status_code == 200
    body = json.loads(handler.received_bodies[0])
    assert "blocks" in body
    assert "U66@DOM1" in body["text"]


def test_send_webhook_delivers_generic_payload(local_webhook_server) -> None:
    url, handler = local_webhook_server
    result = send_webhook(url, _summary(), format="generic")
    body = json.loads(handler.received_bodies[0])
    assert body["alert_id"] == "GS-00000001"
    assert "blocks" not in body


def test_send_webhook_reports_connection_failure_gracefully() -> None:
    # Port 1 on loopback should reliably refuse the connection.
    result = send_webhook("http://127.0.0.1:1", _summary(), format="slack", timeout=1.0)
    assert result.success is False
    assert result.status_code is None
    assert result.error is not None


def test_config_store_defaults_to_disabled() -> None:
    store = WebhookConfigStore()
    config = store.get()
    assert config.enabled is False
    assert config.url is None


def test_config_store_update_and_get_round_trip() -> None:
    store = WebhookConfigStore()
    updated = store.update(
        url="http://example.invalid/hook", enabled=True, format="generic", minimum_severity="medium"
    )
    assert store.get() == updated
    assert updated.url == "http://example.invalid/hook"


def test_should_dispatch_false_when_disabled() -> None:
    store = WebhookConfigStore()
    store.update(url="http://example.invalid/hook", enabled=False, format="slack", minimum_severity="low")
    assert store.should_dispatch("critical") is False


def test_should_dispatch_false_when_no_url() -> None:
    store = WebhookConfigStore()
    store.update(url=None, enabled=True, format="slack", minimum_severity="low")
    assert store.should_dispatch("critical") is False


def test_should_dispatch_respects_severity_threshold() -> None:
    store = WebhookConfigStore()
    store.update(url="http://example.invalid/hook", enabled=True, format="slack", minimum_severity="high")
    assert store.should_dispatch("medium") is False
    assert store.should_dispatch("high") is True
    assert store.should_dispatch("critical") is True
