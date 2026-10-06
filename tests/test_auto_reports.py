"""Automatic SOC reports: every account the system locks gets an incident report."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from fastapi.testclient import TestClient
from test_response_api import _request

from graphsentinel.api.auto_reports import AutoReportService, report_webhook_payload
from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService
from graphsentinel.detection.fusion import NoisyOrConfig


class _FakeReport:
    def __init__(self, account: str) -> None:
        self.account = account

    def model_dump_json(self) -> str:
        return json.dumps({
            "account": self.account,
            "headline": f"Suspicious movement by {self.account}",
            "severity": "critical",
            "executive_summary": [{"text": "Locked after a confident alert.", "evidence_ids": ["F-001"]}],
            "actions_pending": [{"action": "isolate_host"}],
        })

    def to_markdown(self) -> str:
        return f"# Suspicious movement by {self.account}"


def test_a_report_is_written_kept_and_delivered_once_per_interval() -> None:
    now = [1_000.0]
    delivered: list[str] = []
    written: list[str] = []

    def generate(account: str) -> _FakeReport:
        written.append(account)
        return _FakeReport(account)

    service = AutoReportService(
        generate=generate,
        provenance=lambda: {"provider": "deterministic"},
        deliver=lambda account, entry: delivered.append(account),
        clock=lambda: now[0],
        inline=True,
        min_interval_seconds=120,
    )
    assert service.request("U66@DOM1", alert_id="GS-1")
    latest = service.latest("U66@DOM1")
    assert latest is not None and latest["trigger_alert"] == "GS-1"
    assert latest["report"]["markdown"].startswith("# Suspicious movement")
    assert delivered == ["U66@DOM1"]
    # Not rewritten inside the interval; rewritten after it.
    assert not service.request("U66@DOM1", alert_id="GS-2")
    now[0] += 121
    assert service.request("U66@DOM1", alert_id="GS-3")
    assert written == ["U66@DOM1", "U66@DOM1"]
    summary = service.summary()
    assert summary["generated"] == 2 and summary["reports"][0]["severity"] == "critical"


def test_a_failing_writer_is_counted_and_never_raises() -> None:
    def broken(account: str) -> _FakeReport:
        raise RuntimeError("model unreachable")

    service = AutoReportService(generate=broken, inline=True)
    assert service.request("U1@DOM1")
    assert service.failed == 1 and service.latest("U1@DOM1") is None


def test_the_slack_message_names_what_waits_for_approval() -> None:
    entry = {
        "account": "U66@DOM1",
        "generated_at": 1,
        "trigger_alert": "GS-1",
        "provenance": {"provider": "deterministic"},
        "report": json.loads(_FakeReport("U66@DOM1").model_dump_json()),
    }
    slack = report_webhook_payload(entry, format="slack")
    assert "CRITICAL" in slack["text"] and "`isolate_host`" in slack["text"]
    generic = report_webhook_payload(entry, format="generic")
    assert generic["type"] == "incident_report" and generic["account"] == "U66@DOM1"


def test_a_locked_account_gets_a_report_over_the_api_and_the_soc_receives_it(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    received: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args: object) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_URL", f"http://127.0.0.1:{server.server_port}/hook")
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_FORMAT", "generic")
    monkeypatch.setenv("GRAPHSENTINEL_WEBHOOK_MIN_SEVERITY", "low")
    monkeypatch.delenv("GRAPHSENTINEL_TRIAGE_AGENT", raising=False)
    monkeypatch.setenv("GRAPHSENTINEL_LOCK_PRIOR_ALERTS", "0")
    try:
        app = create_app(DetectionService(threshold=0.5, fusion=NoisyOrConfig()))
        client = TestClient(app)
        event = _request(1)
        scored = client.post("/score-batch", json={"events": [event]}).json()
        assert scored["results"][0]["alerted"]
        app.state.auto_reports.wait_idle(30)
        listing = client.get("/api/v1/soc/reports").json()
        assert listing["enabled"] is True
        assert [r["account"] for r in listing["reports"]] == [event["user"]]
        full = client.get(f"/api/v1/soc/reports/{event['user']}").json()
        assert full["report"]["account"] == event["user"]
        assert full["report"]["markdown"].startswith("#")
        assert any(a["action"] == "lock_account" for a in full["report"]["actions_taken"])
        deadline = time.time() + 5
        while time.time() < deadline and not any(r.get("type") == "incident_report" for r in received):
            time.sleep(0.05)
    finally:
        server.shutdown()
    reports = [r for r in received if r.get("type") == "incident_report"]
    assert reports and reports[0]["account"] == event["user"]
    assert client.get("/api/v1/soc/reports/nobody@DOM1").status_code == 404
