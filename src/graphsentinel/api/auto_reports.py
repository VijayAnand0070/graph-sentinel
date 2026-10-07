"""Automatic SOC reports: an incident report written for every account the system locks.

When an alert locks an account (or the account is already locked and moves
again), the analyst who picks up the approval queue needs the story of that
account, not a list of events. This service writes the SOC incident report
for the account in the background -- with the local language model when it is
enabled, otherwise with the deterministic writer -- keeps the latest report per
account, and hands it to a delivery hook (the SOC webhook).

One worker thread, one queue: a local model serves one request at a time, and
an account already waiting is not queued twice. A report written later simply
covers the alerts that arrived in the meantime. Generation failures are
logged and counted; they never touch detection.
"""

from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("graphsentinel.auto_reports")


@dataclass
class AutoReportService:
    #: Writes the report for one account (``DetectionService.soc_report``).
    generate: Callable[[str], Any]
    #: Returns the provenance of the report just written.
    provenance: Callable[[], dict[str, Any]] = lambda: {}
    #: Called with (account, report payload) after each report; e.g. the webhook.
    deliver: Callable[[str, dict[str, Any]], None] | None = None
    clock: Callable[[], float] = time.time
    #: Write synchronously in ``request`` (tests); otherwise on a worker thread.
    inline: bool = False
    #: An account reported this recently is not reported again (seconds).
    min_interval_seconds: float = 120.0
    #: Folder each report is also saved to (Markdown and JSON); None keeps them in memory only.
    report_dir: Path | None = None
    generated: int = 0
    failed: int = 0
    _reports: dict[str, dict[str, Any]] = field(default_factory=dict)
    _queued: set[str] = field(default_factory=set)
    _triggers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self._queue: queue.Queue[str] = queue.Queue()
        self._worker: threading.Thread | None = None

    # ------------------------------------------------------------ requests
    def request(self, account: str, *, alert_id: str = "") -> bool:
        """Ask for a report on ``account``; False if one is already queued."""
        if not account:
            return False
        with self._lock:
            if account in self._queued:
                return False
            last = self._reports.get(account)
            if last is not None and self.clock() - last["generated_at"] < self.min_interval_seconds:
                return False
            self._queued.add(account)
            self._triggers[account] = alert_id
        if self.inline:
            self._write(account)
            return True
        self._queue.put(account)
        self._ensure_worker()
        return True

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                self._worker = threading.Thread(target=self._run, name="soc-auto-report", daemon=True)
                self._worker.start()

    def _run(self) -> None:
        while True:
            account = self._queue.get()
            try:
                self._write(account)
            finally:
                self._queue.task_done()

    def _write(self, account: str) -> None:
        with self._lock:
            self._queued.discard(account)
            trigger = self._triggers.pop(account, "")
        try:
            report = self.generate(account)
        except Exception:  # noqa: BLE001 - a report must never break detection
            self.failed += 1
            logger.exception("automatic SOC report failed for %s", account)
            return
        payload = json.loads(report.model_dump_json())
        payload["markdown"] = report.to_markdown()
        entry = {
            "account": account,
            "generated_at": int(self.clock()),
            "trigger_alert": trigger,
            "provenance": dict(self.provenance() or {}),
            "report": payload,
        }
        with self._lock:
            self._reports[account] = entry
            self.generated += 1
        logger.info("automatic SOC report written for %s (%s)", account, entry["provenance"].get("provider"))
        self._save(entry)
        if self.deliver is not None:
            try:
                self.deliver(account, entry)
            except Exception:  # noqa: BLE001
                logger.exception("automatic SOC report delivery failed for %s", account)

    def _save(self, entry: dict[str, Any]) -> None:
        if self.report_dir is None:
            return
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(entry["generated_at"]))
            stem = f"{stamp}_{re.sub(r'[^A-Za-z0-9._-]+', '_', entry['account'])}"
            (self.report_dir / f"{stem}.md").write_text(entry["report"]["markdown"], encoding="utf-8")
            (self.report_dir / f"{stem}.json").write_text(json.dumps(entry, indent=2), encoding="utf-8")
            entry["saved_to"] = str(self.report_dir / f"{stem}.md")
        except OSError:
            logger.exception("automatic SOC report could not be saved for %s", entry["account"])

    # ------------------------------------------------------------ views
    def wait_idle(self, timeout: float = 30.0) -> None:
        """Block until the queue is empty (tests and shutdown)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if not self._queued:
                    return
            time.sleep(0.05)

    def latest(self, account: str) -> dict[str, Any] | None:
        with self._lock:
            return self._reports.get(account)

    def summary(self) -> dict[str, Any]:
        with self._lock:
            rows = sorted(self._reports.values(), key=lambda e: e["generated_at"], reverse=True)
            return {
                "reports": [
                    {
                        "account": e["account"],
                        "generated_at": e["generated_at"],
                        "trigger_alert": e["trigger_alert"],
                        "headline": e["report"]["headline"],
                        "severity": e["report"]["severity"],
                        "provider": e["provenance"].get("provider"),
                        "fallback": e["provenance"].get("fallback"),
                        "saved_to": e.get("saved_to"),
                    }
                    for e in rows
                ],
                "queued": sorted(self._queued),
                "generated": self.generated,
                "failed": self.failed,
                "report_dir": str(self.report_dir) if self.report_dir is not None else None,
            }


def report_webhook_payload(entry: dict[str, Any], *, format: str) -> dict[str, Any]:
    """The SOC message for an automatic report: Slack text or generic JSON."""
    report = entry["report"]
    if format == "slack":
        summary = " ".join(s["text"] for s in report.get("executive_summary", [])[:2])
        pending = ", ".join(f"`{a['action']}`" for a in report.get("actions_pending", []))
        text = (
            f"*GraphSentinel incident report · {report['severity'].upper()}*\n"
            f"*{report['headline']}*\n{summary}"
            + (f"\nWaiting for your approval: {pending}" if pending else "")
        )
        return {"text": text, "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text[:2900]}}]}
    return {
        "type": "incident_report",
        "source": "graphsentinel",
        "account": entry["account"],
        "generated_at": entry["generated_at"],
        "trigger_alert": entry["trigger_alert"],
        "provider": entry["provenance"].get("provider"),
        "headline": report["headline"],
        "severity": report["severity"],
        "report": report,
    }


__all__ = ["AutoReportService", "report_webhook_payload"]
