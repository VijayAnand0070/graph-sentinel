"""Outbound webhook configuration and dispatch — the I/O boundary around the
pure payload builders in ``graphsentinel.integrations``.

Uses the standard library's ``urllib`` rather than adding an HTTP client
dependency; the request volume here (analyst-triggered test sends, or one
POST per newly alerted event) never justifies a connection-pooling client.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from threading import RLock
from typing import Literal

from graphsentinel.integrations.alert_summary import Severity, WebhookAlertSummary
from graphsentinel.integrations.webhook import build_generic_payload, build_slack_payload

WebhookFormat = Literal["slack", "generic"]

_SEVERITY_RANK: dict[Severity, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True, slots=True)
class WebhookConfig:
    url: str | None = None
    enabled: bool = False
    format: WebhookFormat = "slack"
    minimum_severity: Severity = "high"


@dataclass(frozen=True, slots=True)
class WebhookDeliveryResult:
    success: bool
    status_code: int | None
    error: str | None


class WebhookConfigStore:
    """Thread-safe holder for the single configured webhook (in-memory by design —
    a URL is operational configuration, not an audit record, so it doesn't need
    the durability the alert/case/playbook stores provide)."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._config = WebhookConfig()

    def get(self) -> WebhookConfig:
        with self._lock:
            return self._config

    def update(
        self,
        *,
        url: str | None,
        enabled: bool,
        format: WebhookFormat,
        minimum_severity: Severity,
    ) -> WebhookConfig:
        with self._lock:
            self._config = WebhookConfig(
                url=url, enabled=enabled, format=format, minimum_severity=minimum_severity
            )
            return self._config

    def should_dispatch(self, severity: Severity) -> bool:
        with self._lock:
            config = self._config
        if not config.enabled or not config.url:
            return False
        return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[config.minimum_severity]


def send_json(url: str, payload: dict[str, object], *, timeout: float = 5.0) -> WebhookDeliveryResult:
    """POST one JSON document (an automatic incident report) to the SOC endpoint."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return WebhookDeliveryResult(success=True, status_code=response.status, error=None)
    except urllib.error.HTTPError as error:
        return WebhookDeliveryResult(success=False, status_code=error.code, error=str(error))
    except urllib.error.URLError as error:
        return WebhookDeliveryResult(success=False, status_code=None, error=str(error.reason))
    except Exception as error:  # noqa: BLE001 - this boundary must never raise
        return WebhookDeliveryResult(success=False, status_code=None, error=str(error))


def send_webhook(
    url: str, summary: WebhookAlertSummary, *, format: WebhookFormat, timeout: float = 5.0
) -> WebhookDeliveryResult:
    payload = build_slack_payload(summary) if format == "slack" else build_generic_payload(summary)
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return WebhookDeliveryResult(success=True, status_code=response.status, error=None)
    except urllib.error.HTTPError as error:
        return WebhookDeliveryResult(success=False, status_code=error.code, error=str(error))
    except urllib.error.URLError as error:
        return WebhookDeliveryResult(success=False, status_code=None, error=str(error.reason))
    except Exception as error:  # noqa: BLE001 — this boundary must never raise into the route
        return WebhookDeliveryResult(success=False, status_code=None, error=str(error))
