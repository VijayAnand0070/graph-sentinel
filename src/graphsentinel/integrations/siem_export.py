"""SIEM-compatible export formats: CEF (ArcSight/Splunk/QRadar) and NDJSON (Elastic/Splunk HEC).

Common Event Format is a de facto standard (originally ArcSight, now widely
accepted by Splunk, QRadar, and Microsoft Sentinel) with a fixed pipe-
delimited header and a key=value extension section. Building it correctly
matters for real ingestion — a misplaced pipe or an unescaped value in the
extension silently corrupts every field after it, so escaping is handled
explicitly here rather than left to strings joined by luck.
"""

from __future__ import annotations

import json

from graphsentinel.integrations.alert_summary import Severity, WebhookAlertSummary

_CEF_SEVERITY: dict[Severity, int] = {"low": 3, "medium": 6, "high": 8, "critical": 10}
CEF_SIGNATURE_ID = "GS-LATMOVE-001"
CEF_NAME = "Lateral movement detected"


def _escape_cef_header_field(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _escape_cef_extension_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n")


def to_cef(
    summary: WebhookAlertSummary,
    *,
    device_vendor: str = "GraphSentinel",
    device_product: str = "TGN-LateralMovement",
    device_version: str = "1.0",
) -> str:
    header = "|".join(
        _escape_cef_header_field(field)
        for field in (
            device_vendor,
            device_product,
            device_version,
            CEF_SIGNATURE_ID,
            CEF_NAME,
            str(_CEF_SEVERITY[summary.severity]),
        )
    )
    extension = " ".join(
        f"{key}={_escape_cef_extension_value(str(value))}"
        for key, value in (
            ("src", summary.source_host),
            ("dst", summary.destination_host),
            ("suser", summary.user),
            ("cs1Label", "risk"),
            ("cs1", f"{summary.risk:.4f}"),
            ("externalId", summary.alert_id),
            ("rt", summary.timestamp * 1000),  # CEF rt is epoch milliseconds
        )
    )
    return f"CEF:0|{header}|{extension}"


def to_ndjson_line(summary: WebhookAlertSummary) -> str:
    return json.dumps(
        {
            "alert_id": summary.alert_id,
            "risk": summary.risk,
            "severity": summary.severity,
            "user": summary.user,
            "source_host": summary.source_host,
            "destination_host": summary.destination_host,
            "@timestamp": summary.timestamp,
            "event.kind": "alert",
            "event.category": "intrusion_detection",
            "observer.vendor": "graphsentinel",
        },
        sort_keys=True,
    )
