import json

import pytest

from graphsentinel.integrations.alert_summary import WebhookAlertSummary, severity_from_risk
from graphsentinel.integrations.siem_export import to_cef, to_ndjson_line
from graphsentinel.integrations.webhook import build_generic_payload, build_slack_payload


def _summary(**overrides) -> WebhookAlertSummary:
    defaults = dict(
        alert_id="GS-00000001",
        risk=0.912,
        user="U66@DOM1",
        source_host="C1823",
        destination_host="C457",
        timestamp=1_700_000_000,
        severity="critical",
    )
    defaults.update(overrides)
    return WebhookAlertSummary(**defaults)


def test_summary_rejects_out_of_range_risk() -> None:
    with pytest.raises(ValueError):
        _summary(risk=1.5)


def test_summary_rejects_empty_entities() -> None:
    with pytest.raises(ValueError):
        _summary(user="")


def test_severity_from_risk_matches_dashboard_bands() -> None:
    assert severity_from_risk(0.0) == "low"
    assert severity_from_risk(0.49) == "low"
    assert severity_from_risk(0.5) == "medium"
    assert severity_from_risk(0.69) == "medium"
    assert severity_from_risk(0.7) == "high"
    assert severity_from_risk(0.849) == "high"
    assert severity_from_risk(0.85) == "critical"
    assert severity_from_risk(1.0) == "critical"


def test_severity_from_risk_rejects_out_of_range() -> None:
    with pytest.raises(ValueError):
        severity_from_risk(-0.1)


def test_slack_payload_contains_entities_and_risk() -> None:
    payload = build_slack_payload(_summary())
    assert "U66@DOM1" in payload["text"]
    assert "C457" in payload["text"]
    assert "0.9120" in payload["text"]
    assert payload["blocks"][0]["type"] == "section"


def test_generic_payload_round_trips_all_fields() -> None:
    summary = _summary()
    payload = build_generic_payload(summary)
    assert payload["alert_id"] == summary.alert_id
    assert payload["risk"] == summary.risk
    assert payload["severity"] == summary.severity
    assert payload["user"] == summary.user
    assert payload["source_host"] == summary.source_host
    assert payload["destination_host"] == summary.destination_host
    assert payload["timestamp"] == summary.timestamp


def test_cef_has_correct_pipe_delimited_header() -> None:
    line = to_cef(_summary())
    header, extension = line.split("|", 6)[0], line.split("|", 6)[6]
    assert line.startswith("CEF:0|GraphSentinel|TGN-LateralMovement|1.0|GS-LATMOVE-001|Lateral movement detected|10|")


def test_cef_severity_mapping() -> None:
    assert to_cef(_summary(severity="low")).split("|")[6] == "3"
    assert to_cef(_summary(severity="medium")).split("|")[6] == "6"
    assert to_cef(_summary(severity="high")).split("|")[6] == "8"
    assert to_cef(_summary(severity="critical")).split("|")[6] == "10"


def test_cef_extension_contains_expected_fields() -> None:
    line = to_cef(_summary())
    assert "src=C1823" in line
    assert "dst=C457" in line
    assert "suser=U66@DOM1" in line
    assert "cs1=0.9120" in line
    assert "externalId=GS-00000001" in line
    assert "rt=1700000000000" in line  # milliseconds


def test_cef_escapes_pipe_in_header_fields() -> None:
    line = to_cef(_summary(), device_vendor="Vendor|WithPipe")
    assert "Vendor\\|WithPipe" in line
    # The escaped pipe must not be mistaken for a field separator.
    assert line.split("|")[1] == "Vendor\\"


def test_cef_escapes_equals_in_extension_values() -> None:
    line = to_cef(_summary(user="weird=user"))
    assert "suser=weird\\=user" in line


def test_ndjson_line_is_valid_json_with_expected_fields() -> None:
    line = to_ndjson_line(_summary())
    parsed = json.loads(line)
    assert parsed["alert_id"] == "GS-00000001"
    assert parsed["severity"] == "critical"
    assert parsed["event.kind"] == "alert"
    assert parsed["observer.vendor"] == "graphsentinel"


def test_ndjson_line_has_no_embedded_newlines() -> None:
    line = to_ndjson_line(_summary())
    assert "\n" not in line
