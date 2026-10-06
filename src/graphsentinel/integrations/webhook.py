"""Builds outbound webhook payloads. Pure formatting — no network I/O here.

Two shapes are produced from the same summary: a Slack-compatible payload
(the incoming-webhook ``blocks`` schema, which also happens to render
reasonably in Discord and Mattermost, both Slack-payload-compatible) and a
flat generic JSON payload for anything else. Keeping payload construction
pure and separate from ``api.integrations`` (which does the actual HTTP
POST) means the exact bytes sent can be unit-tested without a network call.
"""

from __future__ import annotations

from typing import Any

from graphsentinel.integrations.alert_summary import WebhookAlertSummary

_SEVERITY_EMOJI = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def build_slack_payload(summary: WebhookAlertSummary) -> dict[str, Any]:
    emoji = _SEVERITY_EMOJI[summary.severity]
    headline = f"{emoji} GraphSentinel · {summary.severity.upper()} risk alert"
    detail = (
        f"*{summary.user}* → *{summary.destination_host}* (via {summary.source_host})\n"
        f"Risk: `{summary.risk:.4f}` · Alert: `{summary.alert_id}`"
    )
    if summary.pending_actions:
        detail += (
            f"\nWaiting for approval: {', '.join(f'`{a}`' for a in summary.pending_actions)}"
            + (f" · decide by <!date^{summary.decision_due}^{{date_short_pretty}} {{time}}|t={summary.decision_due}>"
               if summary.decision_due else "")
        )
    return {
        "text": f"{headline}: {summary.user} -> {summary.destination_host} (risk {summary.risk:.4f})",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{headline}*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": detail}},
        ],
    }


def build_generic_payload(summary: WebhookAlertSummary) -> dict[str, Any]:
    return {
        "alert_id": summary.alert_id,
        "risk": summary.risk,
        "severity": summary.severity,
        "user": summary.user,
        "source_host": summary.source_host,
        "destination_host": summary.destination_host,
        "timestamp": summary.timestamp,
        "pending_actions": list(summary.pending_actions),
        "decision_due": summary.decision_due,
        "source": "graphsentinel",
    }
