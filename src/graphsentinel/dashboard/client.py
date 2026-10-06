"""Small HTTP client used by the dashboard; no direct database coupling."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class DashboardApiClient:
    def __init__(self, base_url: str, *, timeout_seconds: float = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def _request(self, path: str, *, method: str = "GET") -> Any:
        request = urllib.request.Request(f"{self.base_url}{path}", method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
            raise RuntimeError(f"GraphSentinel API request failed: {error}") from error

    def health(self) -> dict[str, Any]:
        return dict(self._request("/health"))

    def metrics(self) -> dict[str, Any]:
        return dict(self._request("/metrics"))

    def alerts(self, *, minimum_risk: float = 0, limit: int = 100) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"minimum_risk": minimum_risk, "limit": limit})
        return list(self._request(f"/alerts?{query}"))

    def path(self, path_id: str) -> dict[str, Any]:
        return dict(self._request(f"/paths/{urllib.parse.quote(path_id, safe='')}"))

    def triage(self, alert_id: str) -> dict[str, Any]:
        return dict(
            self._request(f"/triage/{urllib.parse.quote(alert_id, safe='')}", method="POST")
        )

    def model(self) -> dict[str, Any]:
        return dict(self._request("/model"))
