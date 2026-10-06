"""Append-only audit log for state-changing API activity.

Why this is not optional
------------------------
The response layer can disable an account, block a network path and isolate a
host. A system able to take those actions must be able to answer, afterwards,
*who asked for this, when, against what, and what happened* -- for incident
review, for the customer's own auditors, and for the case where the product
itself is the thing that caused an outage.

It is also table stakes for SOC 2 CC7.2 and ISO 27001 A.12.4: security-relevant
events recorded, protected from tampering, and reviewable.

Design constraints
------------------
* **Append-only.** Entries are never rewritten in place. A log that can be
  edited is not evidence.
* **No secrets, ever.** The actor is identified by a short fingerprint of the
  presented API key, never the key itself. An audit log that leaks credentials
  converts a read-only compromise into a full one.
* **Never breaks the request.** A failed audit write is logged and swallowed.
  Refusing to serve because the audit file is unwritable turns a disk problem
  into an outage; the alternative -- silently dropping the record -- is worse,
  so the failure is counted and surfaced through :meth:`stats`.
* **Reads are not audited.** Only mutations are, because logging every GET
  from a polling console would bury the entries that matter.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any, Iterable

logger = logging.getLogger(__name__)

#: Requests that change state. Everything else is a read.
MUTATING_METHODS = frozenset({"POST", "PATCH", "PUT", "DELETE"})

#: Paths whose effects reach outside the product. Flagged so a reviewer can
#: filter to "things that touched production" without knowing every route.
HIGH_IMPACT_PREFIXES = (
    "/api/v1/playbooks/",
    "/api/v1/integrations/",
    "/api/v1/alerts/",
    "/api/v1/cases/",
    "/api/v1/feature-state/",
    "/api/v1/training/",
)

#: Header names that must never reach the log, in any form.
SECRET_HEADERS = frozenset({"x-api-key", "authorization", "cookie", "proxy-authorization"})


def actor_fingerprint(api_key: str | None) -> str:
    """Stable, non-reversible identifier for whoever made the request.

    A short SHA-256 prefix: enough to correlate a series of actions to one
    caller and to spot an unexpected key in use, without ever storing material
    that could be replayed.
    """
    if not api_key:
        return "anonymous"
    digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
    return f"key:{digest[:12]}"


@dataclass(frozen=True, slots=True)
class AuditEntry:
    timestamp: int
    request_id: str
    actor: str
    method: str
    path: str
    status: int
    outcome: str
    latency_ms: float
    high_impact: bool
    client: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditLog:
    """Durable append-only log with a bounded in-memory tail for querying."""

    path: Path | None = None
    tail_size: int = 1_000
    _tail: deque[AuditEntry] = field(default_factory=deque)
    _lock: RLock = field(default_factory=RLock)
    _written: int = 0
    _write_failures: int = 0

    def __post_init__(self) -> None:
        if self.tail_size <= 0:
            raise ValueError("tail_size must be positive")
        self._tail = deque(maxlen=self.tail_size)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        request_id: str,
        actor: str,
        method: str,
        path: str,
        status: int,
        latency_ms: float,
        client: str = "",
        detail: dict[str, Any] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=int(time.time()),
            request_id=request_id,
            actor=actor,
            method=method.upper(),
            path=path,
            status=status,
            outcome=_outcome_for(status),
            latency_ms=round(latency_ms, 2),
            high_impact=is_high_impact(method, path),
            client=client,
            detail=_redact(detail or {}),
        )
        with self._lock:
            self._tail.append(entry)
            if self.path is not None:
                try:
                    # Line-buffered append. Opening per write costs a syscall
                    # and keeps the file consistent if the process dies between
                    # requests, which a long-lived handle would not.
                    with self.path.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(entry.to_dict(), sort_keys=True) + "\n")
                    self._written += 1
                except OSError as error:
                    # Never fail the request over an audit write. Count it so
                    # the gap is visible rather than silent.
                    self._write_failures += 1
                    logger.warning("audit write failed for %s %s: %s", method, path, error)
        return entry

    def recent(
        self,
        *,
        limit: int = 100,
        high_impact_only: bool = False,
        actor: str | None = None,
    ) -> tuple[AuditEntry, ...]:
        """Most recent entries first."""
        with self._lock:
            entries: Iterable[AuditEntry] = reversed(self._tail)
            selected = []
            for entry in entries:
                if high_impact_only and not entry.high_impact:
                    continue
                if actor is not None and entry.actor != actor:
                    continue
                selected.append(entry)
                if len(selected) >= limit:
                    break
            return tuple(selected)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "persisted": self.path is not None,
                "path": str(self.path) if self.path else None,
                "entries_written": self._written,
                "write_failures": self._write_failures,
                "tail_held": len(self._tail),
                "tail_capacity": self.tail_size,
                # Surfaced rather than buried: a non-zero failure count means
                # the audit trail has holes, which a reviewer must know.
                "degraded": self._write_failures > 0,
            }


def _outcome_for(status: int) -> str:
    if status == 401 or status == 403:
        return "denied"
    if 200 <= status < 300:
        return "success"
    if 400 <= status < 500:
        return "rejected"
    return "error"


def is_high_impact(method: str, path: str) -> bool:
    """Does this request reach outside the product?"""
    if method.upper() not in MUTATING_METHODS:
        return False
    return any(path.startswith(prefix) for prefix in HIGH_IMPACT_PREFIXES)


def _redact(detail: dict[str, Any]) -> dict[str, Any]:
    """Strip anything that could carry a credential.

    Applied to every detail payload rather than trusting callers to be careful,
    because one careless call site is all it takes to put a key in a file that
    is, by design, kept for years.
    """
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        if key.lower() in SECRET_HEADERS or "key" in key.lower() or "token" in key.lower():
            clean[key] = "[redacted]"
        elif isinstance(value, dict):
            clean[key] = _redact(value)
        elif isinstance(value, str) and len(value) > 512:
            clean[key] = value[:512] + "...[truncated]"
        else:
            clean[key] = value
    return clean


def default_audit_log() -> AuditLog:
    """Build the process-wide log from the environment.

    Without ``GRAPHSENTINEL_AUDIT_LOG`` the log still runs in memory, so the
    recent-activity endpoint works in development; it simply does not survive a
    restart, and ``stats()["persisted"]`` says so.
    """
    configured = os.getenv("GRAPHSENTINEL_AUDIT_LOG", "").strip()
    return AuditLog(path=Path(configured) if configured else None)
