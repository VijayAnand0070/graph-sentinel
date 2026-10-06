"""Audit log for state-changing API activity.

A product that can disable accounts and isolate hosts must be able to answer
"who asked for this" afterwards. These tests pin the properties that make the
log usable as evidence: it records mutations, it never records credentials, and
it never takes the service down when it cannot write.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from graphsentinel.api.audit import (MUTATING_METHODS, AuditLog,
                                     actor_fingerprint, is_high_impact)
from graphsentinel.api.main import create_app
from graphsentinel.api.service import DetectionService


class TestActorFingerprint:
    def test_the_key_itself_never_appears(self) -> None:
        """An audit log that leaks credentials turns a read-only compromise
        into a full one."""
        secret = "super-secret-api-key-value"
        fingerprint = actor_fingerprint(secret)
        assert secret not in fingerprint
        assert fingerprint.startswith("key:")
        assert len(fingerprint) == len("key:") + 12

    def test_the_same_key_always_yields_the_same_actor(self) -> None:
        """Correlating a series of actions to one caller depends on this."""
        assert actor_fingerprint("abc") == actor_fingerprint("abc")
        assert actor_fingerprint("abc") != actor_fingerprint("abd")

    def test_absent_key_is_anonymous(self) -> None:
        assert actor_fingerprint(None) == "anonymous"
        assert actor_fingerprint("") == "anonymous"


class TestHighImpact:
    def test_playbook_execution_is_high_impact(self) -> None:
        """Its effects reach outside the product."""
        assert is_high_impact("POST", "/api/v1/playbooks/containment/run")

    def test_reads_are_never_high_impact(self) -> None:
        assert not is_high_impact("GET", "/api/v1/playbooks/containment/run")

    def test_ordinary_mutations_are_not_flagged(self) -> None:
        assert not is_high_impact("POST", "/api/v1/live/events")


class TestAuditLog:
    def test_entries_are_recorded_newest_first(self) -> None:
        log = AuditLog()
        for i in range(3):
            log.record(request_id=f"r{i}", actor="key:abc", method="POST",
                       path=f"/api/v1/thing/{i}", status=200, latency_ms=1.0)
        recent = log.recent()
        assert [e.path for e in recent] == [
            "/api/v1/thing/2", "/api/v1/thing/1", "/api/v1/thing/0"
        ]

    def test_outcome_classifies_denials_separately_from_errors(self) -> None:
        """A reviewer looking for attempted-but-blocked actions needs these
        distinguishable from a server fault."""
        log = AuditLog()
        for status, expected in ((200, "success"), (401, "denied"),
                                 (404, "rejected"), (500, "error")):
            entry = log.record(request_id="r", actor="a", method="POST",
                               path="/p", status=status, latency_ms=1.0)
            assert entry.outcome == expected

    def test_persisted_entries_are_valid_jsonl(self, tmp_path) -> None:
        path = tmp_path / "audit.jsonl"
        log = AuditLog(path=path)
        log.record(request_id="r1", actor="key:abc", method="POST",
                   path="/api/v1/cases", status=201, latency_ms=4.2)
        log.record(request_id="r2", actor="key:abc", method="DELETE",
                   path="/api/v1/cases/1", status=204, latency_ms=1.1)

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["request_id"] == "r1"
        assert first["outcome"] == "success"

    def test_the_log_appends_and_never_rewrites(self, tmp_path) -> None:
        """A log that can be edited in place is not evidence."""
        path = tmp_path / "audit.jsonl"
        AuditLog(path=path).record(request_id="r1", actor="a", method="POST",
                                   path="/p", status=200, latency_ms=1.0)
        first = path.read_text(encoding="utf-8")

        AuditLog(path=path).record(request_id="r2", actor="a", method="POST",
                                   path="/p", status=200, latency_ms=1.0)
        second = path.read_text(encoding="utf-8")
        assert second.startswith(first)
        assert len(second) > len(first)

    def test_an_unwritable_path_does_not_raise(self, tmp_path) -> None:
        """Refusing to serve because the audit file is unwritable turns a disk
        problem into an outage."""
        blocked = tmp_path / "audit.jsonl"
        blocked.mkdir()                       # a directory where a file belongs
        log = AuditLog(path=blocked)
        log.record(request_id="r", actor="a", method="POST", path="/p",
                   status=200, latency_ms=1.0)

        stats = log.stats()
        assert stats["write_failures"] == 1
        # The gap must be visible rather than silent.
        assert stats["degraded"] is True
        # In-memory tail still works, so the trail is not wholly lost.
        assert len(log.recent()) == 1

    def test_secrets_are_redacted_from_detail(self) -> None:
        log = AuditLog()
        entry = log.record(
            request_id="r", actor="a", method="POST", path="/p", status=200,
            latency_ms=1.0,
            detail={"api_key": "leak-me", "x-api-key": "leak-me",
                    "auth_token": "leak-me", "safe": "kept"},
        )
        rendered = json.dumps(entry.to_dict())
        assert "leak-me" not in rendered
        assert entry.detail["safe"] == "kept"

    def test_nested_secrets_are_redacted(self) -> None:
        log = AuditLog()
        entry = log.record(request_id="r", actor="a", method="POST", path="/p",
                           status=200, latency_ms=1.0,
                           detail={"outer": {"session_token": "leak-me"}})
        assert "leak-me" not in json.dumps(entry.to_dict())

    def test_long_values_are_truncated(self) -> None:
        log = AuditLog()
        entry = log.record(request_id="r", actor="a", method="POST", path="/p",
                           status=200, latency_ms=1.0,
                           detail={"body": "x" * 2_000})
        assert len(entry.detail["body"]) < 600

    def test_tail_is_bounded(self) -> None:
        """Unbounded in-memory retention is a slow memory leak in a service
        that runs for months."""
        log = AuditLog(tail_size=10)
        for i in range(50):
            log.record(request_id=str(i), actor="a", method="POST", path="/p",
                       status=200, latency_ms=1.0)
        assert len(log.recent(limit=100)) == 10

    def test_filters_narrow_the_view(self) -> None:
        log = AuditLog()
        log.record(request_id="1", actor="key:aaa", method="POST",
                   path="/api/v1/playbooks/containment/run", status=200, latency_ms=1.0)
        log.record(request_id="2", actor="key:bbb", method="POST",
                   path="/api/v1/live/events", status=200, latency_ms=1.0)

        assert len(log.recent(high_impact_only=True)) == 1
        assert len(log.recent(actor="key:bbb")) == 1

    def test_stats_report_whether_the_log_survives_a_restart(self, tmp_path) -> None:
        assert AuditLog().stats()["persisted"] is False
        assert AuditLog(path=tmp_path / "a.jsonl").stats()["persisted"] is True


class TestMiddlewareIntegration:
    def test_mutations_are_audited_and_reads_are_not(self) -> None:
        """Auditing every GET from a polling console would bury what matters."""
        client = TestClient(create_app(DetectionService(threshold=0.7)))

        client.get("/api/v1/overview")
        client.post("/api/v1/cases", json={"title": "t", "summary": "s"})

        body = client.get("/api/v1/audit").json()
        paths = [e["path"] for e in body["entries"]]
        assert "/api/v1/cases" in paths
        assert "/api/v1/overview" not in paths

    def test_a_failed_request_is_still_audited(self) -> None:
        """Attempted actions matter as much as successful ones."""
        client = TestClient(create_app(DetectionService(threshold=0.7)))
        client.post("/api/v1/alerts/does-not-exist/triage")

        entries = client.get("/api/v1/audit").json()["entries"]
        matching = [e for e in entries if "does-not-exist" in e["path"]]
        assert matching and matching[0]["outcome"] in {"rejected", "error"}

    def test_the_entry_carries_request_id_and_actor(self) -> None:
        client = TestClient(create_app(DetectionService(threshold=0.7)))
        client.post("/api/v1/cases", json={"title": "t", "summary": "s"},
                    headers={"X-Request-ID": "trace-me"})

        entries = client.get("/api/v1/audit").json()["entries"]
        entry = next(e for e in entries if e["path"] == "/api/v1/cases")
        assert entry["request_id"] == "trace-me"
        assert entry["actor"] == "anonymous"        # no key configured here
        assert entry["latency_ms"] >= 0

    def test_supplied_api_key_never_reaches_the_log(self) -> None:
        client = TestClient(create_app(DetectionService(threshold=0.7)))
        client.post("/api/v1/cases", json={"title": "t", "summary": "s"},
                    headers={"X-API-Key": "do-not-log-me"})

        rendered = json.dumps(client.get("/api/v1/audit").json())
        assert "do-not-log-me" not in rendered


def test_mutating_methods_cover_the_write_verbs() -> None:
    assert MUTATING_METHODS == {"POST", "PATCH", "PUT", "DELETE"}
    assert "GET" not in MUTATING_METHODS
