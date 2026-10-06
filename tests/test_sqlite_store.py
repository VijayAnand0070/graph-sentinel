from pathlib import Path

import pytest

from graphsentinel.api.schemas import AlertRecord
from graphsentinel.api.store import SQLiteAlertStore
from graphsentinel.detection.fusion import RiskComponents, fuse_risk
from graphsentinel.detection.path_ranker import SuspiciousPath
from graphsentinel.explain.evidence import build_evidence_bundle
from graphsentinel.explain.triage import DeterministicTriageProvider


def _alert() -> AlertRecord:
    evidence = build_evidence_bundle(
        alert_id="GS-0001",
        timestamp=10,
        user="U1",
        source_host="C1",
        destination_host="C2",
        risk=fuse_risk(RiskComponents(0.9, 0.8, 0.7, 0.6, 0.5)),
        is_new_pair=True,
        user_fanout_5m=2,
        recent_failures=1,
    )
    return AlertRecord(alert_id="GS-0001", event_id=1, timestamp=10, risk=0.8, evidence=evidence)


def _path() -> SuspiciousPath:
    return SuspiciousPath(
        path_id="GS-P-1-2",
        event_ids=(1, 2),
        host_ids=(1, 2, 3),
        user_ids=(1, 2),
        timestamps=(10, 20),
        score=0.8,
        mean_edge_risk=0.8,
        new_edge_ratio=1.0,
        pivot_density=0.5,
        evidence_support=0.5,
        redteam_overlap=False,
    )


def test_sqlite_store_persists_alert_path_triage_and_metrics(tmp_path: Path) -> None:
    path = tmp_path / "graphsentinel.db"
    store = SQLiteAlertStore(path)
    alert = _alert()
    store.commit_detection_batch(scored_count=2, alerts=[alert], paths=[_path()])
    report = DeterministicTriageProvider().generate(alert.evidence)
    store.attach_triage(alert.alert_id, report)
    store.close()

    reopened = SQLiteAlertStore(path)
    persisted_alert = reopened.get_alert(alert.alert_id)
    persisted_path = reopened.get_path("GS-P-1-2")
    assert persisted_alert is not None and persisted_alert.triage == report
    assert persisted_path is not None and persisted_path.host_ids == (1, 2, 3)
    assert reopened.metrics() == {
        "scored_events": 2,
        "alerts": 1,
        "paths": 1,
        "alert_rate": 0.5,
    }
    reopened.close()


def test_sqlite_batch_conflict_rolls_back_counter(tmp_path: Path) -> None:
    store = SQLiteAlertStore(tmp_path / "graphsentinel.db")
    alert = _alert()
    store.commit_detection_batch(scored_count=1, alerts=[alert], paths=[])

    with pytest.raises(ValueError, match="already exists"):
        store.commit_detection_batch(scored_count=3, alerts=[alert], paths=[_path()])

    assert store.metrics() == {
        "scored_events": 1,
        "alerts": 1,
        "paths": 0,
        "alert_rate": 1.0,
    }
    store.close()
