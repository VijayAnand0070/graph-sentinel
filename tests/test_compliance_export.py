import pytest

from graphsentinel.api.product import build_compliance_export
from graphsentinel.api.schemas import AlertRecord
from graphsentinel.api.store import AlertStore, CaseStore
from graphsentinel.detection.fusion import RiskComponents, fuse_risk
from graphsentinel.explain.evidence import build_evidence_bundle


def _alert(alert_id: str, event_id: int, *, risk_value: float = 0.9) -> AlertRecord:
    evidence = build_evidence_bundle(
        alert_id=alert_id,
        timestamp=100 + event_id,
        user="U1",
        source_host="C1",
        destination_host="C2",
        risk=fuse_risk(RiskComponents(risk_value, 0.8, 0.7, 0.6, 0.5)),
        is_new_pair=True,
        user_fanout_5m=2,
        recent_failures=1,
    )
    return AlertRecord(
        alert_id=alert_id, event_id=event_id, timestamp=100 + event_id, risk=evidence.scores.fused, evidence=evidence
    )


def test_raises_keyerror_for_unknown_case() -> None:
    with pytest.raises(KeyError):
        build_compliance_export(CaseStore(), AlertStore(), "CASE-99999999")


def test_bundles_case_metadata_and_resolved_alerts() -> None:
    case_store = CaseStore()
    alert_store = AlertStore()
    alert_store.put_alert(_alert("GS-1", 1))
    alert_store.put_alert(_alert("GS-2", 2))
    case = case_store.create_case(title="Lateral movement via C1823", alert_ids=("GS-1", "GS-2"), now=1000)
    case_store.add_note(case.case_id, author="alice", text="confirmed compromise", now=1100)

    record = build_compliance_export(case_store, alert_store, case.case_id)

    assert record.case_id == case.case_id
    assert record.title == "Lateral movement via C1823"
    assert record.status == "open"
    assert len(record.alerts) == 2
    assert {a.alert_id for a in record.alerts} == {"GS-1", "GS-2"}
    assert record.unresolved_alert_ids == ()
    assert len(record.notes) == 1
    assert record.notes[0].author == "alice"
    assert "human review" in record.disclaimer


def test_missing_alert_is_reported_as_unresolved_not_dropped_silently() -> None:
    case_store = CaseStore()
    alert_store = AlertStore()
    alert_store.put_alert(_alert("GS-1", 1))
    # GS-2 was never persisted (e.g. purged) but is still referenced by the case.
    case = case_store.create_case(title="Partial case", alert_ids=("GS-1", "GS-2"), now=1000)

    record = build_compliance_export(case_store, alert_store, case.case_id)

    assert len(record.alerts) == 1
    assert record.alerts[0].alert_id == "GS-1"
    assert record.unresolved_alert_ids == ("GS-2",)


def test_alert_entries_carry_correct_severity_classification() -> None:
    case_store = CaseStore()
    alert_store = AlertStore()
    alert_store.put_alert(_alert("GS-1", 1, risk_value=0.99))
    case = case_store.create_case(title="High risk case", alert_ids=("GS-1",), now=1000)

    record = build_compliance_export(case_store, alert_store, case.case_id)

    assert record.alerts[0].severity in ("high", "critical")


def test_closed_case_preserves_closed_reason() -> None:
    case_store = CaseStore()
    alert_store = AlertStore()
    case = case_store.create_case(title="Resolved", alert_ids=("GS-1",), now=1000)
    case_store.update_status(case.case_id, "closed", closed_reason="false positive", now=2000)

    record = build_compliance_export(case_store, alert_store, case.case_id)

    assert record.status == "closed"
    assert record.closed_reason == "false positive"
