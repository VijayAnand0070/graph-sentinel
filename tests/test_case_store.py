from pathlib import Path

import pytest

from graphsentinel.api.store import CaseStore, SQLiteCaseStore


@pytest.fixture(params=["memory", "sqlite"])
def case_store(request: pytest.FixtureRequest, tmp_path: Path) -> CaseStore | SQLiteCaseStore:
    if request.param == "memory":
        return CaseStore()
    return SQLiteCaseStore(tmp_path / "cases.db")


def test_create_case_assigns_sequential_ids(case_store: CaseStore | SQLiteCaseStore) -> None:
    first = case_store.create_case(title="Case A", alert_ids=("GS-1",), now=100)
    second = case_store.create_case(title="Case B", alert_ids=("GS-2",), now=101)
    assert first.case_id == "CASE-00000001"
    assert second.case_id == "CASE-00000002"
    assert first.status == "open"
    assert first.created_at == 100
    assert first.updated_at == 100
    assert first.notes == ()


def test_get_case_returns_none_for_unknown_id(case_store: CaseStore | SQLiteCaseStore) -> None:
    assert case_store.get_case("CASE-99999999") is None


def test_list_cases_filters_by_status(case_store: CaseStore | SQLiteCaseStore) -> None:
    a = case_store.create_case(title="A", alert_ids=("GS-1",), now=100)
    case_store.create_case(title="B", alert_ids=("GS-2",), now=101)
    case_store.update_status(a.case_id, "closed", closed_reason="resolved", now=200)

    open_cases = case_store.list_cases(status="open")
    closed_cases = case_store.list_cases(status="closed")
    assert len(open_cases) == 1
    assert open_cases[0].title == "B"
    assert len(closed_cases) == 1
    assert closed_cases[0].title == "A"


def test_list_cases_orders_by_most_recently_updated(case_store: CaseStore | SQLiteCaseStore) -> None:
    a = case_store.create_case(title="A", alert_ids=("GS-1",), now=100)
    case_store.create_case(title="B", alert_ids=("GS-2",), now=101)
    case_store.add_note(a.case_id, author="alice", text="bumping this one", now=500)

    cases = case_store.list_cases()
    assert cases[0].title == "A"


def test_update_status_rejects_invalid_status(case_store: CaseStore | SQLiteCaseStore) -> None:
    case = case_store.create_case(title="A", alert_ids=("GS-1",), now=100)
    with pytest.raises(ValueError):
        case_store.update_status(case.case_id, "archived", closed_reason=None, now=200)


def test_update_status_raises_keyerror_for_unknown_case(
    case_store: CaseStore | SQLiteCaseStore,
) -> None:
    with pytest.raises(KeyError):
        case_store.update_status("CASE-99999999", "closed", closed_reason=None, now=200)


def test_closing_records_reason_and_reopening_clears_it(
    case_store: CaseStore | SQLiteCaseStore,
) -> None:
    case = case_store.create_case(title="A", alert_ids=("GS-1",), now=100)
    closed = case_store.update_status(case.case_id, "closed", closed_reason="false positive", now=200)
    assert closed.closed_reason == "false positive"
    reopened = case_store.update_status(closed.case_id, "open", closed_reason=None, now=300)
    assert reopened.closed_reason is None
    assert reopened.status == "open"


def test_add_note_appends_and_updates_timestamp(case_store: CaseStore | SQLiteCaseStore) -> None:
    case = case_store.create_case(title="A", alert_ids=("GS-1",), now=100)
    updated = case_store.add_note(case.case_id, author="alice", text="checked source host", now=150)
    assert len(updated.notes) == 1
    assert updated.notes[0].author == "alice"
    assert updated.notes[0].text == "checked source host"
    assert updated.updated_at == 150

    updated2 = case_store.add_note(updated.case_id, author="bob", text="confirmed lateral move", now=200)
    assert len(updated2.notes) == 2
    assert updated2.notes[0].author == "alice"  # order preserved
    assert updated2.notes[1].author == "bob"


def test_link_alerts_merges_and_deduplicates(case_store: CaseStore | SQLiteCaseStore) -> None:
    case = case_store.create_case(title="A", alert_ids=("GS-1", "GS-2"), now=100)
    updated = case_store.link_alerts(case.case_id, ("GS-2", "GS-3"), now=150)
    assert updated.alert_ids == ("GS-1", "GS-2", "GS-3")


def test_link_alerts_raises_keyerror_for_unknown_case(
    case_store: CaseStore | SQLiteCaseStore,
) -> None:
    with pytest.raises(KeyError):
        case_store.link_alerts("CASE-99999999", ("GS-1",), now=100)


def test_list_cases_rejects_non_positive_limit(case_store: CaseStore | SQLiteCaseStore) -> None:
    with pytest.raises(ValueError):
        case_store.list_cases(limit=0)


def test_sqlite_case_store_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    store = SQLiteCaseStore(path)
    case = store.create_case(title="Persistent case", alert_ids=("GS-1",), now=100)
    store.add_note(case.case_id, author="alice", text="note one", now=150)
    store.close()

    reopened = SQLiteCaseStore(path)
    fetched = reopened.get_case(case.case_id)
    assert fetched is not None
    assert fetched.title == "Persistent case"
    assert len(fetched.notes) == 1
    # The ID counter must also survive reopening, not restart from CASE-00000001.
    next_case = reopened.create_case(title="Second", alert_ids=("GS-2",), now=200)
    assert next_case.case_id == "CASE-00000002"
