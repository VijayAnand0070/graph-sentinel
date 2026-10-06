from pathlib import Path

import pytest

from graphsentinel.api.store import PlaybookExecutionStore, SQLitePlaybookExecutionStore
from graphsentinel.detection.playbooks import CONTAINMENT_PLAYBOOK, execute_playbook


@pytest.fixture(params=["memory", "sqlite"])
def exec_store(
    request: pytest.FixtureRequest, tmp_path: Path
) -> PlaybookExecutionStore | SQLitePlaybookExecutionStore:
    if request.param == "memory":
        return PlaybookExecutionStore()
    return SQLitePlaybookExecutionStore(tmp_path / "playbooks.db")


def _run(risk: float = 0.9, now: int = 100):
    return execute_playbook(CONTAINMENT_PLAYBOOK, entity="C1", entity_kind="host", risk=risk, now=now)


def test_record_assigns_sequential_ids(
    exec_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore,
) -> None:
    first = exec_store.record(_run(now=100))
    second = exec_store.record(_run(now=101))
    assert first.execution_id == "RUN-00000001"
    assert second.execution_id == "RUN-00000002"


def test_record_preserves_execution_fields(
    exec_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore,
) -> None:
    record = exec_store.record(_run(risk=0.95, now=500))
    assert record.playbook_name == "containment"
    assert record.entity == "C1"
    assert record.entity_kind == "host"
    assert record.risk_at_trigger == pytest.approx(0.95)
    assert record.triggered_at == 500
    assert len(record.steps) == len(CONTAINMENT_PLAYBOOK.steps)


def test_list_executions_orders_newest_first(
    exec_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore,
) -> None:
    exec_store.record(_run(now=100))
    exec_store.record(_run(now=300))
    exec_store.record(_run(now=200))
    ordered = exec_store.list_executions()
    assert [r.triggered_at for r in ordered] == [300, 200, 100]


def test_list_executions_rejects_non_positive_limit(
    exec_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore,
) -> None:
    with pytest.raises(ValueError):
        exec_store.list_executions(limit=0)


def test_list_executions_respects_limit(
    exec_store: PlaybookExecutionStore | SQLitePlaybookExecutionStore,
) -> None:
    for i in range(5):
        exec_store.record(_run(now=i))
    assert len(exec_store.list_executions(limit=2)) == 2


def test_sqlite_store_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "playbooks.db"
    store = SQLitePlaybookExecutionStore(path)
    store.record(_run(now=100))
    store.close()

    reopened = SQLitePlaybookExecutionStore(path)
    executions = reopened.list_executions()
    assert len(executions) == 1
    assert executions[0].triggered_at == 100
    # ID counter must also survive reopening.
    next_record = reopened.record(_run(now=200))
    assert next_record.execution_id == "RUN-00000002"
