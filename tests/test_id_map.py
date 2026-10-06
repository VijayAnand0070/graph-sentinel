from pathlib import Path

import pytest

from graphsentinel.ingestion.id_map import StableIdMap


def test_stable_id_map_reserves_unknown_and_preserves_order(tmp_path: Path) -> None:
    mapping = StableIdMap("hosts")
    assert mapping.encode("?") == 0
    assert mapping.encode(" C12 ") == 1
    assert mapping.encode("C7") == 2
    assert mapping.encode("C12") == 1

    path = tmp_path / "hosts.json"
    mapping.save(path)
    restored = StableIdMap.load(path, expected_namespace="hosts")

    assert restored.lookup("C12") == 1
    assert restored.encode("C99") == 3


def test_id_map_rejects_namespace_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "hosts.json"
    StableIdMap("hosts").save(path)

    with pytest.raises(ValueError, match="Expected namespace"):
        StableIdMap.load(path, expected_namespace="users")
