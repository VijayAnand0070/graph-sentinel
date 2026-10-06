from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from graphsentinel.ingestion.labels import RedTeamIndex


def test_redteam_index_matches_exact_tuple_and_counts_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "redteam.txt.gz"
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write("10,U1@D,C1,C2\n10,U1@D,C1,C2\n")

    index = RedTeamIndex.from_gzip(path)

    assert index.rows_read == 2
    assert len(index.events) == 1
    assert index.duplicate_rows == 1
    assert index.contains(10, "U1@D", "C1", "C2")
    assert not index.contains(10, "U1@D", "C2", "C1")


def test_redteam_index_rejects_wrong_schema(tmp_path: Path) -> None:
    path = tmp_path / "redteam.txt.gz"
    with gzip.open(path, "wt", encoding="utf-8") as stream:
        stream.write("10,U1@D,C1\n")

    with pytest.raises(ValueError, match="expected 4 columns"):
        RedTeamIndex.from_gzip(path)
