from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from graphsentinel.datasets.catalog import LANL_FILE_SPECS
from graphsentinel.datasets.integrity import IntegrityError, inspect_gzip


def _write_gzip(path: Path, lines: list[str]) -> None:
    with gzip.open(path, "wt", encoding="utf-8", newline="") as stream:
        stream.write("".join(lines))


def test_full_auth_scan_reports_contract_statistics(tmp_path: Path) -> None:
    path = tmp_path / "auth.txt.gz"
    _write_gzip(
        path,
        [
            "1,U1@D,U1@D,C1,C2,Kerberos,Network,LogOn,Success\n",
            "2,U1@D,?,C1,C3,NTLM,Network,LogOn,Fail\n",
            "4,U2@D,U2@D,C2,C4,Negotiate,Service,LogOn,Success\n",
        ],
    )

    result = inspect_gzip(path, LANL_FILE_SPECS[path.name], full_scan=True)

    assert result.validation_level == "full"
    assert result.total_rows == 3
    assert result.malformed_rows == 0
    assert result.missing_values["dst_user"] == 1
    assert result.timestamp_min == 1
    assert result.timestamp_max == 4
    assert result.timestamps_non_decreasing
    assert result.first_valid_row is not None
    assert result.last_valid_row is not None
    assert len(result.sha256) == 64


def test_quick_scan_is_explicitly_partial(tmp_path: Path) -> None:
    path = tmp_path / "redteam.txt.gz"
    _write_gzip(path, ["1,U1@D,C1,C2\n", "2,U2@D,C2,C3\n"])

    result = inspect_gzip(
        path,
        LANL_FILE_SPECS[path.name],
        full_scan=False,
        quick_scan_rows=1,
    )

    assert result.validation_level == "quick"
    assert result.rows_examined == 1
    assert result.total_rows is None
    assert result.last_valid_row is None


def test_scan_flags_malformed_and_out_of_order_rows(tmp_path: Path) -> None:
    path = tmp_path / "redteam.txt.gz"
    _write_gzip(path, ["3,U1@D,C1,C2\n", "not-a-time,U2@D,C2,C3\n", "2,U3@D,C3,C4\n"])

    result = inspect_gzip(path, LANL_FILE_SPECS[path.name], full_scan=True)

    assert result.malformed_rows == 1
    assert not result.timestamps_non_decreasing


def test_non_gzip_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "auth.txt.gz"
    path.write_text("not gzip", encoding="utf-8")

    with pytest.raises(IntegrityError, match="not a gzip"):
        inspect_gzip(path, LANL_FILE_SPECS[path.name], full_scan=True)
