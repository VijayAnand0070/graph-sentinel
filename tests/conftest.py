"""Shared test setup."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _soc_reports_in_tmp(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    """Automatic SOC reports written by an API under test go to a temporary folder."""
    monkeypatch.setenv("GRAPHSENTINEL_SOC_REPORT_DIR", str(tmp_path / "soc_reports"))
