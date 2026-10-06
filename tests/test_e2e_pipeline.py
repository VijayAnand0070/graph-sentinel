"""The end-to-end pipeline check and the synthetic raw corpus it runs on.

The full run (raw text -> served, responding API) takes about seven minutes on
CPU and is opt-in: ``GRAPHSENTINEL_E2E=1 pytest tests/test_e2e_pipeline.py``.
The corpus writer and the report renderer are tested unconditionally.
"""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from graphsentinel.simulation.rawcorpus import (
    PARTITION_WINDOWS,
    RawCorpusSpec,
    write_synthetic_lanl_corpus,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "e2e_pipeline.py"


def _rows(path: Path) -> list[list[str]]:
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return [line.rstrip("\n").split(",") for line in stream if line.strip()]


class TestSyntheticRawCorpus:
    def test_it_is_lanl_shaped_and_chronological(self, tmp_path: Path) -> None:
        summary = write_synthetic_lanl_corpus(tmp_path, RawCorpusSpec(days=1, events_per_day=2_000))
        auth = _rows(summary.auth_path)
        assert summary.rows == len(auth)
        assert all(len(row) == 9 for row in auth)
        stamps = [int(row[0]) for row in auth]
        assert stamps == sorted(stamps) and stamps[0] >= 1
        assert all(row[8] in {"Success", "Fail"} for row in auth)
        assert any(row[5] == "?" for row in auth), "missing values are part of the shape"
        assert (
            summary.self_loops > 0 and sum(row[3] == row[4] for row in auth) == summary.self_loops
        )

    def test_red_team_rows_match_auth_rows_and_are_never_local_logons(self, tmp_path: Path) -> None:
        summary = write_synthetic_lanl_corpus(tmp_path, RawCorpusSpec(days=1, events_per_day=2_000))
        auth = {(row[0], row[1], row[3], row[4]) for row in _rows(summary.auth_path)}
        redteam = _rows(summary.redteam_path)
        assert len(redteam) == summary.redteam_rows == 3 * 2 * 6
        for row in redteam:
            assert tuple(row) in auth
            assert row[2] != row[3]
        stamps = [int(row[0]) for row in redteam]
        assert stamps == sorted(stamps)

    def test_every_partition_gets_campaigns_after_local_logons_are_dropped(
        self, tmp_path: Path
    ) -> None:
        """The split is 70/15/15 by index over what the ingest keeps."""
        summary = write_synthetic_lanl_corpus(tmp_path, RawCorpusSpec(days=2, events_per_day=3_000))
        kept = [row for row in _rows(summary.auth_path) if row[3] != row[4]]
        labelled = {tuple(row) for row in _rows(summary.redteam_path)}
        positions = [
            index / len(kept)
            for index, row in enumerate(kept)
            if (row[0], row[1], row[3], row[4]) in labelled
        ]
        assert positions
        assert any(p < 0.70 for p in positions)
        assert any(0.70 <= p < 0.85 for p in positions)
        assert any(p >= 0.85 for p in positions)
        for low, high in PARTITION_WINDOWS:
            assert any(low - 0.03 <= p <= high + 0.03 for p in positions)

    def test_the_same_seed_writes_the_same_bytes(self, tmp_path: Path) -> None:
        a = write_synthetic_lanl_corpus(tmp_path / "a", RawCorpusSpec(days=1, events_per_day=500))
        b = write_synthetic_lanl_corpus(tmp_path / "b", RawCorpusSpec(days=1, events_per_day=500))
        assert _rows(a.auth_path) == _rows(b.auth_path)
        assert _rows(a.redteam_path) == _rows(b.redteam_path)


class TestReport:
    def test_a_failed_run_renders_its_failure(self) -> None:
        import importlib.util

        spec = importlib.util.spec_from_file_location("e2e_pipeline", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules["e2e_pipeline"] = module  # dataclasses resolve the module by name
        spec.loader.exec_module(module)
        summary = {
            "outcome": "failed",
            "seconds": 61.0,
            "run_dir": "r",
            "raw_dir": "d",
            "parameters": {"epochs": 1},
            "environment": {"python": "3.13", "torch": None, "platform": "x"},
            "stages": [
                {
                    "name": "verify",
                    "status": "passed",
                    "seconds": 1.0,
                    "details": {"files": ["auth.txt.gz"]},
                    "error": None,
                },
                {
                    "name": "ingest",
                    "status": "failed",
                    "seconds": 2.0,
                    "details": {},
                    "error": "ingest matched no red-team events",
                },
            ],
        }
        text = module.render_summary(summary)
        assert "**Outcome: failed**" in text
        assert "| ingest | failed |" in text
        assert "ingest matched no red-team events" in text


@pytest.mark.skipif(
    os.getenv("GRAPHSENTINEL_E2E") != "1", reason="set GRAPHSENTINEL_E2E=1 to run the full pipeline"
)
def test_the_whole_pipeline_runs_on_the_synthetic_corpus(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--synthetic",
            "--run-dir",
            str(run_dir),
            "--epochs",
            "2",
            "--resamples",
            "50",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=1_800,
        check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert completed.returncode == 0, completed.stdout[-3000:] + completed.stderr[-3000:]
    summary = json.loads((run_dir / "e2e_summary.json").read_text(encoding="utf-8"))
    assert summary["outcome"] == "passed"
    assert [s["name"] for s in summary["stages"]] == [
        "verify",
        "ingest",
        "features",
        "baselines",
        "train",
        "score",
        "report",
        "backfill",
        "serve",
    ]
    assert all(s["status"] in {"passed", "reused"} for s in summary["stages"])
    serve = summary["stages"][-1]["details"]
    assert serve["agreement"]["fused_risk"]["max_abs_delta"] <= 1e-5
    assert serve["response"]["status"]["counts"]["dispatched"] > 0
    assert serve["restart"]["features_restored"] is True
    assert (run_dir / "E2E_REPORT.md").is_file()
