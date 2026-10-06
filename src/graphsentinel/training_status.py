"""Shared, dependency-free bridge so a CLI-driven training run's progress is
visible to the API's Training Monitor even though the two run as separate
processes with no shared memory.

The CLI's ``graphsentinel train tgn`` writes a small status file on every
epoch; the API's ``TrainingManager.status()`` reads it back and reports it
whenever it doesn't have an in-process job of its own running. This module
has no heavy dependencies (no torch, no FastAPI) so importing it from the CLI
stays cheap.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

DEFAULT_EXTERNAL_STATUS_PATH = Path("artifacts/runtime/cli-training-status.json")

# A file older than this is treated as a stale leftover from a run that never
# reached a terminal state (crashed process, killed job) rather than a live one.
#
# This is generous on purpose: the CLI only writes on epoch boundaries (no
# background heartbeat thread), and on this project's actual hardware a
# single epoch over the full bounded dataset has been observed to take well
# over an hour under system contention. A short window would misreport a
# slow-but-alive epoch as dead. The trade-off is slower crash detection for a
# single-operator dev/demo setup, which is the honest choice here — a real
# heartbeat would need a background thread inside the training loop itself.
STALE_AFTER_SECONDS = 3 * 3600


def write_external_training_status(
    *,
    state: str,
    epoch: int,
    total_epochs: int,
    train_loss: float | None = None,
    validation_pr_auc: float | None = None,
    message: str = "",
    started_at: int | None = None,
    completed_at: int | None = None,
    checkpoint_path: str | None = None,
    report_path: str | None = None,
    path: Path | None = None,
) -> None:
    """Atomically persist CLI training progress for the API to pick up.

    The file lives where the API looks for it: ``GRAPHSENTINEL_TRAINING_STATUS_PATH``
    when set (the variable the API reads), else the default. A training run in
    an isolated directory therefore never overwrites the status of the
    deployment an operator is watching.
    """

    if path is None:
        configured = os.getenv("GRAPHSENTINEL_TRAINING_STATUS_PATH", "").strip()
        path = Path(configured) if configured else DEFAULT_EXTERNAL_STATUS_PATH
    payload: dict[str, Any] = {
        "source": "cli",
        "state": state,
        "epoch": epoch,
        "total_epochs": total_epochs,
        "progress": (epoch / total_epochs) if total_epochs > 0 else 0.0,
        "train_loss": train_loss,
        "validation_pr_auc": validation_pr_auc,
        "message": message,
        "started_at": started_at,
        "completed_at": completed_at,
        "checkpoint_path": checkpoint_path,
        "report_path": report_path,
        "written_at": int(time.time()),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(temporary, path)


def read_external_training_status(
    *, path: Path = DEFAULT_EXTERNAL_STATUS_PATH
) -> dict[str, Any] | None:
    """Return the CLI's last-written status if the file exists, parses, and isn't stale."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    written_at = payload.get("written_at")
    if not isinstance(written_at, int) or time.time() - written_at > STALE_AFTER_SECONDS:
        return None
    return payload
