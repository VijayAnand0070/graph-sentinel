"""Cross-process lease for artifact-mutating model pipeline jobs."""

from __future__ import annotations

import json
import os
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4


class PipelineBusyError(RuntimeError):
    """Raised when another live process owns the model pipeline."""


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class LeaseHandle:
    token: str
    owner: str
    job_id: str


class PipelineLease:
    """An exclusive, stale-owner-aware filesystem lease.

    The lease protects the shared feature, report, and checkpoint locations when
    multiple API worker processes are accidentally configured.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def acquire(self, *, owner: str, job_id: str) -> LeaseHandle:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        token = uuid4().hex
        payload = {
            "schema_version": 1,
            "token": token,
            "owner": owner,
            "job_id": job_id,
            "pid": os.getpid(),
            "acquired_at": time.time(),
        }
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode()
        temporary = self.path.with_name(f".{self.path.name}.{token}.tmp")
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            for _attempt in range(3):
                try:
                    os.link(temporary, self.path)
                except FileExistsError:
                    current = self.read()
                    current_pid = current.get("pid") if current else None
                    if isinstance(current_pid, int) and _pid_is_alive(current_pid):
                        assert current is not None
                        current_owner = str(current.get("owner", "another pipeline"))
                        current_job = str(current.get("job_id", "unknown"))
                        raise PipelineBusyError(
                            f"{current_owner} job {current_job} already owns the model pipeline"
                        ) from None
                    if current is None:
                        try:
                            age = time.time() - self.path.stat().st_mtime
                        except FileNotFoundError:
                            continue
                        if age < 30:
                            raise PipelineBusyError(
                                "another process is establishing the model pipeline lease"
                            ) from None
                    with suppress(FileNotFoundError):
                        self.path.unlink()
                    continue
                return LeaseHandle(token=token, owner=owner, job_id=job_id)
            raise PipelineBusyError("could not acquire the model pipeline lease")
        finally:
            temporary.unlink(missing_ok=True)

    def release(self, handle: LeaseHandle) -> None:
        current = self.read()
        if current is not None and current.get("token") == handle.token:
            with suppress(FileNotFoundError):
                self.path.unlink()

    def read(self) -> dict[str, object] | None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        return payload if isinstance(payload, dict) else None

    def has_live_owner(self) -> bool:
        current = self.read()
        pid = current.get("pid") if current else None
        return isinstance(pid, int) and _pid_is_alive(pid)
