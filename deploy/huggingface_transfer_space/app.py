"""Private Hugging Face Space worker for official LANL-to-Hub transfer."""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import os
import pathlib
import threading
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from huggingface_hub import HfApi

SOURCE_PAGE = "https://csr.lanl.gov/data/cyber1/"
DOI = "10.17021/1179829"
FILES = {
    "auth.txt.gz": {"columns": 9, "expected_bytes": 7_626_505_158},
    "redteam.txt.gz": {"columns": 4, "expected_bytes": 4_846},
}
WORK = pathlib.Path("/tmp/graphsentinel-lanl")
STATE = WORK / "status.json"
LOCK = threading.Lock()


def write_state(**changes: Any) -> None:
    with LOCK:
        current: dict[str, Any] = {}
        if STATE.is_file():
            try:
                loaded = json.loads(STATE.read_text(encoding="utf-8"))
                current = loaded if isinstance(loaded, dict) else {}
            except (OSError, json.JSONDecodeError):
                current = {}
        current.update(changes)
        current["updated_at"] = datetime.now(UTC).isoformat()
        temporary = STATE.with_suffix(".tmp")
        temporary.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(STATE)


def get_token() -> str:
    query = urllib.parse.urlencode(
        {
            "email": os.environ["LANL_EMAIL"],
            "usage": os.environ["LANL_USAGE"],
        }
    )
    with urllib.request.urlopen(
        f"https://csr.lanl.gov/data-fence/token?{query}", timeout=60
    ) as response:
        token = response.read().decode("utf-8").strip()
    if not token:
        raise RuntimeError("LANL returned an empty access token")
    return token


def download(name: str) -> pathlib.Path:
    destination = WORK / name
    expected = int(FILES[name]["expected_bytes"])
    if destination.is_file() and destination.stat().st_size == expected:
        return destination
    destination.unlink(missing_ok=True)
    token = get_token()
    url = f"https://csr.lanl.gov/data-fence/{token}/cyber1/{name}"
    request = urllib.request.Request(url, headers={"User-Agent": "GraphSentinel/0.9"})
    downloaded = 0
    with urllib.request.urlopen(request, timeout=180) as response, destination.open("wb") as output:
        while chunk := response.read(8 * 1024 * 1024):
            output.write(chunk)
            downloaded += len(chunk)
            write_state(
                stage="download",
                file=name,
                downloaded_bytes=downloaded,
                expected_bytes=expected,
                progress=round(downloaded / expected, 6),
            )
    if destination.stat().st_size != expected:
        raise RuntimeError(
            f"{name} content length mismatch: expected {expected}, got {destination.stat().st_size}"
        )
    return destination


def inspect_archive(path: pathlib.Path, expected_columns: int) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(8 * 1024 * 1024):
            digest.update(chunk)

    rows = 0
    malformed = 0
    previous = -1
    non_decreasing = True
    with gzip.open(path, "rt", encoding="utf-8", newline="") as stream:
        for fields in csv.reader(stream):
            rows += 1
            if len(fields) != expected_columns:
                malformed += 1
                continue
            try:
                timestamp = int(fields[0])
            except ValueError:
                malformed += 1
                continue
            if timestamp < previous:
                non_decreasing = False
            previous = timestamp
            if rows % 5_000_000 == 0:
                write_state(stage="verify", file=path.name, verified_rows=rows)
    if malformed or not non_decreasing:
        raise RuntimeError(
            f"{path.name} failed contract: malformed={malformed}, ordered={non_decreasing}"
        )
    return {
        "file": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
        "validation_level": "full",
        "rows_examined": rows,
        "malformed_rows": malformed,
        "timestamps_non_decreasing": non_decreasing,
    }


def worker() -> None:
    try:
        WORK.mkdir(parents=True, exist_ok=True)
        write_state(state="running", stage="initializing", progress=0.0)
        results: list[dict[str, Any]] = []
        for name, contract in FILES.items():
            path = download(name)
            write_state(stage="verify", file=name, progress=None)
            results.append(inspect_archive(path, int(contract["columns"])))

        hashes = {item["file"]: item["sha256"] for item in results}
        canonical = hashlib.sha256(
            json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        manifest = {
            "schema_version": 1,
            "dataset": "LANL Comprehensive, Multi-Source Cyber-Security Events",
            "dataset_doi": DOI,
            "source_page": SOURCE_PAGE,
            "registered_at_utc": datetime.now(UTC).isoformat(),
            "scope": "core",
            "files": results,
        }
        (WORK / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (WORK / "README.md").write_text(
            "---\nlicense: cc0-1.0\ntags:\n- cybersecurity\n- temporal-graph\n---\n\n"
            "# Private GraphSentinel LANL core mirror\n\n"
            f"Source: {SOURCE_PAGE}\n\nDOI: {DOI}\n\nDataset SHA-256: `{canonical}`\n",
            encoding="utf-8",
        )
        write_state(stage="upload", file=None, progress=None, dataset_sha256=canonical)
        HfApi().upload_folder(
            repo_id=os.environ["TARGET_DATASET_REPO"],
            repo_type="dataset",
            folder_path=WORK,
            allow_patterns=["auth.txt.gz", "redteam.txt.gz", "manifest.json", "README.md"],
            commit_message="Store fully verified GraphSentinel LANL core dataset",
        )
        write_state(state="completed", stage="complete", progress=1.0)
    except Exception as error:
        write_state(state="failed", stage="failed", error=f"{type(error).__name__}: {error}")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        payload = STATE.read_bytes() if STATE.is_file() else b'{"state":"starting"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    threading.Thread(target=worker, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 7860), Handler).serve_forever()
