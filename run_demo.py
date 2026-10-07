"""Start the GraphSentinel console with the bundled demo model (no LANL download needed).

    python run_demo.py            then open http://127.0.0.1:8010

Response actions run in dry-run mode: every lock is planned and audited, nothing is executed.
Incident reports are written by the local language model when Ollama is running with the model
(qwen3.5:4b by default) and langgraph is installed; otherwise by the deterministic writer.
Set GRAPHSENTINEL_TRIAGE_AGENT=0 to force the deterministic writer.
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

DEMO_ENV = {
    "GRAPHSENTINEL_CHECKPOINT": "artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt",
    "GRAPHSENTINEL_ID_MAP_DIR": "artifacts/id_maps_lanl_1m_cuda",
    "GRAPHSENTINEL_TGN_MEMORY": "artifacts/state/tgn_memory.npz",
    "GRAPHSENTINEL_FEATURE_STATE": "artifacts/state/feature_state.json.gz",
    "GRAPHSENTINEL_DATABASE": "artifacts/runtime/demo.db",
    "GRAPHSENTINEL_PHASE16_STATE": "artifacts/runtime/demo-phase16-state.json",
    "GRAPHSENTINEL_FUSION": "noisy_or",
    "GRAPHSENTINEL_AUTO_RESPONSE": "dry_run",
    "GRAPHSENTINEL_RESPONSE_BACKEND": "dry_run",
    "PYTHONIOENCODING": "utf-8",
}



def local_model_ready(model: str) -> bool:
    """True when Ollama answers and has ``model``, and langgraph can be imported."""
    try:
        import langgraph  # noqa: F401
    except ImportError:
        return False
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
    if not host.startswith("http"):
        host = "http://" + host
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=2) as reply:
            names = {m.get("name") for m in json.load(reply).get("models", [])}
    except (OSError, ValueError):
        return False
    return model in names or f"{model}:latest" in names


if __name__ == "__main__":
    required = ("GRAPHSENTINEL_CHECKPOINT", "GRAPHSENTINEL_TGN_MEMORY", "GRAPHSENTINEL_FEATURE_STATE")
    missing = [DEMO_ENV[k] for k in required if not Path(DEMO_ENV[k]).is_file()]
    if missing:
        sys.exit(f"Demo files missing: {missing}. Clone the full repository (git clone, not a partial download).")
    for key, value in DEMO_ENV.items():
        os.environ.setdefault(key, value)
    Path("artifacts/runtime").mkdir(parents=True, exist_ok=True)
    model = os.environ.setdefault("GRAPHSENTINEL_OLLAMA_MODEL", "qwen3.5:4b")
    if "GRAPHSENTINEL_TRIAGE_AGENT" not in os.environ:
        os.environ["GRAPHSENTINEL_TRIAGE_AGENT"] = "1" if local_model_ready(model) else "0"
    if os.environ["GRAPHSENTINEL_TRIAGE_AGENT"] == "1":
        print(f"AI reports: on (local model {model} via Ollama)")
    else:
        print(f"AI reports: off (start Ollama with {model} and install langgraph to turn them on)")
    port = os.environ.get("GRAPHSENTINEL_PORT", "8010")
    print(f"GraphSentinel demo: open http://127.0.0.1:{port} (Ctrl+C to stop)")
    from graphsentinel.api.run import run

    raise SystemExit(run(["--host", "127.0.0.1", "--port", port]))
