"""Start the GraphSentinel console with the bundled demo model (no LANL download needed).

    python run_demo.py            then open http://127.0.0.1:8010

Response actions run in dry-run mode: every lock is planned and audited, nothing is executed.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

DEMO_ENV = {
    "GRAPHSENTINEL_CHECKPOINT": "artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt",
    "GRAPHSENTINEL_ID_MAP_DIR": "artifacts/id_maps_lanl_1m_cuda",
    "GRAPHSENTINEL_TGN_MEMORY": "artifacts/state/tgn_memory.npz",
    "GRAPHSENTINEL_FEATURE_STATE": "artifacts/state/feature_state.json.gz",
    "GRAPHSENTINEL_DATABASE": "artifacts/runtime/demo.db",
    "GRAPHSENTINEL_FUSION": "noisy_or",
    "GRAPHSENTINEL_AUTO_RESPONSE": "dry_run",
    "GRAPHSENTINEL_RESPONSE_BACKEND": "dry_run",
    "PYTHONIOENCODING": "utf-8",
}

if __name__ == "__main__":
    missing = [v for k, v in DEMO_ENV.items() if k.endswith(("CHECKPOINT", "MEMORY", "STATE")) and not Path(v).is_file()]
    if missing:
        sys.exit(f"Demo files missing: {missing}. Clone the full repository (git clone, not a partial download).")
    for key, value in DEMO_ENV.items():
        os.environ.setdefault(key, value)
    Path("artifacts/runtime").mkdir(parents=True, exist_ok=True)
    port = os.environ.get("GRAPHSENTINEL_PORT", "8010")
    print(f"GraphSentinel demo: open http://127.0.0.1:{port} (Ctrl+C to stop)")
    from graphsentinel.api.run import run

    raise SystemExit(run(["--host", "127.0.0.1", "--port", port]))
