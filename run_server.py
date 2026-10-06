import os
import uvicorn

if __name__ == "__main__":
    os.environ["GRAPHSENTINEL_CHECKPOINT"] = "artifacts/models/tgn-lanl_250k_cuda-candidate-4ca094f1eea4.pt"
    os.environ["GRAPHSENTINEL_ID_MAP_DIR"] = "artifacts/id_maps_lanl_bounded"
    os.environ["GRAPHSENTINEL_DATABASE"] = "artifacts/runtime/graphsentinel.db"
    os.environ["GRAPHSENTINEL_DEVICE"] = "cuda" if os.environ.get("CUDA_VISIBLE_DEVICES") != "" else "cpu"
    
    print("Starting GraphSentinel Server with TGN Checkpoint...")
    print(f"Checkpoint: {os.environ['GRAPHSENTINEL_CHECKPOINT']}")
    print(f"ID Maps:    {os.environ['GRAPHSENTINEL_ID_MAP_DIR']}")
    uvicorn.run("graphsentinel.api.main:app", host="127.0.0.1", port=8000, log_level="info")
