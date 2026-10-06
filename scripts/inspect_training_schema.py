"""Step 0: Inspection script to output exact column names, dtypes, and sample rows from features_lanl_bounded."""

import json
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq

def inspect_schema():
    input_dir = Path("data/processed/features_lanl_bounded")
    id_map_dir = Path("artifacts/id_maps_lanl_bounded")

    print("=== STEP 0: DATASET & ID MAP INSPECTION ===")
    dataset = pq.ParquetDataset(input_dir)
    table = dataset.read()
    df = table.to_pandas()

    print(f"\n1. Training Dataset Shape: {df.shape}")
    print("\n2. Columns and DataTypes:")
    for col, dtype in df.dtypes.items():
        print(f"   - {col}: {dtype}")

    print("\n3. First 5 Sample Rows:")
    print(df.head(5).to_string())

    print("\n4. ID Maps Inspection:")
    for name in ["users", "hosts", "auth_types", "logon_types", "orientations"]:
        json_path = id_map_dir / f"{name}.json"
        if json_path.exists():
            content = json.loads(json_path.read_text(encoding="utf-8"))
            values = content.get("values", [])
            print(f"   - {name}.json: total items = {len(values)}, sample first 5 = {values[:5]}")
        else:
            print(f"   - {name}.json: NOT FOUND")

if __name__ == "__main__":
    inspect_schema()
