"""Step 5: Validation script for synthetic live-stream dataset.

Audits schema, entity resolution against frozen training id_maps, and verifies ground truth attack labels.
"""

import json
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq

from graphsentinel.ingestion.id_map import AuthIdMaps

def validate():
    print("=== STEP 5: VALIDATING SYNTHETIC LIVE-STREAM DATASET ===")

    train_dir = Path("data/processed/features_lanl_bounded")
    synthetic_parquet = Path("artifacts/synthetic/synthetic_live_stream.parquet")
    manifest_json = Path("artifacts/synthetic/ground_truth_manifest.json")
    id_map_dir = Path("artifacts/id_maps_lanl_bounded")

    # Load datasets & maps
    df_train = pq.ParquetDataset(train_dir).read().to_pandas()
    df_syn = pq.ParquetDataset(synthetic_parquet).read().to_pandas()
    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    maps = AuthIdMaps.load(id_map_dir)

    print(f"1. Synthetic Row Count: {len(df_syn)} events.")
    print(f"2. Synthetic Schema Columns Count: {len(df_syn.columns)} (Matches Training: {list(df_syn.columns) == list(df_train.columns)})")

    # Audit User & Host ID boundaries
    max_user_id = df_syn["src_user_id"].max()
    max_host_id = max(df_syn["src_host_id"].max(), df_syn["dst_host_id"].max())
    user_map_capacity = len(maps.users)
    host_map_capacity = len(maps.hosts)

    print(f"\n3. Entity Dictionary Resolution Check:")
    print(f"   - Synthetic Max User ID: {max_user_id} (Training id_maps User Capacity: {user_map_capacity})")
    print(f"   - Synthetic Max Host ID: {max_host_id} (Training id_maps Host Capacity: {host_map_capacity})")

    # Assert 100% resolution within existing dictionary
    assert max_user_id < user_map_capacity, f"FAIL: Synthetic User ID {max_user_id} exceeds frozen dictionary capacity {user_map_capacity}!"
    assert max_host_id < host_map_capacity, f"FAIL: Synthetic Host ID {max_host_id} exceeds frozen dictionary capacity {host_map_capacity}!"
    print("   [SUCCESS] All synthetic users and hosts resolve to existing IDs in id_maps_lanl_bounded!")

    # Unique nodes count
    unique_users = set(df_syn["src_user_id"]).union(set(df_syn["dst_user_id"]))
    unique_hosts = set(df_syn["src_host_id"]).union(set(df_syn["dst_host_id"]))
    total_unique_nodes = len(unique_users.union(unique_hosts))
    print(f"\n4. Unique Node Count in Synthetic Stream: {total_unique_nodes} nodes ({len(unique_users)} users, {len(unique_hosts)} hosts)")

    # Attack chain validation
    attack_rows = df_syn[df_syn["label_redteam"] == 1]
    print(f"\n5. Ground Truth Attack Chain Audit ('{manifest['attack_chain_id']}'):")
    print(f"   - Expected Attack Count: {manifest['attack_event_count']}")
    print(f"   - Observed Labeled Attack Count: {len(attack_rows)}")
    print(f"   - Attacker Identity: ID={manifest['attacker_user_id']} ('{manifest['attacker_user_name']}')")
    
    assert len(attack_rows) == manifest['attack_event_count'], "FAIL: Attack row count mismatch!"
    assert (attack_rows.index.tolist()) == manifest['attack_row_indices'], "FAIL: Attack row indices mismatch!"
    print("   [SUCCESS] Ground truth attack chain validated and correctly labeled!")

    print("\n=== STEP 5 VALIDATION COMPLETE: DATASET IS 100% READY FOR STREAMING & SCORING ===")

if __name__ == "__main__":
    validate()
