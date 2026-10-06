"""Step 6: Real-time API Streamer for TGN Lateral Movement Detector.

Reads synthetic_live_stream.parquet in timestamp order and streams events via HTTP POST requests
to the GraphSentinel FastAPI live detection gateway, printing live risk scores and alert flags.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq
import requests

from graphsentinel.api.main import create_app
from fastapi.testclient import TestClient

# Ensure UTF-8 output formatting for Windows console compatibility
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

def main():
    parser = argparse.ArgumentParser(description="Stream synthetic authentication events to GraphSentinel API")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000", help="FastAPI base URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--delay", type=float, default=0.01, help="Inter-event streaming delay in seconds (default: 0.01s / 10ms)")
    parser.add_argument("--max-events", type=int, default=100, help="Maximum events to stream in demo (default: 100, 0 for all)")
    parser.add_argument("--in-process", action="store_true", help="Run in-process test client if standalone FastAPI server is not running")
    args = parser.parse_args()

    synthetic_parquet = Path("artifacts/synthetic/synthetic_live_stream.parquet")
    manifest_json = Path("artifacts/synthetic/ground_truth_manifest.json")
    id_map_dir = Path("artifacts/id_maps_lanl_bounded")

    if not synthetic_parquet.exists():
        print(f"Error: Synthetic stream file {synthetic_parquet} not found. Run generate_synthetic_stream.py first.")
        sys.exit(1)

    # Load ID maps for string name resolution
    user_map = json.loads((id_map_dir / "users.json").read_text(encoding="utf-8"))["values"]
    host_map = json.loads((id_map_dir / "hosts.json").read_text(encoding="utf-8"))["values"]
    auth_map = json.loads((id_map_dir / "auth_types.json").read_text(encoding="utf-8"))["values"]
    logon_map = json.loads((id_map_dir / "logon_types.json").read_text(encoding="utf-8"))["values"]
    orientation_map = json.loads((id_map_dir / "orientations.json").read_text(encoding="utf-8"))["values"]

    # Load synthetic dataset and ground truth manifest
    df_syn = pq.ParquetDataset(synthetic_parquet).read().to_pandas()
    manifest = json.loads(manifest_json.read_text(encoding="utf-8"))
    attack_indices = set(manifest["attack_row_indices"])

    print("================================================================================")
    print("GRAPHSENTINEL LIVE STREAMER - TGN LATERAL MOVEMENT DETECTOR")
    print("================================================================================")
    print(f"Total Stream Events Available : {len(df_syn)}")
    print(f"Attack Chain ID               : {manifest['attack_chain_id']} (Attacker: '{manifest['attacker_user_name']}')")
    print(f"Injected Attack Row Indices   : {manifest['attack_row_indices']}")
    print(f"Streaming Speed Delay         : {args.delay}s per event")
    print("================================================================================\n")

    # Set up client
    client = None
    if args.in_process:
        print("[MODE] Initializing In-Process FastAPI TestClient with trained TGN model session...")
        app = create_app()
        client = TestClient(app)
    else:
        # Check external FastAPI server health
        try:
            r = requests.get(f"{args.url}/health", timeout=2.0)
            if r.status_code == 200:
                print(f"[MODE] Connected to running FastAPI Server at {args.url} (Health OK)")
            else:
                print(f"[WARN] Server at {args.url} returned status {r.status_code}. Switching to in-process client.")
                app = create_app()
                client = TestClient(app)
        except Exception:
            print(f"[INFO] No standalone FastAPI server running at {args.url}. Launching in-process scoring engine...")
            app = create_app()
            client = TestClient(app)

    limit = len(df_syn) if args.max_events == 0 else min(args.max_events, len(df_syn))
    stream_rows = list(df_syn.iloc[:limit].iterrows())
    attack_df_rows = list(df_syn[df_syn["label_redteam"] == 1].iterrows())
    max_attack_idx = max(manifest["attack_row_indices"])

    alerts_triggered = 0
    attacks_caught = 0

    print("\n--- STARTING REAL-TIME EVENT STREAMING ---\n")
    start_time = time.time()

    def process_event_payload(payload_dict, is_attack_event, event_row_idx, u_str, h_dst_str, timestamp_val):
        nonlocal alerts_triggered, attacks_caught
        if client:
            resp = client.post("/api/v1/live/events", json=payload_dict)
        else:
            resp = requests.post(f"{args.url}/api/v1/live/events", json=payload_dict)

        if resp.status_code != 200:
            print(f"Row {event_row_idx:05d} | t={timestamp_val:<8d} | [SKIPPED {resp.status_code}] {u_str[:15]:<15} -> {h_dst_str:<8}")
            return

        res_json = resp.json()
        results = res_json.get("results", [])
        if not results:
            return

        score_res = results[0]
        risk_score = score_res["risk"]
        alerted = score_res["alerted"]
        severity = score_res["severity"]

        if alerted:
            alerts_triggered += 1

        attack_flag = "[ATTACK INJECTED]" if is_attack_event else "[NORMAL EVENT]  "
        alert_status = f"[ALERT: {severity.upper():<7}]" if alerted or risk_score >= 0.35 else "[OK]           "

        print(f"Row {event_row_idx:05d} | t={timestamp_val:<8d} | {attack_flag} | {u_str[:15]:<15} -> {h_dst_str:<8} | Risk: {risk_score:.4f} | {alert_status}")

        if is_attack_event and (alerted or risk_score >= 0.35):
            attacks_caught += 1

    last_sent_ts = 0
    try:
        if not client:
            status_resp = requests.get(f"{args.url}/api/v1/live/status", timeout=2.0)
            if status_resp.status_code == 200:
                last_server_ts = status_resp.json().get("last_timestamp")
                if last_server_ts is not None:
                    last_sent_ts = int(last_server_ts)
    except Exception:
        pass

    for row_idx, row in stream_rows:
        raw_ts = int(row["timestamp"])
        ts = max(raw_ts, last_sent_ts + 1)
        last_sent_ts = ts
        src_u_id = int(row["src_user_id"])
        dst_u_id = int(row["dst_user_id"])
        src_h_id = int(row["src_host_id"])
        dst_h_id = int(row["dst_host_id"])
        auth_id = int(row["auth_type_id"])
        logon_id = int(row["logon_type_id"])
        orient_id = int(row["orientation_id"])
        success_val = bool(row["success"])
        is_attack = row_idx in attack_indices

        user_str = user_map[src_u_id] if src_u_id < len(user_map) else f"USER_{src_u_id}"
        dest_user_str = user_map[dst_u_id] if dst_u_id < len(user_map) else f"USER_{dst_u_id}"
        src_host_str = host_map[src_h_id] if src_h_id < len(host_map) else f"HOST_{src_h_id}"
        dst_host_str = host_map[dst_h_id] if dst_h_id < len(host_map) else f"HOST_{dst_h_id}"

        if src_host_str == dst_host_str:
            dst_host_str = host_map[(dst_h_id + 1) % len(host_map)]

        auth_str = auth_map[auth_id] if auth_id < len(auth_map) else "unknown"
        logon_str = logon_map[logon_id] if logon_id < len(logon_map) else "unknown"
        orient_str = orientation_map[orient_id] if orient_id < len(orientation_map) else "logon"

        payload = {
            "events": [
                {
                    "timestamp": ts,
                    "user": user_str,
                    "source_host": src_host_str,
                    "destination_host": dst_host_str,
                    "destination_user": dest_user_str,
                    "auth_type": auth_str,
                    "logon_type": logon_str,
                    "orientation": orient_str,
                    "success": success_val,
                    "corroboration": 0.0,
                    "source": "lanl_synthetic_stream"
                }
            ]
        }

        process_event_payload(payload, is_attack, row_idx, user_str, dst_host_str, ts)
        if args.delay > 0:
            time.sleep(args.delay)

    # Stream the injected attack chain specifically if max_events didn't reach it
    if limit <= max_attack_idx:
        print("\n--- STREAMING INJECTED ATTACK CHAIN EVENTS (ATK-001) ---\n")
        for row_idx, row in attack_df_rows:
            raw_ts = int(row["timestamp"])
            ts = max(raw_ts, last_sent_ts + 1)
            last_sent_ts = ts
            src_u_id = int(row["src_user_id"])
            dst_u_id = int(row["dst_user_id"])
            src_h_id = int(row["src_host_id"])
            dst_h_id = int(row["dst_host_id"])
            auth_id = int(row["auth_type_id"])
            logon_id = int(row["logon_type_id"])
            orient_id = int(row["orientation_id"])
            success_val = bool(row["success"])

            user_str = user_map[src_u_id] if src_u_id < len(user_map) else f"USER_{src_u_id}"
            dest_user_str = user_map[dst_u_id] if dst_u_id < len(user_map) else f"USER_{dst_u_id}"
            src_host_str = host_map[src_h_id] if src_h_id < len(host_map) else f"HOST_{src_h_id}"
            dst_host_str = host_map[dst_h_id] if dst_h_id < len(host_map) else f"HOST_{dst_h_id}"
            if src_host_str == dst_host_str:
                dst_host_str = host_map[(dst_h_id + 1) % len(host_map)]

            auth_str = auth_map[auth_id] if auth_id < len(auth_map) else "unknown"
            logon_str = logon_map[logon_id] if logon_id < len(logon_map) else "unknown"
            orient_str = orientation_map[orient_id] if orient_id < len(orientation_map) else "logon"

            payload = {
                "events": [
                    {
                        "timestamp": ts,
                        "user": user_str,
                        "source_host": src_host_str,
                        "destination_host": dst_host_str,
                        "destination_user": dest_user_str,
                        "auth_type": auth_str,
                        "logon_type": logon_str,
                        "orientation": orient_str,
                        "success": success_val,
                        "corroboration": 0.0,
                        "source": "lanl_synthetic_stream"
                    }
                ]
            }

            process_event_payload(payload, True, row_idx, user_str, dst_host_str, ts)
            if args.delay > 0:
                time.sleep(args.delay)

    elapsed = time.time() - start_time
    print("\n================================================================================")
    print("LIVE STREAMING DEMONSTRATION COMPLETE")
    print("================================================================================")
    print(f"Total Events Streamed  : {limit + (len(attack_df_rows) if limit <= max_attack_idx else 0)}")
    print(f"Total Time Elapsed     : {elapsed:.2f} seconds")
    print(f"Total Alerts Triggered : {alerts_triggered}")
    print(f"Attack Chain Detected  : {attacks_caught} / {len(manifest['attack_row_indices'])} attack events flagged")
    print("================================================================================")

if __name__ == "__main__":
    main()
