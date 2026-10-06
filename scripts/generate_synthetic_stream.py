"""Generate a high-quality, schema-faithful synthetic live-stream dataset.

Three distinct attack chains are injected, each modelling a different TTPs profile:

  ATK-001  Slow & stealthy lateral movement
           Long dwell between hops, normal business-hours timing, one attacker,
           star topology from a single compromised workstation.

  ATK-002  Credential spray + pivot chain
           Burst of authentication failures before each success, then true
           multi-hop pivoting where each hop's source host is the previous hop's
           destination (A→B, B→C, C→D), escalating toward a high-value target.

  ATK-003  Off-hours supply-chain infiltration
           A shared-service account (typically seen only during the day)
           authenticates to core infrastructure hosts at 2–4 AM using rare
           Kerberos-style auth types, staying just below the burst threshold.
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

from graphsentinel.features.causal import CausalFeatureEngine
from graphsentinel.ingestion.auth import NormalizedAuthEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hour_weight(timestamp: int, peak_hour: int = 10, off_hour: bool = False) -> float:
    """Business-hours probability envelope — higher weight near peak_hour."""
    hour = (timestamp % 86_400) // 3_600
    if off_hour:
        # Night-time: weight peaks around 3 AM
        distance = min(abs(hour - 3), 24 - abs(hour - 3))
    else:
        distance = min(abs(hour - peak_hour), 24 - abs(hour - peak_hour))
    return math.exp(-0.08 * distance ** 2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("=== GraphSentinel Synthetic Stream Generator v2 ===")

    input_dir = Path("data/processed/features_lanl_bounded")
    id_map_dir = Path("artifacts/id_maps_lanl_bounded")
    out_dir = Path("artifacts/synthetic")
    out_dir.mkdir(parents=True, exist_ok=True)

    user_map: list[str] = json.loads((id_map_dir / "users.json").read_text(encoding="utf-8"))["values"]
    host_map: list[str] = json.loads((id_map_dir / "hosts.json").read_text(encoding="utf-8"))["values"]

    table = pq.ParquetDataset(input_dir).read()
    df_train = table.to_pandas()
    print(f"Training data loaded: {len(df_train):,} events, "
          f"max ts={int(df_train['timestamp'].max())}")

    max_timestamp = int(df_train["timestamp"].max())
    user_counts = df_train["src_user_id"].value_counts()
    host_counts = df_train["dst_host_id"].value_counts()

    warm_users = [int(uid) for uid in user_counts.index if uid != 0][:1_500]
    warm_hosts = [int(hid) for hid in host_counts.index if hid != 0][:750]

    rng = np.random.default_rng(42)
    random.seed(42)

    # -----------------------------------------------------------------------
    # STEP 1 — Normal event generation (Poisson process, business-hours weighted)
    # -----------------------------------------------------------------------
    print("\n=== STEP 1: ~25 000 SYNTHETIC NORMAL EVENTS ===")

    df_warm = df_train[df_train["src_user_id"].isin(warm_users)]
    user_profiles: dict[int, list[tuple]] = {}
    for uid in warm_users:
        rows = df_warm[df_warm["src_user_id"] == uid]
        if rows.empty:
            continue
        user_profiles[uid] = list(zip(
            rows["dst_user_id"].values,
            rows["src_host_id"].values,
            rows["dst_host_id"].values,
            rows["auth_type_id"].values,
            rows["logon_type_id"].values,
            rows["orientation_id"].values,
            rows["success"].values,
        ))

    sim_duration = 7 * 86_400  # 7 days — nominal window used for placing the attack chains
    t_start = max_timestamp + 1
    total_normal_target = 25_000

    user_list = list(user_profiles.keys())

    # Business-hours acceptance-rejection thinning keeps roughly one in four raw
    # candidates (the weight curve integrates to ~26% of a uniform day), so the
    # raw Poisson rate must be oversampled well past the target count, and the
    # loop must keep generating until the target is actually reached rather
    # than pre-computing a fixed number of raw candidates.
    avg_interval = sim_duration / (total_normal_target * 4)
    normal_timestamps: list[int] = []
    t = t_start
    max_t = t_start + 30 * 86_400  # safety cap: never simulate past 30 days
    while len(normal_timestamps) < total_normal_target and t < max_t:
        dt = int(rng.exponential(scale=avg_interval))
        dt = max(1, min(dt, 300))
        t += dt
        if rng.random() < _hour_weight(t):
            normal_timestamps.append(t)
    t_end = normal_timestamps[-1] if normal_timestamps else t
    if len(normal_timestamps) < total_normal_target:
        print(f"  warning: only reached {len(normal_timestamps):,} of {total_normal_target:,} target normal events")

    raw_events: list[dict] = []
    for ev_id, ts in enumerate(normal_timestamps):
        uid = random.choice(user_list)
        tup = random.choice(user_profiles[uid])
        dst_user, src_host, dst_host, auth_type, logon_type, orientation, success = tup
        raw_events.append({
            "event_id": ev_id,
            "timestamp": int(ts),
            "src_user_id": int(uid),
            "dst_user_id": int(dst_user),
            "src_host_id": int(src_host),
            "dst_host_id": int(dst_host),
            "auth_type_id": int(auth_type),
            "logon_type_id": int(logon_type),
            "orientation_id": int(orientation),
            "success": int(success),
            "label_redteam": 0,
            "day": int(ts) // 86_400,
            "hour": (int(ts) % 86_400) // 3_600,
            "attack_chain_id": None,
        })

    print(f"Generated {len(raw_events):,} normal events "
          f"[{t_start} → {t_end}]")

    # -----------------------------------------------------------------------
    # STEP 2 — ATK-001: Slow & stealthy lateral movement
    # -----------------------------------------------------------------------
    print("\n=== STEP 2: ATK-001 — Slow & stealthy lateral movement ===")

    ATK001_USER = 80  # U66@DOM1
    atk001_src_host = int(
        df_train[df_train["src_user_id"] == ATK001_USER]["src_host_id"].value_counts().index[0]
    )
    atk001_seen_dsts = set(
        df_train[df_train["src_user_id"] == ATK001_USER]["dst_host_id"].unique()
    )
    atk001_targets = [h for h in warm_hosts if h not in atk001_seen_dsts][:7]

    atk001_start = t_start + int(0.30 * sim_duration)  # Early in the window
    atk001_events: list[dict] = []
    atk001_steps: list[dict] = []
    cur = atk001_start
    for step_i, dst_h in enumerate(atk001_targets):
        # Slow: 3–8 minutes between hops, only during business hours
        dt = random.randint(180, 480)
        cur += dt
        # Skip forward if we land in off-hours
        while _hour_weight(cur) < 0.2:
            cur += 1_800
        day = cur // 86_400
        hour = (cur % 86_400) // 3_600
        ev = {
            "event_id": -1,
            "timestamp": int(cur),
            "src_user_id": int(ATK001_USER),
            "dst_user_id": int(ATK001_USER),
            "src_host_id": int(atk001_src_host),
            "dst_host_id": int(dst_h),
            "auth_type_id": 1,  # NTLM
            "logon_type_id": 1,  # Network
            "orientation_id": 1,  # LogOn
            "success": 1,
            "label_redteam": 1,
            "day": int(day),
            "hour": int(hour),
            "attack_chain_id": "ATK-001",
        }
        raw_events.append(ev)
        atk001_events.append(ev)
        atk001_steps.append({
            "step": step_i + 1,
            "timestamp": int(cur),
            "attacker_user_id": int(ATK001_USER),
            "attacker_user_name": user_map[ATK001_USER] if ATK001_USER < len(user_map) else f"U{ATK001_USER}",
            "source_host_id": int(atk001_src_host),
            "source_host_name": host_map[atk001_src_host] if atk001_src_host < len(host_map) else f"H{atk001_src_host}",
            "destination_host_id": int(dst_h),
            "destination_host_name": host_map[dst_h] if dst_h < len(host_map) else f"H{dst_h}",
            "tactic": "lateral_movement",
        })

    print(f"  Injected {len(atk001_events)} ATK-001 hops "
          f"[ts {atk001_start} → {cur}]")

    # -----------------------------------------------------------------------
    # STEP 3 — ATK-002: Credential spray + true multi-hop pivot chain
    # -----------------------------------------------------------------------
    print("\n=== STEP 3: ATK-002 — Credential spray + pivot chain ===")

    # Use a mid-activity user that has many training destinations
    mid_users = [uid for uid in warm_users if 50 < user_counts.get(uid, 0) < 500]
    ATK002_USER = mid_users[3] if len(mid_users) > 3 else warm_users[15]
    atk002_seen_dsts = set(
        df_train[df_train["src_user_id"] == ATK002_USER]["dst_host_id"].unique()
    )
    atk002_chain_hosts = [h for h in warm_hosts if h not in atk002_seen_dsts][:8]
    # True pivot: A→B, B→C, C→D, ...
    atk002_src_host_initial = int(
        df_train[df_train["src_user_id"] == ATK002_USER]["src_host_id"].value_counts().index[0]
    )

    atk002_start = t_start + int(0.55 * sim_duration)
    atk002_events: list[dict] = []
    atk002_steps: list[dict] = []
    cur = atk002_start
    current_src_host = atk002_src_host_initial

    for step_i, dst_h in enumerate(atk002_chain_hosts):
        # Spray: 1-3 failures, then a success
        n_failures = random.randint(1, 3)
        for _ in range(n_failures):
            dt = random.randint(5, 20)
            cur += dt
            day = cur // 86_400
            hour = (cur % 86_400) // 3_600
            fail_ev = {
                "event_id": -1,
                "timestamp": int(cur),
                "src_user_id": int(ATK002_USER),
                "dst_user_id": int(ATK002_USER),
                "src_host_id": int(current_src_host),
                "dst_host_id": int(dst_h),
                "auth_type_id": 2,  # NTLM challenge/response
                "logon_type_id": 1,
                "orientation_id": 1,
                "success": 0,  # Failure
                "label_redteam": 1,
                "day": int(day),
                "hour": int(hour),
                "attack_chain_id": "ATK-002",
            }
            raw_events.append(fail_ev)
            atk002_events.append(fail_ev)

        dt = random.randint(10, 40)
        cur += dt
        day = cur // 86_400
        hour = (cur % 86_400) // 3_600
        success_ev = {
            "event_id": -1,
            "timestamp": int(cur),
            "src_user_id": int(ATK002_USER),
            "dst_user_id": int(ATK002_USER),
            "src_host_id": int(current_src_host),
            "dst_host_id": int(dst_h),
            "auth_type_id": 2,
            "logon_type_id": 1,
            "orientation_id": 1,
            "success": 1,
            "label_redteam": 1,
            "day": int(day),
            "hour": int(hour),
            "attack_chain_id": "ATK-002",
        }
        raw_events.append(success_ev)
        atk002_events.append(success_ev)
        atk002_steps.append({
            "step": step_i + 1,
            "timestamp": int(cur),
            "attacker_user_id": int(ATK002_USER),
            "attacker_user_name": user_map[ATK002_USER] if ATK002_USER < len(user_map) else f"U{ATK002_USER}",
            "source_host_id": int(current_src_host),
            "source_host_name": host_map[current_src_host] if current_src_host < len(host_map) else f"H{current_src_host}",
            "destination_host_id": int(dst_h),
            "destination_host_name": host_map[dst_h] if dst_h < len(host_map) else f"H{dst_h}",
            "failures_before_success": n_failures,
            "tactic": "credential_spray_pivot",
        })
        # Pivot: next hop's source is this hop's destination
        current_src_host = dst_h

    print(f"  Injected {len(atk002_events)} ATK-002 events "
          f"({len(atk002_steps)} successful hops + failures) [ts {atk002_start} → {cur}]")

    # -----------------------------------------------------------------------
    # STEP 4 — ATK-003: Off-hours supply-chain infiltration via service account
    # -----------------------------------------------------------------------
    print("\n=== STEP 4: ATK-003 — Off-hours supply-chain infiltration ===")

    # Find a service-like account: low unique-user count, high-frequency, specific hours
    svc_candidates = [
        uid for uid in warm_users
        if uid not in {ATK001_USER, ATK002_USER}
        and 100 < user_counts.get(uid, 0) < 800
    ]
    ATK003_USER = svc_candidates[1] if len(svc_candidates) > 1 else warm_users[30]
    atk003_seen_dsts = set(
        df_train[df_train["src_user_id"] == ATK003_USER]["dst_host_id"].unique()
    )
    # Target high-value hosts (most-connected destinations in training data)
    hv_targets = [int(h) for h in host_counts.index[:20] if int(h) not in atk003_seen_dsts][:6]
    atk003_src_host = int(
        df_train[df_train["src_user_id"] == ATK003_USER]["src_host_id"].value_counts().index[0]
    )

    # Place ATK-003 in the early morning of day 5 of the simulation
    day5_midnight = t_start + 4 * 86_400
    atk003_start = day5_midnight + 2 * 3_600  # 2 AM
    atk003_events: list[dict] = []
    atk003_steps: list[dict] = []
    cur = atk003_start

    for step_i, dst_h in enumerate(hv_targets):
        # Slow and stealthy at night: 8–20 minute gaps
        dt = random.randint(480, 1_200)
        cur += dt
        day = cur // 86_400
        hour = (cur % 86_400) // 3_600
        # Use rare auth type: 3 = Kerberos
        ev = {
            "event_id": -1,
            "timestamp": int(cur),
            "src_user_id": int(ATK003_USER),
            "dst_user_id": int(ATK003_USER),
            "src_host_id": int(atk003_src_host),
            "dst_host_id": int(dst_h),
            "auth_type_id": 3,  # Kerberos (rare for this account)
            "logon_type_id": 2,  # Batch / service
            "orientation_id": 1,
            "success": 1,
            "label_redteam": 1,
            "day": int(day),
            "hour": int(hour),
            "attack_chain_id": "ATK-003",
        }
        raw_events.append(ev)
        atk003_events.append(ev)
        atk003_steps.append({
            "step": step_i + 1,
            "timestamp": int(cur),
            "attacker_user_id": int(ATK003_USER),
            "attacker_user_name": user_map[ATK003_USER] if ATK003_USER < len(user_map) else f"U{ATK003_USER}",
            "source_host_id": int(atk003_src_host),
            "source_host_name": host_map[atk003_src_host] if atk003_src_host < len(host_map) else f"H{atk003_src_host}",
            "destination_host_id": int(dst_h),
            "destination_host_name": host_map[dst_h] if dst_h < len(host_map) else f"H{dst_h}",
            "tactic": "supply_chain_offhours",
        })

    print(f"  Injected {len(atk003_events)} ATK-003 events "
          f"[ts {atk003_start} → {cur}, hour {atk003_start % 86_400 // 3_600}–{cur % 86_400 // 3_600}]")

    # -----------------------------------------------------------------------
    # STEP 5 — Sort, re-ID, run CausalFeatureEngine
    # -----------------------------------------------------------------------
    print("\n=== STEP 5: CAUSAL FEATURE ENGINE ===")

    raw_events.sort(key=lambda x: x["timestamp"])
    for idx, ev in enumerate(raw_events):
        ev["event_id"] = idx

    normalized_events = [
        NormalizedAuthEvent(
            event_id=ev["event_id"],
            timestamp=ev["timestamp"],
            src_user_id=ev["src_user_id"],
            dst_user_id=ev["dst_user_id"],
            src_host_id=ev["src_host_id"],
            dst_host_id=ev["dst_host_id"],
            auth_type_id=ev["auth_type_id"],
            logon_type_id=ev["logon_type_id"],
            orientation_id=ev["orientation_id"],
            success=ev["success"],
            label_redteam=ev["label_redteam"],
            day=ev["day"],
            hour=ev["hour"],
        )
        for ev in raw_events
    ]

    engine = CausalFeatureEngine()
    print(f"Computing 27 rolling causal features over {len(normalized_events):,} events...")
    feature_records = list(engine.transform(normalized_events))

    records_dicts = [rec.to_dict() for rec in feature_records]
    df_synthetic = pd.DataFrame(records_dicts)
    df_synthetic["feature_day"] = df_synthetic["day"]

    df_synthetic = df_synthetic[df_train.columns]
    for col in df_train.columns:
        if col == "feature_day":
            # A pandas category dtype does not survive a parquet round-trip in
            # this pyarrow/pandas combination (verified: writes as category,
            # reads back as int64 regardless of source). feature_day isn't
            # consumed by any downstream reader, so match what actually
            # round-trips rather than chasing an environment quirk.
            df_synthetic[col] = df_synthetic[col].astype("int64")
        else:
            df_synthetic[col] = df_synthetic[col].astype(df_train[col].dtype)

    print(f"Final dataset shape: {df_synthetic.shape}")
    comparable_dtypes = df_train.dtypes.drop("feature_day")
    dtype_ok = (df_synthetic.dtypes.drop("feature_day") == comparable_dtypes).all()
    print(f"Dtype match (excluding feature_day, a known category/int64 parquet quirk): {dtype_ok}")

    # -----------------------------------------------------------------------
    # STEP 6 — Write outputs + ground-truth manifest
    # -----------------------------------------------------------------------
    print("\n=== STEP 6: WRITING OUTPUTS ===")

    parquet_path = out_dir / "synthetic_live_stream.parquet"
    csv_path = out_dir / "synthetic_live_stream.csv"
    manifest_path = out_dir / "ground_truth_manifest.json"

    df_synthetic.to_parquet(parquet_path, index=False)
    df_synthetic.to_csv(csv_path, index=False)

    attack_meta = [
        {
            "chain_id": "ATK-001",
            "profile": "slow_stealthy_lateral_movement",
            "attacker_user_id": int(ATK001_USER),
            "attacker_user_name": user_map[ATK001_USER] if ATK001_USER < len(user_map) else f"U{ATK001_USER}",
            "event_count": int(len(atk001_events)),
            "steps": atk001_steps,
        },
        {
            "chain_id": "ATK-002",
            "profile": "credential_spray_pivot_chain",
            "attacker_user_id": int(ATK002_USER),
            "attacker_user_name": user_map[ATK002_USER] if ATK002_USER < len(user_map) else f"U{ATK002_USER}",
            "event_count": int(len(atk002_events)),
            "steps": atk002_steps,
        },
        {
            "chain_id": "ATK-003",
            "profile": "offhours_supply_chain_infiltration",
            "attacker_user_id": int(ATK003_USER),
            "attacker_user_name": user_map[ATK003_USER] if ATK003_USER < len(user_map) else f"U{ATK003_USER}",
            "event_count": int(len(atk003_events)),
            "steps": atk003_steps,
        },
    ]

    all_attack_indices = [
        int(i) for i in df_synthetic[df_synthetic["label_redteam"] == 1].index
    ]

    manifest_data = {
        "dataset_name": "synthetic_live_stream_v2",
        "generator_version": "2.0.0",
        # The stream stores integer ids; they are names only through this
        # dictionary. The API names the stream with it, not with whatever
        # dictionary the server happens to serve with.
        "id_map_dir": id_map_dir.as_posix(),
        "total_rows": int(len(df_synthetic)),
        "normal_rows": int(len(raw_events) - len(atk001_events) - len(atk002_events) - len(atk003_events)),
        "attack_rows": int(len(all_attack_indices)),
        "attack_row_indices": all_attack_indices,
        "attack_chains": attack_meta,
    }

    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    total_attacks = len(atk001_events) + len(atk002_events) + len(atk003_events)
    print(f"\nSummary:")
    print(f"  Normal events : {len(raw_events) - total_attacks:,}")
    print(f"  ATK-001 events: {len(atk001_events):,} ({len(atk001_steps)} hops)")
    print(f"  ATK-002 events: {len(atk002_events):,} ({len(atk002_steps)} successful hops)")
    print(f"  ATK-003 events: {len(atk003_events):,} ({len(atk003_steps)} hops, off-hours)")
    print(f"  Total          : {len(df_synthetic):,}")
    print(f"\nOutputs → {out_dir}/")
    print(f"  {parquet_path.name}")
    print(f"  {csv_path.name}")
    print(f"  {manifest_path.name}")


if __name__ == "__main__":
    main()
