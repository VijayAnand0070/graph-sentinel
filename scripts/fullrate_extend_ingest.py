"""Extend the full-rate corpus with later days, keeping every existing id.

The first ingest covered days 0-15 and was used for development; days 16-29
(60 more red-team events from two attacker hosts) are the final test window.
This skips the raw file to the start day cheaply, then normalises rows exactly
as ``ingestion.auth`` does (local logons dropped, labels matched), encoding
entities with the existing id maps extended in place of fresh ones, so an
account or host keeps its id across both windows.

    python scripts/fullrate_extend_ingest.py --start-day 16 --end-day 29 \\
        --id-maps artifacts/fullrate/id_maps --id-maps-out artifacts/fullrate/id_maps_0_29 \\
        --output artifacts/fullrate/interim
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from graphsentinel.ingestion.auth import SECONDS_PER_DAY, NormalizedAuthEvent  # noqa: E402
from graphsentinel.ingestion.id_map import AuthIdMaps  # noqa: E402
from graphsentinel.ingestion.labels import RedTeamIndex  # noqa: E402
from graphsentinel.ingestion.parquet import ParquetPartitionWriter  # noqa: E402

EVENT_ID_OFFSET = 1_000_000_000


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--auth", type=Path, default=ROOT / "data/raw/lanl/auth.txt.gz")
    ap.add_argument("--redteam", type=Path, default=ROOT / "data/raw/lanl/redteam.txt.gz")
    ap.add_argument("--start-day", type=int, required=True)
    ap.add_argument("--end-day", type=int, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--id-maps-out", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--chunk-rows", type=int, default=200_000)
    args = ap.parse_args(argv)
    start_t = args.start_day * SECONDS_PER_DAY
    end_t = (args.end_day + 1) * SECONDS_PER_DAY - 1
    labels = RedTeamIndex.from_gzip(args.redteam)
    maps = AuthIdMaps.load(args.id_maps)
    writer = ParquetPartitionWriter(args.output)
    started = time.perf_counter()
    stats = {"skipped": 0, "read": 0, "self_loops": 0, "kept": 0, "redteam": 0, "rejected": 0}
    chunk: list[NormalizedAuthEvent] = []
    with gzip.open(args.auth, "rt", encoding="utf-8", newline="") as stream:
        for line in stream:
            comma = line.find(",")
            t = int(line[:comma])
            if t < start_t:
                stats["skipped"] += 1
                if stats["skipped"] % 50_000_000 == 0:
                    print(f"  skipped {stats['skipped']:,} rows ({time.perf_counter() - started:.0f}s)", flush=True)
                continue
            if t > end_t:
                break
            stats["read"] += 1
            values = [v.strip() for v in line.rstrip("\r\n").split(",")]
            if len(values) != 9:
                stats["rejected"] += 1
                continue
            success = {"success": 1, "fail": 0}.get(values[8].casefold())
            if success is None:
                stats["rejected"] += 1
                continue
            label = int(labels.contains(t, values[1], values[3], values[4]))
            if values[3] == values[4]:
                stats["self_loops"] += 1
                continue
            chunk.append(
                NormalizedAuthEvent(
                    event_id=EVENT_ID_OFFSET + stats["kept"],
                    timestamp=t,
                    src_user_id=maps.users.encode(values[1]),
                    dst_user_id=maps.users.encode(values[2]),
                    src_host_id=maps.hosts.encode(values[3]),
                    dst_host_id=maps.hosts.encode(values[4]),
                    auth_type_id=maps.auth_types.encode(values[5]),
                    logon_type_id=maps.logon_types.encode(values[6]),
                    orientation_id=maps.orientations.encode(values[7]),
                    success=success,
                    label_redteam=label,
                    day=t // SECONDS_PER_DAY,
                    hour=(t % SECONDS_PER_DAY) // 3_600,
                )
            )
            stats["kept"] += 1
            stats["redteam"] += label
            if len(chunk) >= args.chunk_rows:
                writer.write(chunk)
                chunk = []
    if chunk:
        writer.write(chunk)
    maps.save(args.id_maps_out)
    stats["seconds"] = round(time.perf_counter() - started, 1)
    stats["users"] = len(maps.users)
    stats["hosts"] = len(maps.hosts)
    (args.output.parent / "reports").mkdir(parents=True, exist_ok=True)
    (args.output.parent / "reports" / f"ingest_days_{args.start_day}_{args.end_day}.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8"
    )
    print(json.dumps(stats), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
