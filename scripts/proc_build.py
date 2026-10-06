"""Stream LANL proc.txt.gz into per-day Parquet files of process *start* events.

Each line is ``time,user@domain,computer,process name,Start|End``. Hosts and users
are mapped to the same integer ids the authentication days use (unknown -> -1),
and process names to a stable 64-bit hash. Only days ``< --days`` are kept, and
reading stops at the first event past them, so the 58-day file is not read to
its end.

    python scripts/proc_build.py --proc artifacts/downloads/lanl/proc.txt.gz \\
        --id-maps artifacts/fullrate/id_maps_0_29 --days 30 --out artifacts/proc/days
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
from pathlib import Path

import numpy as np
import polars as pl
import pyarrow as pa
import pyarrow.csv as pacsv

DAY = 86_400


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--proc", type=Path, required=True)
    ap.add_argument("--id-maps", type=Path, required=True)
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--block-mb", type=int, default=64)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--allow-partial", action="store_true", help="treat a truncated archive as its end (tests)")
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    hosts = json.loads((args.id_maps / "hosts.json").read_text(encoding="utf-8"))["values"]
    users = json.loads((args.id_maps / "users.json").read_text(encoding="utf-8"))["values"]
    host_map = pl.DataFrame({"computer": hosts, "host": np.arange(len(hosts), dtype=np.int32)})
    user_map = pl.DataFrame({"user_name": users, "user": np.arange(len(users), dtype=np.int32)})

    names = ["time", "user_name", "computer", "process", "action"]
    reader = pacsv.open_csv(
        gzip.open(args.proc, "rb"),
        read_options=pacsv.ReadOptions(column_names=names, block_size=args.block_mb << 20),
        convert_options=pacsv.ConvertOptions(column_types={
            "time": pa.int64(), "user_name": pa.string(), "computer": pa.string(),
            "process": pa.string(), "action": pa.string()}),
    )
    buffers: dict[int, list[pl.DataFrame]] = {}
    written: dict[int, int] = {}
    started = time.perf_counter()
    rows = 0
    done = False

    def flush(day: int) -> None:
        parts = buffers.pop(day, [])
        if not parts:
            return
        frame = pl.concat(parts).sort("t", maintain_order=True)
        frame.write_parquet(args.out / f"proc{day:02d}.parquet")
        written[day] = frame.height
        print(f"day {day:02d}: {frame.height:,} process starts", flush=True)

    while not done:
        try:
            batch = reader.read_next_batch()
        except StopIteration:
            break
        except EOFError:
            if not args.allow_partial:
                raise
            break
        f = pl.from_arrow(batch)
        rows += f.height
        if f["time"].min() >= args.days * DAY:  # type: ignore[operator]
            break
        f = f.filter((pl.col("action") == "Start") & (pl.col("time") < args.days * DAY))
        if f.height == 0:
            continue
        f = (
            f.join(host_map, on="computer", how="left")
            .join(user_map, on="user_name", how="left")
            .select(
                pl.col("time").cast(pl.Int32).alias("t"),
                pl.col("host").fill_null(-1).cast(pl.Int32),
                pl.col("user").fill_null(-1).cast(pl.Int32),
                pl.col("process").hash(seed=1729).reinterpret(signed=True).alias("proc"),
            )
        )
        for (day,), part in f.with_columns((pl.col("t") // DAY).alias("day")).partition_by("day", as_dict=True).items():
            buffers.setdefault(int(day), []).append(part.drop("day"))
        # the file is in time order: every day below the batch's first day is complete
        first_day = int(f["t"].min()) // DAY  # type: ignore[arg-type]
        for day in sorted(d for d in buffers if d < first_day):
            flush(day)
        if rows and rows % 50_000_000 < batch.num_rows:
            print(f"... {rows:,} lines read, {time.perf_counter() - started:.0f}s", flush=True)
    for day in sorted(buffers):
        flush(day)
    (args.out / "summary.json").write_text(json.dumps({
        "source": str(args.proc), "days": args.days, "lines_read": rows, "starts_per_day": written,
        "seconds": round(time.perf_counter() - started, 1)}, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
