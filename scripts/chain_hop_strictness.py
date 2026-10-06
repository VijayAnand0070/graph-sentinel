"""Hourly benign cost of the shipped chain rule at full rate, by what the
*current* event must be, under the tracker-owned novelty test (Finding 27).

  A  current event unrestricted (three prior novel successful hops, moving on
     from a reached host: what ``continues_chain`` returns -- the pivot
     channel's question)
  B  A, and the current event is a successful authentication
  C  B, and its destination is one the account has never successfully reached
     (what ``is_chain_hop`` returns -- the rule's question, shipped)

    python scripts/chain_hop_strictness.py artifacts/e2e/fullrate_day1/features \
        artifacts/prevention/chain_hop_strictness.json
"""

from __future__ import annotations

import json
import sys
import time
from itertools import groupby
from pathlib import Path

ROOT = Path("D:/graph_sentinel")
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from chain_rule_study import records_from_frame  # noqa: E402
from measure_prevention import load_frame  # noqa: E402

from graphsentinel.detection.policy import DEFAULT_CHAIN_RULE  # noqa: E402

data = Path(sys.argv[1])
out = Path(sys.argv[2])
frame = load_frame(data)
print("events", frame.height, "rule", DEFAULT_CHAIN_RULE.name, flush=True)
tracker = DEFAULT_CHAIN_RULE.tracker()
hours: dict[int, dict[str, object]] = {}
t0 = time.time()
for _ts, grouped in groupby(records_from_frame(frame), key=lambda r: r.timestamp):
    group = list(grouped)
    hour = group[0].timestamp // 3_600
    bucket = hours.setdefault(
        hour, {"benign": 0, "A": 0, "B": 0, "C": 0, "uA": set(), "uB": set(), "uC": set()}
    )
    for record in group:
        _signals, chain = tracker.signals(record)
        if record.label_redteam:
            continue
        bucket["benign"] += 1  # type: ignore[operator]
        if not chain:
            continue
        reached = tracker.chains._reached_ever.get(record.src_user_id, set())
        flags = {
            "A": True,
            "B": bool(record.success),
            "C": bool(record.success) and record.dst_host_id not in reached,
        }
        for v, hit in flags.items():
            if hit:
                bucket[v] += 1  # type: ignore[operator]
                bucket["u" + v].add(record.src_user_id)  # type: ignore[attr-defined]
    tracker.observe_group(group)
print(f"scored in {time.time() - t0:.0f}s", flush=True)
rows = []
for hour, b in sorted(hours.items()):
    benign = int(b["benign"])  # type: ignore[arg-type]
    row = {"hour": hour, "benign": benign}
    for v in "ABC":
        row[v] = int(b[v])  # type: ignore[arg-type]
        row[v + "_per_10k"] = round(int(b[v]) / benign * 1e4, 2) if benign else 0.0  # type: ignore[arg-type]
        row[v + "_accounts"] = len(b["u" + v])  # type: ignore[arg-type]
    rows.append(row)
    print(
        f"hour {hour:3d} benign {benign:8,}"
        f"  A {row['A']:6,} ({row['A_per_10k']:7.2f}/10k, {row['A_accounts']:4d} acct)"
        f"  B {row['B']:6,} ({row['B_per_10k']:7.2f}/10k)"
        f"  C {row['C']:6,} ({row['C_per_10k']:7.2f}/10k, {row['C_accounts']:4d} acct)"
    )
total_benign = sum(r["benign"] for r in rows)
summary = {v: round(sum(r[v] for r in rows) / total_benign * 1e4, 2) for v in "ABC"}
print("whole day per 10k:", summary)
out.write_text(
    json.dumps(
        {"data": str(data), "rule": DEFAULT_CHAIN_RULE.name, "hours": rows, "day_per_10k": summary},
        indent=1,
    )
)
