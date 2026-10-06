"""Evaluate GraphSentinel on the OTRF Security-Datasets lateral-movement recordings.

A second, independent, public dataset: real Windows Security telemetry from a
small lab domain (``theshire.local``), each recording one adversary moving
laterally with a known tool (Empire, Covenant, PurpleSharp, ...). Everything
here goes through the product's own code: the format is sniffed exactly as
``--format auto`` does, events are read by the Windows adapter, and every event
is scored by the served API (``/api/v1/live/events``) -- the same path a new
customer's logs take.

Ground truth is ``data/raw/otrf/ground_truth.json``: one reviewable label per
recording, each justified by a quote from OTRF's own metadata (the attacker's
console transcript, ``simulation.adversary_view``). An event is an attack event
when it authenticates from the attacker's workstation into the host the
attacker's command targets (and as the named account, where one is named).

Recordings are read straight from their zips, in memory. Some contain logged
attacker PowerShell (Empire stagers in script-block logs), which the local
antivirus rightly blocks when unzipped to disk; reading from the archive needs
no change to any security setting.

Usage::

    python scripts/otrf_evaluate.py --data data/raw/otrf --api http://127.0.0.1:8010 \\
        --out artifacts/otrf
"""

from __future__ import annotations

import argparse
import io
import ipaddress
import json
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graphsentinel.sources import ParseStats, SourceEvent, adapter_for, canonical_host
from graphsentinel.sources.detect import sniff


# --------------------------------------------------------------------------- ground truth
@dataclass
class Truth:
    dataset: str
    label: str
    evidence: str
    accounts: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    targets: set[str] = field(default_factory=set)

    @property
    def usable(self) -> bool:
        return self.label != "excluded" and bool(self.targets)


def short(name: str) -> str:
    """One spelling per host: canonical, then FQDN -> NetBIOS (IPs untouched)."""
    canonical = canonical_host(name)
    if not canonical:
        return ""
    try:
        ipaddress.ip_address(canonical)
        return canonical
    except ValueError:
        return canonical.split(".")[0].upper()


def load_truth(path: Path) -> dict[str, Truth]:
    """Reviewable labels, each justified by a quote from OTRF's own metadata."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    truths: dict[str, Truth] = {}
    for name, entry in doc["recordings"].items():
        truths[name] = Truth(
            dataset=name,
            label=entry.get("label", "excluded"),
            evidence=entry.get("evidence", ""),
            accounts={a.lower() for a in entry.get("accounts", [])},
            sources={short(s) for s in entry.get("sources", [])},
            targets={short(t) for t in entry.get("targets", [])},
        )
    return truths


# --------------------------------------------------------------------------- events
def read_recording(zip_path: Path) -> tuple[str, list[SourceEvent], ParseStats]:
    with zipfile.ZipFile(zip_path) as archive:
        lines: list[str] = []
        for member in archive.namelist():
            if member.endswith(".json"):
                with archive.open(member) as handle:
                    lines.extend(io.TextIOWrapper(handle, encoding="utf-8", errors="replace"))
    detection = sniff(lines)
    stats = ParseStats()
    adapter = adapter_for(detection.format, column_map=detection.column_map)
    events = list(adapter.parse(lines, stats))
    return detection.format, [e for e in events if not e.is_self_loop], stats


def is_attack(event: SourceEvent, truth: Truth) -> bool:
    if not truth.usable:
        return False
    account = event.user.split("@")[0].lower()
    return (
        (not truth.accounts or account in truth.accounts)
        and short(event.destination_host) in truth.targets
        and (not truth.sources or short(event.source_host) in truth.sources)
    )


# --------------------------------------------------------------------------- scoring
def post(api: str, events: list[dict[str, Any]], batch_id: str) -> list[dict[str, Any]]:
    body = json.dumps({"batch_id": batch_id, "events": events}).encode()
    request = urllib.request.Request(
        api.rstrip("/") + "/api/v1/live/events",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        return json.loads(response.read())["results"]


def last_timestamp(api: str) -> int:
    with urllib.request.urlopen(api.rstrip("/") + "/api/v1/live/status", timeout=60) as r:
        return int(json.loads(r.read()).get("last_timestamp") or 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", type=Path, default=Path("data/raw/otrf"))
    parser.add_argument("--api", default="http://127.0.0.1:8010")
    parser.add_argument("--out", type=Path, default=Path("artifacts/otrf"))
    parser.add_argument("--threshold", type=float, default=0.3292)
    args = parser.parse_args()

    zips = sorted((args.data / "lateral_movement").glob("*.zip"))
    truths = load_truth(args.data / "ground_truth.json")
    recordings = []
    for zip_path in zips:
        fmt, events, stats = read_recording(zip_path)
        truth = truths.get(zip_path.stem) or Truth(
            zip_path.stem, "excluded", "not in ground_truth.json"
        )
        recordings.append((zip_path.stem, fmt, events, stats, truth))

    # One lab, observed over many days: replay the recordings in time order.
    recordings.sort(key=lambda r: min((e.timestamp for e in r[2]), default=0))
    results = []
    events_out: list[dict[str, Any]] = []
    for name, fmt, events, stats, truth in recordings:
        record: dict[str, Any] = {
            "dataset": name,
            "format": fmt,
            "lines": stats.lines,
            "auth_edges": len(events),
            "label": truth.label,
            "evidence": truth.evidence,
            "attacker": {
                "accounts": sorted(truth.accounts),
                "sources": sorted(truth.sources),
                "targets": sorted(truth.targets),
            },
        }
        if not events:
            record["outcome"] = "no authentication edges in the recording"
            results.append(record)
            continue
        ordered = sorted(events, key=lambda e: e.timestamp)
        # The gateway refuses a batch that does not advance its clock; shift the
        # recording forward as a whole (relative timing is what the detector
        # reasons about) and send one batch per distinct second.
        shift = max(0, last_timestamp(args.api) + 1 - ordered[0].timestamp)
        scored: list[tuple[SourceEvent, dict[str, Any]]] = []
        groups: dict[int, list[SourceEvent]] = {}
        for event in ordered:
            groups.setdefault(event.timestamp + shift, []).append(event)
        for second, group in sorted(groups.items()):
            payload = []
            for e in group:
                item = e.to_payload()
                item["timestamp"] = second
                payload.append(item)
            try:
                answers = post(args.api, payload, f"otrf-{name}-{second}")
            except urllib.error.HTTPError as error:
                record.setdefault("refused", 0)
                record["refused"] += len(group)
                if error.code != 409:
                    raise
                continue
            scored.extend(zip(group, answers, strict=True))
        for e, a in scored:
            events_out.append({
                "dataset": name, "label": truth.label, "attack": is_attack(e, truth),
                "user": e.user, "source": e.source_host, "destination": e.destination_host,
                "success": e.success, "risk": a["risk"], "alerted": bool(a.get("alerted")),
            })
        attack = [(e, a) for e, a in scored if is_attack(e, truth)]
        benign = [(e, a) for e, a in scored if not is_attack(e, truth)]
        risks = sorted((a["risk"] for _, a in scored), reverse=True)
        best = max((a["risk"] for _, a in attack), default=None)
        record.update(
            {
                "scored": len(scored),
                "attack_events": len(attack),
                "attack_alerted": sum(1 for _, a in attack if a["risk"] >= args.threshold),
                "attack_best_risk": best,
                "attack_best_rank": (risks.index(best) + 1) if best is not None else None,
                "benign_alerted": sum(1 for _, a in benign if a["risk"] >= args.threshold),
                "benign_events": len(benign),
                "attack_examples": [
                    {
                        "user": e.user, "source": e.source_host, "destination": e.destination_host,
                        "success": e.success, "risk": round(a["risk"], 4),
                        "technique": (a.get("tactic") or {}).get("technique_id"),
                    }
                    for e, a in attack[:4]
                ],
            }
        )
        if not truth.usable:
            record["outcome"] = f"excluded: {truth.evidence}"
        elif not attack:
            record["outcome"] = "attacker's authentication not present in the recording"
        elif record["attack_alerted"]:
            record["outcome"] = "detected"
        else:
            record["outcome"] = "missed"
        results.append(record)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "otrf_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    (args.out / "otrf_events.json").write_text(json.dumps(events_out, indent=1), encoding="utf-8")
    print(f"{'dataset':<52} {'outcome':<46} best risk  rank  benign alerts")
    for r in results:
        best_rank = r.get("attack_best_rank")
        rank = f"{best_rank}/{r.get('scored')}" if best_rank else "-"
        risk = f"{r['attack_best_risk']:.3f}" if r.get("attack_best_risk") is not None else "  -  "
        print(f"{r['dataset'][:52]:<52} {r['outcome'][:46]:<46} {risk:>9}  {rank:>6}  "
              f"{r.get('benign_alerted', 0)}/{r.get('benign_events', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
