"""A small LANL-format raw corpus with planted campaigns, for pipeline checks.

The end-to-end pipeline (``scripts/e2e_pipeline.py``) runs the product's own
entry points from raw text to a served, responding API. Running it on the real
corpus takes an hour; running it on this one takes minutes, and it is the same
code path from the first byte: gzip text in LANL's nine-column layout, a
red-team file whose keys match auth rows exactly, chronological timestamps,
``?`` for missing values, local logons the ingest must drop, failures, machine
accounts, and campaigns planted in each chronological partition so the split
has positives everywhere it needs them.

It is a *pipeline* fixture, not a benchmark: the campaigns are deliberately
easy (fast chains to hosts the account has never touched) so that a two-epoch
model trained on twenty thousand events can be expected to find some of them.
Nothing measured on it says anything about detection quality on real traffic.
"""

from __future__ import annotations

import gzip
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SECONDS_PER_DAY = 86_400
DOMAIN = "DOM1"


@dataclass(frozen=True, slots=True)
class RawCorpusSpec:
    seed: int = 7
    days: int = 3
    users: int = 80
    hosts: int = 60
    events_per_day: int = 8_000
    #: Share of benign events that are local logons (source host == destination
    #: host). LANL is 54%; the ingest must drop them, so the fixture has them.
    self_loop_share: float = 0.35
    failure_share: float = 0.04
    missing_share: float = 0.10
    #: Campaigns planted in each of the three chronological partitions.
    campaigns_per_partition: int = 2
    hops_per_campaign: int = 6
    #: Seconds between hops, drawn uniformly from this range.
    hop_interval: tuple[int, int] = (20, 90)


@dataclass(frozen=True, slots=True)
class RawCorpusSummary:
    auth_path: Path
    redteam_path: Path
    rows: int
    self_loops: int
    redteam_rows: int
    first_timestamp: int
    last_timestamp: int
    campaigns: tuple[tuple[str, int, int], ...]  # (user, first hop time, last hop time)

    def to_dict(self) -> dict[str, object]:
        return {
            "auth_path": str(self.auth_path),
            "redteam_path": str(self.redteam_path),
            "rows": self.rows,
            "self_loops": self.self_loops,
            "redteam_rows": self.redteam_rows,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "campaigns": [list(c) for c in self.campaigns],
        }


#: Where inside each chronological partition (train 70%, validation 15%,
#: test 15%, by event index) the campaigns are planted. Kept away from the
#: boundaries so a campaign never straddles two partitions.
PARTITION_WINDOWS: tuple[tuple[float, float], ...] = ((0.20, 0.55), (0.72, 0.82), (0.88, 0.96))

AUTH_TYPES = ("Kerberos", "Kerberos", "Negotiate", "NTLM")
LOGON_TYPES = ("Network", "Network", "Batch", "Service", "Interactive")


def _hour_weight(hour: int) -> float:
    """Working hours are busier; the rate is what the features key on."""
    if 8 <= hour < 18:
        return 1.0
    if 6 <= hour < 8 or 18 <= hour < 21:
        return 0.4
    return 0.1


def _draw_timestamps(rng: random.Random, days: int, per_day: int) -> list[int]:
    stamps: list[int] = []
    weights = [_hour_weight(h) for h in range(24)]
    for day in range(days):
        hours = rng.choices(range(24), weights=weights, k=per_day)
        for hour in hours:
            stamps.append(day * SECONDS_PER_DAY + hour * 3_600 + rng.randrange(3_600))
    stamps.sort()
    # LANL starts at 1, never 0.
    return [max(1, s) for s in stamps]


def write_synthetic_lanl_corpus(
    raw_dir: Path, spec: RawCorpusSpec | None = None
) -> RawCorpusSummary:
    """Write ``auth.txt.gz`` and ``redteam.txt.gz`` under ``raw_dir``."""

    spec = spec or RawCorpusSpec()
    if spec.users < 8 or spec.hosts < 12:
        raise ValueError("the corpus needs at least 8 users and 12 hosts")
    if spec.days < 1 or spec.events_per_day < 100:
        raise ValueError("the corpus needs at least one day of at least 100 events")
    rng = random.Random(spec.seed)
    raw_dir.mkdir(parents=True, exist_ok=True)

    hosts = [f"C{100 + i}" for i in range(spec.hosts)]
    users = [f"U{1000 + i}@{DOMAIN}" for i in range(spec.users)]
    home = {user: rng.choice(hosts) for user in users}
    usual: dict[str, list[str]] = {}
    for user in users:
        others = [h for h in hosts if h != home[user]]
        usual[user] = rng.sample(others, k=rng.randint(2, 4))

    rows: list[tuple[int, str, str, str, str, str, str, str, str]] = []
    self_loops = 0
    for stamp in _draw_timestamps(rng, spec.days, spec.events_per_day):
        user = rng.choice(users)
        src = home[user]
        if rng.random() < spec.self_loop_share:
            dst = src
            actor = f"{src}$@{DOMAIN}" if rng.random() < 0.5 else user
            self_loops += 1
        else:
            dst = rng.choice(usual[user])
            actor = user
        auth_type = "?" if rng.random() < spec.missing_share else rng.choice(AUTH_TYPES)
        logon_type = "?" if rng.random() < spec.missing_share else rng.choice(LOGON_TYPES)
        orientation = "LogOff" if rng.random() < 0.15 else "LogOn"
        success = "Fail" if rng.random() < spec.failure_share else "Success"
        rows.append((stamp, actor, actor, src, dst, auth_type, logon_type, orientation, success))

    # The chronological split is by event index, not by time, and traffic is
    # not uniform in time; so campaigns are placed at index quantiles of the
    # benign stream, which is what the split will see.
    benign_stamps = [row[0] for row in rows]
    redteam: list[tuple[int, str, str, str]] = []
    campaigns: list[tuple[str, int, int]] = []
    for low, high in PARTITION_WINDOWS:
        for _ in range(spec.campaigns_per_partition):
            user = rng.choice(users)
            never = [h for h in hosts if h != home[user] and h not in usual[user]]
            path = rng.sample(never, k=min(spec.hops_per_campaign, len(never)))
            start = benign_stamps[int(rng.uniform(low, high) * (len(benign_stamps) - 1))]
            stamp = start
            src = home[user]
            for dst in path:
                rows.append((stamp, user, user, src, dst, "NTLM", "Network", "LogOn", "Success"))
                redteam.append((stamp, user, src, dst))
                src = dst
                stamp += rng.randint(*spec.hop_interval)
            campaigns.append((user, start, stamp))

    rows.sort(key=lambda r: r[0])
    redteam.sort(key=lambda r: r[0])

    auth_path = raw_dir / "auth.txt.gz"
    redteam_path = raw_dir / "redteam.txt.gz"
    with gzip.open(auth_path, "wt", encoding="utf-8", newline="") as stream:
        for row in rows:
            stream.write(",".join(str(v) for v in row) + "\n")
    with gzip.open(redteam_path, "wt", encoding="utf-8", newline="") as stream:
        for labelled in redteam:
            stream.write(",".join(str(v) for v in labelled) + "\n")

    return RawCorpusSummary(
        auth_path=auth_path,
        redteam_path=redteam_path,
        rows=len(rows),
        self_loops=self_loops,
        redteam_rows=len(redteam),
        first_timestamp=rows[0][0],
        last_timestamp=rows[-1][0],
        campaigns=tuple(campaigns),
    )


# --------------------------------------------------------------------------
# The same corpus in other formats, so the pipeline can be checked end to end
# through every source adapter. Each writer takes the LANL rows produced above
# and renders them the way that log would have recorded the same movement;
# the labels are rewritten to the entity names the adapter will produce.
# --------------------------------------------------------------------------

LanlRow = tuple[int, str, str, str, str, str, str, str, str]
EPOCH_BASE = 1_772_400_000  # 2026-03-01T20:00:00Z; LANL's second 1 lands just after it

_LOGON_CODES = {"Network": 3, "Batch": 4, "Service": 5, "Interactive": 2}


def _iso(stamp: int) -> str:
    from datetime import UTC, datetime

    moment = datetime.fromtimestamp(EPOCH_BASE + stamp, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000000+00:00")


def _address(host: str) -> str:
    """A stable private IPv4 for a synthetic host name, for sensors that see addresses."""
    number = int("".join(ch for ch in host if ch.isdigit()) or "0")
    return f"10.{(number >> 16) & 255}.{(number >> 8) & 255}.{number & 255}"


def _read_lanl(raw_dir: Path) -> tuple[list[LanlRow], list[tuple[int, str, str, str]]]:
    rows: list[LanlRow] = []
    with gzip.open(raw_dir / "auth.txt.gz", "rt", encoding="utf-8") as stream:
        for line in stream:
            p = line.rstrip("\n").split(",")
            rows.append((int(p[0]), p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]))
    labels: list[tuple[int, str, str, str]] = []
    with gzip.open(raw_dir / "redteam.txt.gz", "rt", encoding="utf-8") as stream:
        for line in stream:
            p = line.rstrip("\n").split(",")
            labels.append((int(p[0]), p[1], p[2], p[3]))
    return rows, labels


def _write_labels(path: Path, labels: list[tuple[int, str, str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        stream.write("time,user,src_host,dst_host\n")
        for stamp, user, src, dst in labels:
            stream.write(f"{stamp},{user},{src},{dst}\n")


def write_corpus_as(raw_dir: Path, format_name: str, out_dir: Path) -> dict[str, Path]:
    """Render ``raw_dir``'s LANL corpus as ``format_name``; return the files.

    The labels are rewritten to the names the adapter will produce:
    ``U1000@DOM1`` and ``C123`` survive every adapter's canonicalisation,
    except that sshd records the client as an address and the account
    without a realm.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    rows, labels = _read_lanl(raw_dir)
    written: dict[str, Path] = {}

    def epoch(stamp: int) -> int:
        return EPOCH_BASE + stamp

    rendered: list[tuple[int, str, str, str]]
    if format_name == "ssh-auth":
        log = out_dir / "auth.log"
        with log.open("w", encoding="utf-8", newline="") as stream:
            for stamp, user, _dst_user, src, dst, _auth, _logon, _orient, success in rows:
                verb = "Accepted publickey" if success == "Success" else "Failed password"
                local = user.split("@")[0]
                stream.write(
                    f"{_iso(stamp)} {dst.lower()} sshd[{1000 + stamp % 9000}]: {verb} for "
                    f"{local} from {_address(src)} port {20000 + stamp % 40000} ssh2\n"
                )
        rendered = [(epoch(t), u.split("@")[0], _address(s), d.upper()) for t, u, s, d in labels]
        written["log"] = log
    elif format_name == "windows-json":
        log = out_dir / "security.jsonl"
        with log.open("w", encoding="utf-8", newline="") as stream:
            for stamp, user, _dst_user, src, dst, auth, logon, _orient, success in rows:
                local, _, realm = user.partition("@")
                record: dict[str, object] = {
                    "EventID": 4624 if success == "Success" else 4625,
                    "@timestamp": _iso(stamp),
                    "Hostname": f"{dst}.corp.example",
                    "TargetUserName": local,
                    "TargetDomainName": realm or "DOM1",
                    "WorkstationName": src,
                    "IpAddress": _address(src),
                    "LogonType": _LOGON_CODES.get(logon, 3),
                    "AuthenticationPackageName": auth if auth != "?" else "NTLM",
                }
                stream.write(json.dumps(record) + "\n")
        rendered = [(epoch(t), u, s, d) for t, u, s, d in labels]
        written["log"] = log
    elif format_name == "zeek":
        log = out_dir / "ntlm.log"
        with log.open("w", encoding="utf-8", newline="") as stream:
            for stamp, user, _dst_user, src, dst, _auth, _logon, _orient, success in rows:
                local, _, realm = user.partition("@")
                record = {
                    "_path": "ntlm",
                    "ts": float(epoch(stamp)),
                    "id.orig_h": _address(src),
                    "id.resp_h": _address(dst),
                    "username": local,
                    "hostname": src,
                    "domainname": realm or "DOM1",
                    "server_nb_computer_name": dst,
                    "success": success == "Success",
                }
                stream.write(json.dumps(record) + "\n")
        rendered = [(epoch(t), u, s, d) for t, u, s, d in labels]
        written["log"] = log
    elif format_name == "tabular":
        log = out_dir / "auth.csv"
        with log.open("w", encoding="utf-8", newline="") as stream:
            stream.write("event_time,account,client,server,result,protocol\n")
            for stamp, user, _dst_user, src, dst, auth, _logon, _orient, success in rows:
                result = "SUCCESS" if success == "Success" else "FAILURE"
                protocol = auth if auth != "?" else "NTLM"
                stream.write(f"{_iso(stamp)},{user},{src},{dst},{result},{protocol}\n")
        rendered = [(epoch(t), u, s, d) for t, u, s, d in labels]
        written["log"] = log
    else:
        raise ValueError(f"no synthetic writer for format {format_name!r}")

    labels_path = out_dir / "labels.csv"
    _write_labels(labels_path, rendered)
    written["labels"] = labels_path
    return written


#: The column map the tabular writer's output needs.
TABULAR_MAP = (
    "timestamp=event_time,user=account,source_host=client,destination_host=server,"
    "success=result:SUCCESS,auth_type=protocol"
)


__all__: Sequence[str] = (
    "PARTITION_WINDOWS",
    "TABULAR_MAP",
    "RawCorpusSpec",
    "RawCorpusSummary",
    "write_corpus_as",
    "write_synthetic_lanl_corpus",
)
