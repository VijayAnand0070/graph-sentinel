"""The chain rule's design space, priced on both sides.

For every candidate shape of the deterministic chain rule -- how many onward
hops by one account, inside what window, counting any hop or only hops to
destinations the account has never reached -- and for each policy on what a
detected chain may do (``alert_only``: raise to the alert floor; ``unattended``:
assert T1021 and raise to the execution gate), this measures:

* on the labelled corpus, the rule's false-positive cost: benign events
  flagged per 10,000, and any labelled attack it catches;
* on the prevention instrument (100 campaigns from ordinary workstations,
  warm state, the production composition), what the policy buys: campaigns
  detected, first alert in hops, hops prevented -- and what it costs: benign
  events acted on unattended and distinct users hit.

The TGN is scored once per stream and cached; the rule and the policy are the
only things that vary between runs, so the comparison changes one thing at a
time. Written as JSON and a table; Finding 25 reads the table.

    python scripts/chain_rule_study.py --out artifacts/prevention/chain_rule_study
"""

from __future__ import annotations

import argparse
import gzip
import json
import statistics
import sys
import time
from collections.abc import Iterable, Iterator, Sequence
from itertools import groupby
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import polars as pl  # noqa: E402
from measure_prevention import (  # noqa: E402
    DEFAULT_CHECKPOINT,
    DEFAULT_DATA,
    DEFAULT_ID_MAPS,
    DEFAULT_WARM_ROOT,
    VALIDATION_END_INDEX,
    build_campaigns,
    load_frame,
    warm_state,
)

from graphsentinel.detection.policy import (  # noqa: E402
    ALERT_ONLY,
    CORROBORATED,
    UNATTENDED,
    ChainRuleConfig,
    ChainRulePolicy,
)
from graphsentinel.features.causal import CausalFeatureEngine, FeatureRecord  # noqa: E402
from graphsentinel.ingestion.id_map import AuthIdMaps  # noqa: E402
from graphsentinel.models.serving import load_inference_session  # noqa: E402
from graphsentinel.onboarding.backfill import FEATURE_STATE_NAME, TGN_MEMORY_NAME  # noqa: E402
from graphsentinel.simulation.generator import generate_stream  # noqa: E402
from graphsentinel.simulation.prevention import (  # noqa: E402
    EntityNames,
    measure_prevention,
    session_scorer,
)
from graphsentinel.simulation.profile import SECONDS_PER_DAY, CorpusProfile  # noqa: E402

FIELDS = tuple(FeatureRecord.__dataclass_fields__)

#: The grid. Hop counts are total hops in the chain (prior hops + 1).
HOPS = (3, 4)
WINDOWS = (300, 600, 1_800, 3_600)
NOVELTY = (False, True)
POLICIES: tuple[ChainRulePolicy, ...] = (ALERT_ONLY, UNATTENDED, CORROBORATED)


def candidate_rules() -> list[ChainRuleConfig]:
    return [
        ChainRuleConfig(prior_hops=hops - 1, window_seconds=window, novel_only=novel)
        for hops in HOPS
        for window in WINDOWS
        for novel in NOVELTY
    ]


def records_from_frame(frame: pl.DataFrame) -> Iterator[FeatureRecord]:
    """Stream records: a full-rate day is millions of rows and must not be
    materialised as objects (7.3 M of them took the machine to its last
    half-gigabyte)."""
    columns = [name for name in FIELDS]
    for row in frame.select(columns).iter_rows(named=True):
        yield FeatureRecord(**row)


def corpus_cost(records: Iterable[FeatureRecord], rule: ChainRuleConfig) -> dict[str, object]:
    """Replay the rule alone over a labelled corpus: what it flags, and of what."""
    tracker = rule.tracker()
    benign = attacks = flagged_benign = flagged_attacks = 0
    users: set[int] = set()
    for _timestamp, grouped in groupby(records, key=lambda r: r.timestamp):
        group = list(grouped)
        for record in group:
            _signals, chain = tracker.signals(record)
            if record.label_redteam:
                attacks += 1
                flagged_attacks += chain
            else:
                benign += 1
                flagged_benign += chain
                if chain:
                    users.add(record.src_user_id)
        tracker.observe_group(group)
    return {
        "events": benign + attacks,
        "benign_flagged": flagged_benign,
        "benign_flagged_per_10k": round(1e4 * flagged_benign / max(1, benign), 3),
        "benign_users_flagged": len(users),
        "attacks": attacks,
        "attacks_flagged": flagged_attacks,
    }


class CachingScorer:
    """Score the stream through the session once; answer from the cache after."""

    def __init__(self, session_factory) -> None:  # type: ignore[no-untyped-def]
        self._session_factory = session_factory
        self._scores: dict[int, float] = {}
        self._live = None

    def __call__(self, group: Sequence[FeatureRecord]) -> Sequence[float]:
        if all(r.event_id in self._scores for r in group):
            return [self._scores[r.event_id] for r in group]
        if self._live is None:
            self._live = session_scorer(self._session_factory())
        probabilities = list(self._live(group))
        for record, probability in zip(group, probabilities, strict=True):
            self._scores[record.event_id] = float(probability)
        return probabilities


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--checkpoint", type=Path, default=DEFAULT_CHECKPOINT)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--id-maps", type=Path, default=DEFAULT_ID_MAPS)
    parser.add_argument("--warm-root", type=Path, default=DEFAULT_WARM_ROOT)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--days", type=float, default=3.0)
    parser.add_argument("--hops", type=int, default=8)
    parser.add_argument("--replicates", type=int, default=5)
    parser.add_argument("--seed", type=int, default=2024)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--warm-limit", type=int, default=VALIDATION_END_INDEX)
    parser.add_argument(
        "--extra-corpus",
        type=Path,
        default=None,
        help="a second labelled feature directory to price the rule on (e.g. the e2e window)",
    )
    parser.add_argument("--skip-corpus", action="store_true")
    parser.add_argument("--corpus-only", action="store_true", help="price the rules; no instrument")
    parser.add_argument("--policies", default=None, help="comma-separated policy names to run")
    parser.add_argument(
        "--rules",
        default=None,
        help="comma-separated rule names to restrict the grid, "
        "e.g. 3hops-1800s-novel,4hops-600s-any",
    )
    args = parser.parse_args(argv)

    def log(message: str) -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)

    args.out.mkdir(parents=True, exist_ok=True)
    rules = candidate_rules()
    if args.rules:
        wanted = {name.strip() for name in args.rules.split(",") if name.strip()}
        rules = [ChainRuleConfig.parse(name) for name in sorted(wanted)]
    results: dict[str, object] = {
        "checkpoint": str(args.checkpoint),
        "grid": {"hops": list(HOPS), "windows": list(WINDOWS), "novelty": list(NOVELTY)},
        "rules": [r.to_dict() for r in rules],
        "policies": [p.to_dict() for p in POLICIES],
        "corpus": {},
        "instrument": {},
    }

    # ---------------------------------------------------------------- corpus cost
    if not args.skip_corpus:
        corpora = {"lanl_545k" if args.data == DEFAULT_DATA else args.data.parent.name: args.data}
        if args.extra_corpus is not None:
            corpora[args.extra_corpus.name] = args.extra_corpus
        for name, path in corpora.items():
            log(f"loading corpus {name}")
            frame = load_frame(path)
            log(f"  {frame.height:,} events; pricing {len(rules)} rules")
            table: dict[str, object] = {}
            for rule in rules:
                started = time.perf_counter()
                table[rule.name] = corpus_cost(records_from_frame(frame), rule)
                log(f"  {rule.name:<20} {table[rule.name]}  ({time.perf_counter() - started:.0f}s)")
            results["corpus"][name] = table
            del frame
            (args.out / "chain_rule_study.json").write_text(
                json.dumps(results, indent=2), encoding="utf-8"
            )

    if args.corpus_only:
        (args.out / "chain_rule_study.md").write_text(render(results), encoding="utf-8")
        return 0

    # ---------------------------------------------------------------- instrument
    warm = warm_state(args.checkpoint, args.data, args.warm_root, limit=args.warm_limit, log=log)
    frame = load_frame(args.data)
    profile = CorpusProfile.measure(frame.head(args.warm_limit))
    start = profile.last_timestamp + 1
    window = int(args.days * SECONDS_PER_DAY)
    campaigns = build_campaigns(
        profile,
        hops=args.hops,
        replicates=args.replicates,
        seed=args.seed,
        start=start,
        window_seconds=window,
    )
    stream = generate_stream(
        profile,
        campaigns=campaigns,
        start_timestamp=start,
        end_timestamp=start + window,
        seed=args.seed,
    )
    log(f"stream: {len(stream.events):,} events ({stream.attack_count} attack)")
    engine = CausalFeatureEngine()
    with gzip.open(warm / FEATURE_STATE_NAME, "rt", encoding="utf-8") as handle:
        engine.restore(json.load(handle))
    records = list(engine.transform(stream.events))
    names = EntityNames.from_id_maps(AuthIdMaps.load(args.id_maps))

    def fresh_session():  # type: ignore[no-untyped-def]
        session = load_inference_session(args.checkpoint, device=args.device)
        session.load_memory(warm / TGN_MEMORY_NAME)
        return session

    scorer = CachingScorer(fresh_session)
    instrument: dict[str, object] = {}
    policies = tuple(
        p for p in POLICIES
        if args.policies is None or p.name in {n.strip() for n in args.policies.split(",")}
    )
    for rule in rules:
        for policy in policies:
            key = f"{rule.name}|{policy.name}"
            started = time.perf_counter()
            report = measure_prevention(
                records,
                stream.truth,
                stream.campaigns,
                scorer=scorer,
                names=names,
                operating_point="noisy_or",
                chain_rule=rule,
                policy=policy,
            )
            summary = report.to_dict()
            chain_campaigns = [c for c in report.campaigns if c.family == "chain"]
            instrument[key] = {
                "rule": rule.name,
                "policy": policy.name,
                "campaigns_detected": sum(c.detected for c in report.campaigns),
                "chain_campaigns_detected": sum(c.detected for c in chain_campaigns),
                "median_first_alert_hop": (
                    statistics.median(report.latency_hops()) if report.latency_hops() else None
                ),
                "prevented_campaign": round(report.prevented_fraction("campaign"), 4),
                "prevented_account": round(report.prevented_fraction("account"), 4),
                "prevented_campaign_chain": round(
                    report.prevented_fraction("campaign", chain_campaigns), 4
                ),
                "campaigns_auto_actioned": sum(
                    any(h.auto_actioned for h in c.hops) for c in report.campaigns
                ),
                "benign_alerted_per_10k": round(report.benign_alert_rate_per_10k, 2),
                "benign_auto_per_10k": round(report.benign_auto_action_rate_per_10k, 2),
                "benign_users_hit": report.benign_users_hit,
                "by_interval": summary["by_interval"],
                "loop": summary["loop"],
            }
            log(
                f"{key:<36} detected {instrument[key]['campaigns_detected']:>3}  "
                f"chain {instrument[key]['chain_campaigns_detected']:>2}/50  "
                f"hop {instrument[key]['median_first_alert_hop']}  "
                f"prevented {instrument[key]['prevented_campaign']:.1%}  "
                f"auto/10k {instrument[key]['benign_auto_per_10k']}  "
                f"users {instrument[key]['benign_users_hit']}  "
                f"({time.perf_counter() - started:.0f}s)"
            )
            results["instrument"] = instrument
            (args.out / "chain_rule_study.json").write_text(
                json.dumps(results, indent=2), encoding="utf-8"
            )

    (args.out / "chain_rule_study.md").write_text(render(results), encoding="utf-8")
    log(f"wrote {args.out / 'chain_rule_study.md'}")
    return 0


def render(results: dict[str, object]) -> str:
    corpus = results["corpus"]  # type: ignore[index]
    instrument = results["instrument"]  # type: ignore[index]
    lines = [
        "# Chain rule design space",
        "",
        "Corpus cost: benign events the rule flags per 10,000 (and labelled attacks it catches).",
        "Instrument: 100 campaigns from ordinary workstations; what each policy buys and costs.",
        "",
        "| Rule | "
        + " | ".join(f"{name} benign/10k (attacks)" for name in corpus)  # type: ignore[attr-defined]
        + " | Policy | Detected | Chains | First hop | Prevented (campaign) | Chains prevented"
        + " | Auto-actioned campaigns | Benign auto/10k | Users hit | Benign alerts/10k |",
        "|---|" + "---|" * len(corpus) + "---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",  # type: ignore[arg-type]
    ]
    if not instrument:
        lines += [
            "",
            "(instrument not run)",
            "",
            "| Rule | " + " | ".join(corpus) + " |",
            "|---|" + "---|" * len(corpus),
        ]  # type: ignore[arg-type]
        for rule in results["rules"]:  # type: ignore[index]
            name = rule["name"]  # type: ignore[index]
            lines.append(
                "| "
                + name
                + " | "
                + " | ".join(
                    f"{corpus[c][name]['benign_flagged_per_10k']} "  # type: ignore[index]
                    f"({corpus[c][name]['attacks_flagged']})"  # type: ignore[index]
                    for c in corpus  # type: ignore[attr-defined]
                )
                + " |"
            )
        return "\n".join(lines) + "\n"
    for _key, row in instrument.items():  # type: ignore[attr-defined]
        rule = row["rule"]
        costs = " | ".join(
            f"{corpus[name][rule]['benign_flagged_per_10k']} "  # type: ignore[index]
            f"({corpus[name][rule]['attacks_flagged']})"  # type: ignore[index]
            for name in corpus  # type: ignore[attr-defined]
        )
        lines.append(
            f"| {rule} | {costs} | {row['policy']} | {row['campaigns_detected']} | "
            f"{row['chain_campaigns_detected']}/50 | {row['median_first_alert_hop']} | "
            f"{row['prevented_campaign']:.1%} | {row['prevented_campaign_chain']:.1%} | "
            f"{row['campaigns_auto_actioned']} | {row['benign_auto_per_10k']} | "
            f"{row['benign_users_hit']} | {row['benign_alerted_per_10k']} |"
        )
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
