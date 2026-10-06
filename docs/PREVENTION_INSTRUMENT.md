# The prevention instrument

How GraphSentinel measures what its response would have *stopped*, and why the
labelled corpus cannot answer that question on its own.

## The question the corpus cannot answer

Every number in `EVALUATION_REPORT.md` is a ranking number: given an attack
event, how far up the queue does it sit. That is the right measurement for an
alert queue and the wrong one for a response system. Prevention is a claim
about hops that *did not happen* because the system acted — and nothing in a
recorded corpus is counterfactual. The red team's fifth move happened whether
or not the fourth was caught.

So prevention has to be measured on campaigns whose full length is known in
advance, against a detection stack composed exactly as the product composes it,
with the response layer's real gating. That is what `src/graphsentinel/simulation`
does.

## What is generated, and from what

| Component | Source | Why it matters |
|---|---|---|
| Benign traffic | Resampled from each user's *own* benign history in the warm-up prefix; Poisson at the measured rate; thinned by the measured hour-of-day profile | Finding 4: a generator encoding an intuition validates the detector against the intuition |
| Attacker host | An ordinary busy workstation (out-degree between the 50th and 95th percentile) with benign history before, during and after | Finding 14: the corpus attacker is attack-only, so identity alone separates the classes there |
| Compromised accounts | Accounts genuinely used at that host (fan-out) or one of them (chain) | A harvested credential store contains what was on the machine |
| Destinations | Weighted by real in-degree, novel for the account used — across the whole stream, not just the profiled history, since the same widely-used credential is compromised many times over three days and the chain rule's novelty is cumulative (Finding 27) | The attacker goes where the value is; the credential's owner has never been there |
| Attack mechanics | The account's own auth type, logon type and orientation; success = 1 | A valid credential has no reason to look suspicious in any other way — the movement is the anomaly |
| State | Feature engine and TGN memory restored from a backfill through the validation boundary | Finding 9: cold state costs 46% of PR-AUC; measuring cold measures the wrong system |

Two campaign families, both measured from the corpus rather than assumed:
**fan-out** (one host, many destinations, rotating accounts — the topology the
LANL red team exhibits) and **chain** (each hop's source is the previous hop's
destination, one account — the pivot the T1021 chain rule exists to catch).

The grid: 2 families × 10 inter-hop intervals (15 s to 1 h, straddling the
300 s chain window and the 1,800 s pivot window) × 5 replicates, 8 hops each,
laid over a 3-day synthetic continuation with a 6-hour lead-in. 100 campaigns,
800 attack events, ~102,000 benign.

## What is scored

The production composition, step for step from `api/live.py`: explicit signals
(novelty, burst, pivot) and the same-account chain tracker; tactic attribution
on raw category names; TGN probability through `InferenceSession` with restored
memory; fusion under the shipped operating point; the chain-rule floor; the
alert threshold; and `plan_for()` to obtain the response plan. The TGN is
injected as a scorer, so a stub can drive the accounting tests and a different
checkpoint can be measured without touching anything else.

## What is reported

| Metric | Definition | Why this unit |
|---|---|---|
| Detection latency in hops | Index of the first alerting hop; 0 is the first move | The unit that describes damage: how far the attacker got |
| Hops prevented, *campaign* semantics | Hops after the first unattended action | Right for a chain under one account, or an attacker holding only session material |
| Hops prevented, *account* semantics | Hops after an action, for that account only | Right for a fan-out rotating credentials: killing one session leaves the others |
| Benign cost | Benign events alerted / auto-actioned per 10k; distinct users hit | The price of the policy in the same window |
| Evasion curve | Detection rate by inter-hop interval | Where the attacker has to slow to, to walk through |

"Prevented" always means *prevented by session invalidation*, because
`force_reauth` is the only disruptive action the response layer runs
unattended (Finding 15). Everything requiring approval is counted as
recommended, not done. Both prevention semantics are reported because the
honest answer depends on what the attacker holds, and choosing the flattering
one would be a claim, not a measurement.

## Assumptions, stated

1. Session invalidation stops the attacker's *next* hop under the stated
   semantics. On-premises Kerberos tickets already issued remain valid
   (`response/connectors.py` records this on every such command), so this is
   optimistic for an attacker holding tickets rather than a password.
2. Benign traffic is stationary over the 3-day window. Finding 18 shows the
   false-positive floor moves ~4× between quiet and busy days; the window
   starts on the day after the validation period and inherits that day's
   character.
3. Campaigns are independent. They are placed on distinct attacker hosts at
   random times and may overlap; nothing in the stack keys on cross-campaign
   structure, so overlap is neutral.
4. Eight hops is the campaign length. Latency is measured in hops, so a longer
   campaign changes "prevented fraction" but not "first alert hop".

## Running it

```bash
python scripts/measure_prevention.py --out artifacts/prevention/production   # the shipped rule and policy
python scripts/chain_rule_study.py --out artifacts/prevention/chain_rule_study \
    --extra-corpus artifacts/e2e/lanl_900k/features   # every rule shape x policy, priced on both sides (Finding 25)
python scripts/measure_prevention.py --checkpoint path/to/variant.pt --out ...   # any other checkpoint
python scripts/validate_techniques.py --out artifacts/prevention/techniques   # per-technique recall/precision
```

The warm state is cached per checkpoint under `artifacts/prevention/warm`. The
first run replays 427,623 events (~20 minutes on CPU); later runs reuse it.

Results are recorded in `DETECTION_RESEARCH_FINDINGS.md`, Findings 21 and 22.
