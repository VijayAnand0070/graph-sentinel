# Detection Research Findings

Measured findings from building the tactic-classification layer. Every number
comes from a replay over the full labelled corpus (`543,615` events, `649`
red-team) or from the deployed API. Harness errors I made along the way are
recorded too, because two of them produced convincing wrong answers.

> **Finding 14 is the one to read first.** It establishes that 99.8% of this
> project's headline test PR-AUC is attributable to a single attacker host that
> is attack-only in training. Findings 1-13 remain correct as stated — they are
> comparisons between detectors on a common corpus, and that comparison is still
> meaningful — but every absolute performance number in this repository sits
> behind that caveat.

---

## Finding 1 — The fusion operator gave the TGN an absolute veto

**Severity: critical. Fixed.**

The risk score fused four channels by weighted average, with weights
constrained to sum to 1:

```
tgn 0.55 | novelty 0.20 | burst 0.10 | pivot 0.10 | corroboration 0.05
```

The three behavioural channels plus corroboration sum to **0.45**. The
calibrated decision threshold is **0.4543**.

> An event with *perfect* novelty, burst, pivot and corroboration scores 0.45
> and does not alert. The behavioural channels could never raise an alert at
> any evidence level. The TGN held an absolute veto over every rule in the
> system.

This is not a tuning accident — it is what a weighted average does. Averaging
is correct for combining estimates *of the same quantity* and wrong for
combining *independent evidence of different kinds*. A model that has never
seen a pattern and a rule that recognises it exactly should not be averaged.

Observable consequence: replaying a labelled five-hop chain through the
deployed scorer returned `0.0015, 0.1202, 0.1354, 0.1479, 0.1576` against the
0.4543 threshold — entirely missed, with `pivot` firing at 1.0 on four hops.

**Fix.** Added a noisy-OR gate alongside the linear operator:

```
P = 1 - prod_i (1 - r_i * s_i)
```

Reliabilities are independent probabilities with no sum-to-one constraint,
which is exactly the property that removes the veto. On the chain hop above:
linear `0.1188` → noisy-OR `0.5748`, dominant channel `pivot`.

Both operators are retained. Noisy-OR changes the score distribution, so the
threshold must be re-derived on validation at the same FP budget before it can
become the default. `FusionConfig.behavioural_ceiling()` now exposes the
quantity that was silently wrong, so a deployment can assert it clears its own
threshold.

---

## Finding 2 — The pivot signal destroyed itself as it ran

**Severity: high. Fixed.**

`pivot` asks whether an event's source host was itself recently reached — the
defining shape of lateral movement. It was implemented against an **unbounded
set of every host ever reached**.

In a finite estate every host eventually becomes some other host's
destination, so the set converges on "all hosts" and the signal converges on
the constant `1.0`:

| Events processed | Pivot fires on | Hosts accumulated |
|---|---|---|
| 1,000 | 50.0% | 152 |
| 10,000 | 57.0% | 946 |
| 50,000 | 64.4% | 3,098 |
| 100,000 | 70.1% | 4,784 |
| 300,000 | 79.9% | 8,678 |
| 543,615 | **85.7%** | 10,548 |

The signal carried progressively less information the longer the system ran.
That is the worst failure mode available: it degrades silently and looks like
it is working.

**Fix.** `RecentDestinations` — a time-windowed set with amortised O(1)
eviction, windowed to 1,800s to match `PathRankerConfig.forward_window_seconds`
so the pivot signal and the path ranker agree on what "recently" means.

---

## Finding 3 — The lateral-movement signature was worse than random

**Severity: critical. Fixed.**

First measurement of T1021 against the 649 labels:

```
attacks classified T1021 : 510/649  (78.6%)
benign classified T1021  : 465,675/542,966  (85.8%)
lift over base rate      : 0.9x
```

A recall of 78.6% looks respectable in isolation and is meaningless next to a
benign firing rate of 85.8%. **Lift below 1.0 means the rule was worse than
guessing.** Recall without a base rate beside it is not a result.

### Finding 3a — Pivot has zero recall on this corpus

Windowing pivot improved selectivity (85.8% → 48.3% benign) but the deeper
problem surfaced on measuring each discriminator alone:

| Discriminator | Attack recall | Benign firing | Lift |
|---|---|---|---|
| pivot (1800s window) | **0.0%** | 47.05% | 0.0× |
| `is_new_pair` | 56.7% | 28.81% | 2.0× |
| `dst_historical_degree <= 3` | 54.7% | 10.02% | 5.5× |
| **`src_host_unique_dst_1h >= 5`** | **76.9%** | **2.37%** | **32.5×** |
| `destination_novelty > 0.7` | 6.6% | 1.93% | 3.4× |
| remote logon type | 100.0% | 83.06% | 1.2× |

Pivot fires on roughly half of benign traffic and on **none** of the attacks.
The attack topology explains it:

- the 649 red-team events originate from just **4 distinct source hosts**
- they reach **292 distinct destinations**
- **644 of 649** have a source host that was *never previously a destination*
  anywhere in the corpus; the remaining 5 were last reached over 115,000
  seconds earlier
- zero attack hosts appear as both source and destination

**The attacker's beachhead was established outside the observable window.**
There is no pivot to see. What is visible is fan-out: 4 sources → 292 targets.
The signature was written for a threat model this corpus does not contain.

### The fix: score on fan-out, demote pivot to supporting

Fan-out separates cleanly — benign traffic sits at a median of 1 destination
per source-hour (p99 = 6) while attacks sit at a median of 11 and reach 46.

A gate makes fan-out *necessary*. Without it the modifiers (`new_pair` +
`rare_dst` = 0.35) clear the reporting threshold alone, labelling 26.7% of
benign traffic as lateral movement on evidence containing no lateral indicator.

| Version | Recall | Benign firing | Lift |
|---|---|---|---|
| Original (unbounded pivot) | 78.6% | 85.8% | 0.9× |
| + windowed pivot | 77.8% | 48.3% | 1.6× |
| + fan-out rewrite | 73.2% | 26.7% | 36.7× |
| **+ fan-out gate** | **73.2%** | **1.07%** | **68.5×** |

A 80× reduction in benign firing for 5.4 points of recall.

---

## Finding 4 — The synthetic stream does not match the real attack topology

**Severity: medium. Open.**

The synthetic live stream contains a textbook pivot chain
(`C3034 → C1020 → C209 → C1139 → C5554 → C1137`, 268 seconds). The real LANL
corpus contains no such chain in its observable window — it contains fan-out
from 4 fixed sources.

The generator encodes an assumption about attacker behaviour that the real
data does not support. Anything validated only against the synthetic stream is
validated against that assumption, not against reality. This is the concrete
form of the general warning about training on synthetic data, and it is the
reason the generator should be rebuilt from the measured topology of the real
corpus rather than from intuition.

---

## Finding 5 — "Valid account abuse" described a quarter of normal work

**Severity: high. Fixed.**

T1078 fired when a new user-host pair succeeded on the first attempt with no
preceding failures. Measured: **28.6% of benign traffic**, and 44% of the live
synthetic stream. The reason is obvious once stated — people legitimately
reach machines they have not used before every day.

No ground truth exists for this technique, so it **cannot be tuned by fitting
to labels**. The only measurable quantity is the benign firing rate, and
tightening has to come from domain reasoning about what the technique actually
requires. Candidate gates, measured within the base condition:

| Additional requirement | Benign firing |
|---|---|
| unusual logon hour/type | 9.20% |
| rare destination (degree ≤ 3) | 3.21% |
| destination novelty > 0.7 | 1.88% |
| explicit alternate credentials | 0.03% |

The technique is about a credential being used *somewhere it does not belong*,
so the gate requires an anomaly that is a property of the **destination**
rather than of the user's routine. Hour-of-day was deliberately excluded from
the gate — shift work and global teams make it a property of the organisation,
not of the access — and kept only as a score booster.

Result: **28.6% → 3.21%** benign firing.

---

## Finding 6 — The Kerberos signature was measuring a logging gap

**Severity: high. Fixed.**

T1550.003 fired when a service ticket (TGS) appeared with no preceding
ticket-granting ticket (TGT) for that account — the textbook shape of a forged
or replayed ticket. It fired on **8.5% of benign traffic**.

The corpus explains why:

| | |
|---|---|
| Accounts requesting a TGS | 16,334 |
| Accounts ever observed with a TGT | 5,635 |
| **TGS accounts with no observed TGT** | **11,859 (72.6%)** |

In this data a service ticket without an observed TGT is the *norm*. The TGT
was issued before the capture window or is simply not logged. The rule was
detecting incomplete telemetry, not attacker behaviour.

**Fix.** The engine now measures its own telemetry completeness
(`TacticEngine.tgt_coverage()` — the share of ticket-requesting accounts for
which a TGT has actually been observed) and the signature consults it. Where
coverage is below 50%, a missing TGT carries no information and the rule stays
silent. Where TGTs are reliably logged, it fires as designed.

> Absence of evidence is only evidence of absence when the evidence would have
> been visible.

This generalises: any rule keyed on the *absence* of a record needs to know
whether that record would have been present. Worth auditing the rest of the
detection surface against it.

---

## Finding 7 — Noisy-OR beats linear fusion, but not for the expected reason

**Severity: n/a (experiment). Result: noisy-OR wins.**

Protocol: reliabilities fitted on validation by coordinate ascent on PR-AUC,
threshold derived on validation at the 25 FP/10k budget, test scored once with
both frozen.

| Operator | Val PR-AUC | **Test PR-AUC** | Test FP/10k | Test recall | R@1000 |
|---|---|---|---|---|---|
| linear | 0.9060 | 0.5753 | 33.23 | 0.8889 | 0.9048 |
| **noisy-OR** | 0.9790 | **0.8041** | 34.44 | 0.9048 | 0.9286 |

**+40% test PR-AUC at the same false-positive budget.**

The fitted reliabilities are the interesting part:

```
tgn 0.95 | novelty 0.05 | burst 0.30 | pivot 0.05 | corroboration 0.35
```

The optimiser drove **novelty and pivot to the floor**. Noisy-OR does not win
by letting the behavioural channels finally contribute — it wins by letting the
TGN's confident signal dominate *without being diluted by an average*. On the
offline features the TGN separates attacks from benign by 360× (means 0.9446
vs 0.0026), and the behavioural channels mostly add noise on top of it.

A related correction: the channel means show `pivot` at 0.85 for attacks vs
0.52 for benign, which appears to contradict Finding 3a. It does not.
`explicit_signals` computes `pivot` as `1.0 if recently-reached else
min(1, src_host_unique_dst_1h / 5)` — the *fallback* branch is fan-out. The
set-membership test has 0% attack recall; the channel looks discriminative only
because fan-out leaks in through its fallback. Two different quantities share
one name, which is worth fixing for clarity alone.

---

## Finding 8 — ~~Training/serving skew, measured~~ **RETRACTED — the comparison was confounded**

> **Correction (Finding 12).** The "9.4x degradation" below compared the
> *offline TGN probability* against the *online fused risk* — two different
> quantities, since fusion deliberately dilutes the model with three
> behavioural channels. Repeating it like-for-like, on a warm deployment,
> gives correlation **0.9400** and online PR-AUC at **100.4%** of offline.
> **There is no serving skew.** The original number measured cold state plus
> the fusion operator, stacked, and attributed both to the feature engine.
>
> The section is kept rather than deleted: the measurement was real, the
> inference from it was wrong, and removing it would hide how the error was
> made.



**Severity: critical. Open. This is the largest defect in the system.**

Finding 7 says the offline TGN is excellent. The live chain probe said the TGN
contributes almost nothing. Both cannot be right, so the same events were sent
through the live API and compared against their cached offline scores.

5,588 corpus events, 22 labelled attacks, identical checkpoint:

| | Offline TGN | Online fused risk |
|---|---|---|
| benign mean | 0.0102 | 0.2034 |
| attack mean | 0.9178 | 0.6029 |
| attack/benign separation | **89.8×** | **3.0×** |
| **PR-AUC** | **0.7831** | **0.0831** |

Pearson correlation between the two scores for the same event: **0.28**. Of 69
events the offline model scores ≥ 0.5, only 33 clear the decision threshold
online.

**A 9.4× PR-AUC degradation between the offline pipeline and the deployed
path.** Every offline metric in the training report describes a system that is
not the one running.

### The confound in this measurement, stated plainly

The online engine computes its rolling features from its own state, which at
test time contained only the synthetic stream — not corpus events 0..525,228.
Features like `delta_user_log`, `user_historical_degree`, `pair_seen_before`
and `destination_novelty` all depend on long history, so part of this gap is
the online engine running with a *colder* history than the offline pipeline
had, rather than computing differently from the same history.

That confound does not make the finding go away — a deployment genuinely does
start cold, and the gap is real for any new install — but it does mean this
number is an upper bound on the skew attributable to the feature engine
itself. The clean experiment is a full-corpus replay through the live API from
event 0, so both paths see identical history. Until that runs, the honest
statement is: **online and offline disagree severely (r = 0.28), with cause
split between feature-engine differences and history warm-up in unknown
proportion.**

This outranks everything else in this document. Fusion operators, signature
tuning and thresholds are all refinements on top of a score that does not
currently survive the trip into production.

---

## Finding 9 — There is no serving skew. There is a cold-start problem.

**Severity: reclassifies Finding 8. Diagnosed.**

Finding 8 could not separate "the online engine computes differently" from
"the online engine knows less". Reading the code settles it: `live.py` and the
offline pipeline both instantiate the *same* `CausalFeatureEngine`. There is no
second implementation, so there is no code-path skew to find.

The entire gap is state, and the engine's state divides cleanly:

| Kind | Members | Behaviour |
|---|---|---|
| **Bounded** | rolling 5m / 15m / 1h / 24h windows | self-healing — correct once the window elapses |
| **Unbounded** | `_pair_total`, `_user_destinations`, `_src_destinations`, `_dst_users`, `_last_user`, `_last_pair`, `_user_logons` | never heal — they encode "has this *ever* happened" |

Measured convergence against a full-history reference, as normalised
divergence by warm-up length:

| Feature | 0 | 5k | 20k | 50k | 100k | **200k** |
|---|---|---|---|---|---|---|
| `dst_historical_degree` | 1.522 | 1.487 | 1.391 | 1.224 | 0.990 | **0.651** |
| `delta_pair_log` | 1.566 | 1.387 | 1.186 | 0.973 | 0.749 | **0.455** |
| `is_new_pair` | 1.689 | 1.439 | 1.192 | 0.953 | 0.718 | **0.424** |
| `pair_seen_before` | 1.689 | 1.439 | 1.192 | 0.953 | 0.718 | **0.424** |
| `pair_rarity` | 1.311 | 1.125 | 0.925 | 0.732 | 0.569 | **0.359** |
| `rare_logon_score` | 0.575 | 0.531 | 0.467 | 0.378 | 0.289 | **0.185** |

**15 of 27 features converge fully. The other 12 never do.** After 200,000
events of warm-up, `is_new_pair` — the strongest single feature in the set — is
still 42% divergent, and only **0.3%** of events receive fully correct
features.

This is not a tuning problem with a warm-up period as its answer. A cold
engine cannot know whether a pair it has never seen is new or merely unobserved,
and no quantity of forward traffic resolves that. `is_new_pair` reads 1 for
every long-established relationship the process has not personally witnessed.

---

## Finding 10 — Restarting the service silently destroyed detection quality

**Severity: critical. Fixed.**

`CausalFeatureEngine()` was constructed fresh at process start, on a model
reload, and nowhere was it ever persisted. Nothing in the codebase saved or
restored it.

Combined with Finding 9, the consequence is severe and was entirely invisible:

> A live stream only moves forward. Cumulative state discarded at restart is
> never rebuilt, so the service came back up **permanently less accurate than
> it went down** — with no error, no warning, and no metric that changed.

This session restarted the server four times. Each restart reset detection to
cold-start quality.

**Fix.** `CausalFeatureEngine` gained `snapshot()`, `restore()` and
`coverage()`, with snapshots as plain JSON-serialisable data (no pickle, so the
state file is not an execution vector in a security product). `live.py`
restores at boot from `GRAPHSENTINEL_FEATURE_STATE`, and two endpoints make the
state observable and durable:

```
GET  /api/v1/feature-state        how much history the engine is carrying
POST /api/v1/feature-state/save   persist it (atomic write via rename)
```

Verified end to end: 11,560 events seeded → 5,250 pairs / 1,446 users / 1,483
source hosts recorded → snapshot written (283 KB gzipped) → **server restarted**
→ state restored identically, `restored_from_snapshot: true`.

Tests pin the guarantee that matters: a restored engine produces features
*identical* to one that processed the whole history, and a deliberately
contrasting test proves a cold engine does not — so the first test cannot pass
vacuously.

### What this means for deployment

Onboarding is not "point it at the log stream and wait". It is:

1. **backfill** — ingest the customer's historical logs once to build cumulative state
2. **snapshot** — persist it as an artifact alongside the checkpoint
3. **restore** on every start, and re-snapshot periodically

`GET /api/v1/feature-state` exists so "is this engine warm?" is a question with
an answer, rather than something inferred from detection quality weeks later.

---

## Finding 11 — Tactic rules were bound to one deployment's entity dictionary

**Severity: critical for any real customer. Fixed.**

Every signature keyed on an event category compared a dictionary index
against a module constant:

```python
if record.logon_type_id in HUMAN_LOGON_TYPES:   # LOGON_INTERACTIVE = 4
```

Those indices are a property of **one** entity dictionary, not of Windows:

| Category | Frozen LANL dictionary | Dictionary built from a customer's logs |
|---|---|---|
| Network | 1 | 1 |
| Service | 2 | 3 |
| **Interactive** | **4** | **2** |

A deployment that builds its own dictionary assigns ids in order of first
appearance. Every category-keyed rule is therefore correct for exactly one
deployment and **silently inert everywhere else** — and worse, an index could
land on a *different* category and fire on the wrong thing.

The failure mode is what makes this dangerous:

> Every unit test was written against the LANL constants, so they all passed.
> The rule produced no error, no warning, and no missing output — it simply
> never matched. Nothing in the test suite or the running system could
> distinguish "this technique is not present" from "this rule cannot fire".

It surfaced only from an end-to-end test that sent **Windows** events through
a gateway holding a non-LANL dictionary: a machine account performing an
interactive logon was classified `T1078` instead of `T1078.002`, because the
machine-account rule was comparing against index 4 while the dictionary had
assigned 2.

**Fix.** `TacticContext` now carries resolved category *names*
(`logon_type_name`, `auth_type_name`, `orientation_name`) and all rules match
on those, case-insensitively. Names are stable across dictionaries. An empty
name never satisfies a rule — the rules fail closed rather than guessing.

`TacticEngine.observe()` still accepts ids for its rolling state, which is
safe because those ids are only ever compared to each other within a single
stream, never to a cross-dictionary constant.

Four regression tests pin the property, including two deliberately
contradictory cases where the name and the id disagree and the name must win.

### The general lesson

Any constant derived from a *learned or discovered* artifact — a dictionary,
a vocabulary, an embedding index — is only valid for the artifact that
produced it. Hard-coding one into logic makes that logic silently
deployment-specific. Worth auditing the rest of the system for the same
pattern.

---

## Finding 12 — Verified: no serving skew, and the fusion was the bottleneck

**Severity: resolves Findings 8, 9 and 1. Confirmed.**

Finding 9 claimed the online/offline gap was cold state rather than a second
feature implementation. That is falsifiable, so it was tested: backfill on
corpus events 0..499,999 only, then replay the held-out 43,615 through the
live API with **original timestamps**, comparing against cached offline scores
for the same `event_id`.

### The first run failed, because the comparison was wrong

Correlation came out 0.4939 against a pre-committed threshold of 0.6 —
`NOT CONFIRMED`. Before accepting that, the rule from the harness-errors
section applied: *suspect the measurement first*. It was comparing offline TGN
probability against online **fused** risk. The scoring response exposed only
the fused score, so the raw channel was not even available — which is why the
confound existed at all.

`ScoreEventResponse.components` now carries the per-channel inputs, and the
comparison was repeated like-for-like.

### Result

| | Offline TGN | Online TGN (warm) | Online fused |
|---|---|---|---|
| benign mean | 0.0055 | 0.0062 | 0.0606 |
| attack mean | 0.8785 | 0.8919 | 0.6155 |
| separation | 158.4× | 143.3× | 10.2× |
| **PR-AUC** | **0.6899** | **0.6924** | **0.2664** |

- correlation offline vs **online TGN**: **0.9400**
- correlation offline vs online **fused**: 0.4939 *(the confounded number)*

**The deployed model reproduces 100.4% of its offline PR-AUC when warm.** There
was never any training/serving skew. Two separate effects had been stacked and
blamed on one cause.

### What the third column shows

The same events, same warm model: TGN PR-AUC **0.6924**, fused output
**0.2664**. **The linear fusion discards 61% of the model's discriminative
power before the threshold ever sees it.** That is independent live-path
confirmation of Finding 1, arrived at from a completely different direction.

### Consequence: noisy-OR shipped

The only reason noisy-OR was held back was Finding 8's suggestion that the TGN
was broken online. It is not. Noisy-OR is now the default
(`GRAPHSENTINEL_FUSION=linear` restores the old behaviour), paired with its own
validation-calibrated threshold:

| Operator | Threshold | Val PR-AUC | **Test PR-AUC** | Test FP/10k |
|---|---|---|---|---|
| linear | 0.362571 | 0.9060 | 0.5753 | 33.23 |
| **noisy_or** | **0.329195** | **0.9790** | **0.8041** | 34.44 |

`select_fusion()` returns the operator and its threshold as one value, because
pairing an operator with the other's threshold silently changes the alert rate
while every number still looks plausible.

Live effect, measured on the 11,560-event synthetic stream: alert rate fell
from **3.6% to 0.91%** — fewer alerts, higher precision, consistent with the
+40% test PR-AUC.

### A correction to Finding 1 while shipping it

The veto is real but narrower than first stated. Linear's behavioural ceiling
is 0.45 against the **checkpoint's deployed threshold of 0.4543** — so in the
configuration that actually ran, behavioural evidence alone could never alert.
But re-deriving the linear threshold on validation gives **0.3626**, which 0.45
clears. Half the original defect was simply that the threshold had never been
recalibrated. "Weighted averages always veto" would have been wrong, and the
regression test now pins the precise version.

### The fitted reliabilities encode *this corpus's* threat model

```
tgn 0.95 | novelty 0.05 | burst 0.30 | pivot 0.05 | corroboration 0.35
```

The fit drove `pivot` to the floor, correctly: on this corpus pivot has 0%
attack recall (Finding 3a). The consequence is that the shipped configuration
scores the labelled five-hop chain at **0.1026** and still does not alert it.

That is not a bug in the operator — it is the fit faithfully learning that
pivot carries no signal *here*. An estate that genuinely experiences pivot-based
lateral movement would need `pivot` weighted far higher, and would have to
re-fit on its own labelled data. This is the same concern as Finding 4, and it
is the strongest argument for per-tenant calibration rather than shipping one
global configuration.

---

## Finding 13 — The chain needed a rule, not a weight

**Severity: closes the open item from Finding 12. Shipped.**

The obvious response to "the fitted config scores the labelled chain at 0.1026
and never alerts it" is to raise the `pivot` reliability. That is the wrong
move, and measuring why produced the more useful answer.

### Why raising the weight fails

`pivot` asked *"was this event's source host recently a destination of
anyone?"* — which describes ordinary client-server traffic:

| Definition | Chain recall | LANL benign | Lift |
|---|---|---|---|
| any-source pivot (shipped) | 42.9% | **47.05%** | **0.9×** |
| same-user chain, 3+ hops, 1800s | 35.7% | 3.693% | 9.7× |
| same-user chain, 3+ hops, 600s | 35.7% | 0.775% | 46.1× |
| same-user chain, 4+ hops, 600s | 32.1% | 0.307% | 104.8× |

A channel firing on 47% of traffic cannot carry weight at any setting. The
weight was never the problem; the definition was. Requiring the **same
account** to be moving onward from a host *it* reached is 60× more selective
for seven points of chain recall.

### And why the better definition still gets weight 0.05

Re-fitting on the improved signal changed nothing: `pivot` came back at 0.05
again, and test PR-AUC moved 0.8041 → 0.8045.

> **A weight is fitted from examples, and the corpus has none.** 644 of its 649
> red-team events have a source host that was never previously a destination —
> the beachhead was established outside the observable window. A channel with
> no positive class gets no weight however good its definition becomes.

Improving a signal cannot manufacture the examples needed to learn its weight.
That is the whole reason a rules layer exists alongside a model.

### The rule, chosen by measured cost

Domain knowledge asserts that a same-account multi-hop walk is malicious. The
cost was measured against the 25 FP/10k budget **before** choosing, not after:

| Rule | Chain hits | FP/10k | Within budget |
|---|---|---|---|
| chain 3+ hops / 600s | 10 | 77.5 | no — 3.1× over |
| chain 4+ hops / 600s | 9 | 30.7 | no |
| **chain 4+ hops / 300s** | **9** | **4.6** | **yes — 18% of budget** |
| chain 5+ hops / 300s | 8 | 1.0 | yes |

Tightening the *window* mattered more than requiring more hops: an attacker
crossing five hosts in five minutes is doing something an administrator does
not. The rule applies a **floor** (0.60), not an override — an event already
scoring higher keeps its score, and `rule_floor` names the rule so a detection
made by a rule is never credited to the model.

### Verified on the live deployment

Replaying the labelled chain (`C3034 → C1020 → C209 → C1139 → C5554 → C1137`,
one account) through the warm running service:

| Hop | Risk | Alerted | Rule floor |
|---|---|---|---|
| C3034 → C1020 | 0.0500 | no | — |
| C1020 → C209 | 0.1017 | no | — |
| C209 → C1139 | 0.1440 | no | — |
| C1139 → C5554 | 0.1786 | no | — |
| **C5554 → C1137** | **0.6000** | **yes** | **chain_pivot** |

Previously 0/5, scoring 0.0015 to 0.1576.

### The honest limitation: it catches the chain late

The rule needs three prior hops, so it fires on the **fifth** hop — by which
point the attacker has reached their target. Catching it earlier is possible
and costs budget:

| Catch at | FP/10k | vs 25 budget |
|---|---|---|
| hop 5 (shipped) | 4.6 | 18% |
| hop 4 | 30.7 | 1.2× over |
| hop 3 | 77.5 | 3.1× over |

That is a policy decision with a priced menu, not a technical limit. A site
willing to spend 30 FP/10k catches the chain a hop earlier. The default spends
the least budget that detects it at all, and the numbers are in the code so the
choice can be revisited with evidence.

---

*Addendum (Finding 25):* the false-positive table above was measured on the
sampled corpus, where one event in several hundred survives and almost no
benign multi-hop pattern is observable. On an unsampled day the 4-hop /
300 s rule flags 760 benign events per 10,000 all day long. The conclusion
that a same-account chain is the right discriminator stands; the cost
figures do not, and the shipped rule is now four *novel* hops in 1,800 s,
priced at full rate.

---

## Finding 14 — 99.8% of the headline PR-AUC is one memorised host

**Severity: critical. Not fixable by a code change — it is a property of the
corpus, and it invalidates the headline number as a measure of detection.**

The test PR-AUC of `0.8210` is the number this project has been quoting. It is
almost entirely the model recognising a single source host ID.

In the LANL corpus the red-team activity originates from a handful of
compromised hosts, and one of them dominates. Across every partition that host
is **attack-only by construction**:

| Partition | Events from host 8426 | Attack | Benign |
|---|---|---|---|
| train | 303 | 303 | **0** |
| validation | 205 | 204 | 1 |
| test | 121 | 121 | **0** |

A model that learns nothing except "source host 8426 is malicious" *could*
score 121 of the 126 test attacks correctly without representing attack
behaviour at all, because host identity is a perfect separator in training.
**Finding 20 tested whether this model does, and it does not:** zeroing every
identity channel leaves its recall on this host at 82–95%. What it learned is
the one campaign's behaviour. The contamination below is real either way — one
host is one pattern — but the mechanism is single-pattern learning, not
identity memorisation, and the remedy is a second pattern, not a regulariser.

### The decisive test

Remove that one host from the test partition and re-measure. What remains is
the 5 attack events originating from other hosts, against 115,871 benign
events — which is the situation any real deployment is in, where the attacker's
host has ordinary history behind it.

| | PR-AUC | 95% CI | Base rate | Lift |
|---|---|---|---|---|
| Full test partition (as published) | **0.8210** | — | 0.001086 | 755.8x |
| Host 8426 removed | **0.00193** | [0.00166, 0.00378] | 0.0000432 | 44.8x |

**The metric collapses by 99.8%.**

Per-host detail, test partition:

| Source host | Attacks | Missed | Miss rate | Mean score | Benign events |
|---|---|---|---|---|---|
| 8426 | 121 | 7 | 6% | 0.9179 | 0 |
| 11807 | 3 | 3 | **100%** | 0.0039 | 2 |
| 10002 | 2 | 2 | **100%** | 0.0510 | 0 |

Every attack from a host other than the memorised one is missed. Their scores
are `0.075, 0.027, 0.0055, 0.0047, 0.0016` against a `0.29696` threshold — not
near-misses, an order of magnitude short.

### What is and is not claimed

The held-out interval `[0.00166, 0.00378]` excludes the base rate, so the model
is **not** reduced to random: it retains a 44.8x lift and does rank those
attacks above most benign traffic. There is behavioural signal. But 0.0019
PR-AUC means roughly 500 alerts per true positive, which is not an operating
point anyone would staff.

The honest limit: **n = 5 attacks** in the held-out set. That is far too few to
estimate generalisation precisely, and the interval is correspondingly wide.
What is *not* uncertain is the mechanism — the attacker host is attack-only in
training, which is verifiable by counting rows rather than inferred from the
result.

### Consequence

Every ranking number in this repository that was measured on the full test
partition — the `0.8210`, the baseline comparisons, the fusion selection —
inherits this. They remain valid as *relative* comparisons between detectors on
this corpus, because all of them face the same shortcut. They are not valid as
estimates of field performance against an unseen attacker.

This is a known pathology of host-labelled intrusion corpora rather than a bug
in this implementation, but the project had been reporting the contaminated
figure without the caveat, which is the actual defect.

### What would fix it

Entity-disjoint evaluation: partition by attacker host so the hosts in test
never appear as attackers in train. On this corpus that leaves ~5 test attacks,
which is too few — so the real answer is that **this corpus cannot support a
credible generalisation claim**, and the synthetic generator (Finding 4) has to
carry that load, with attacker hosts that also produce benign traffic.

---

## Finding 15 — The auto-execution gate means 51% precision, not 85%

**Severity: high. Contained by the action table, now enforced by test.**

The response layer auto-executes at `risk >= 0.85`. That value was chosen off
the score scale. Measured against labels on the test partition, it is not a
confidence at all:

| Threshold | Purpose | Alerts | Attacks | Precision | 95% CI |
|---|---|---|---|---|---|
| 0.2970 | `tgn_only` alert | 514 | 114 | 22.18% | [18.8%, 26.0%] |
| 0.3292 | `noisy_or` alert | 490 | 114 | 23.27% | [19.7%, 27.2%] |
| 0.4543 | original shipped | 421 | 112 | 26.60% | [22.6%, 31.0%] |
| 0.6000 | chain rule floor | 331 | 109 | 32.93% | [28.1%, 38.2%] |
| **0.8500** | **auto-execution gate** | 211 | 107 | **50.71%** | [44.0%, 57.4%] |
| 0.9900 | — | 107 | 91 | 85.05% | [77.1%, 90.6%] |

**A score of 0.85 corresponds to a coin flip, not to 85% confidence.** Roughly
half of everything auto-actioned at that gate is benign.

Requiring the interval's *lower bound* to clear a target — rather than the point
estimate, which is how a gate ends up looser than intended:

| Target precision | Threshold | Alerts | Recall |
|---|---|---|---|
| >= 50% | 0.9231 | 183 | 83.3% |
| >= 75% | 0.9896 | 109 | 72.2% |
| >= 90% | **not achievable** at any threshold with >= 20 alerts | | |

### Why this is not an incident

Swept exhaustively over every technique x confidence x risk, exactly one action
with non-zero disruption can fire unattended:

| Action | Disruption | Auto-executes? |
|---|---|---|
| `increase_monitoring` | 0 | yes |
| `notify_soc` | 0 | yes |
| `force_reauth` | 1 | yes — only at confidence=high **and** risk >= 0.85 |
| `lock_account`, `block_network_path` | 3 | no — approval required |
| `reset_credentials`, `disable_service_account` | 4 | no |
| `isolate_host` | 5 | no |

So the realised cost of the miscalibration is that ~104 benign events per 211
auto-actions see **one extra authentication prompt**. That is a designed-for
outcome, and the layered gate is doing precisely the job it was built for.

### The actual risk

That safety was a property of the *action table*, not a guarantee. Every harsher
action happens to carry `requires_approval=True`; one new entry added without
the flag would silently put account lockout behind a coin-flip gate, and nothing
would have caught it. Now pinned by
`test_no_meaningfully_disruptive_action_can_ever_auto_execute`, which sweeps the
full cross-product — and was mutation-checked by flipping `lock_account`'s flag
to confirm the test actually fails when the invariant breaks.

Recommendation: the constant stays, but it is a **rank threshold, not a
probability**, and should be documented and named as one wherever it appears
(`response.py`, `product.py`, `playbooks.py`, `alert_summary.py`, `main.py`).

---

## Finding 16 — The scores are 3.6x over-confident, and the diagram that should show it cannot

**Severity: medium. Documented, not corrected.**

Hypothesis stated before measuring: training with a positive-class weight capped
at 120x deliberately distorts the likelihood, so the output should be
systematically over-confident. **Confirmed in direction.**

| Partition | Mean prediction | Prevalence | Ratio | ECE | Brier |
|---|---|---|---|---|---|
| validation | 0.004353 | 0.002200 | **2.0x over** | 0.002194 | — |
| test | 0.003919 | 0.001086 | **3.6x over** | 0.002833 | 0.001843 |

Brier decomposition on test: reliability `0.000080`, resolution `0.000011`,
uncertainty `0.001085`. The uncertainty term — fixed by prevalence and
unimprovable by any model — is **93% of the Brier score**, which is why quoting
Brier alone on rare events says almost nothing about the detector.

### ECE is the wrong statistic for a rare-event detector

The decile reliability diagram is uninformative here: 9 of 10 bins show
predicted and observed both at `0.00000`, and **all 126 test attacks fall into
bin 9**. The score distribution is too bimodal for decile binning — median
score `3e-8`, p99.9 `0.986`.

Raising the bin count fixes the diagram but exposes something worse about the
summary statistic:

| Bins | Bins containing any positive | ECE |
|---|---|---|
| 10 | 1 | 0.002833 |
| 50 | 2 | 0.002833 |
| 200 | 5 | 0.002837 |

**ECE is essentially constant regardless of resolution.** It is a
population-weighted average of per-bin error, and 99.5% of the population sits
in bins where predicted and observed are both ~0 and the error is therefore ~0.
No amount of binning changes that, so ECE on this problem reports the base rate
of the *uninformative* region and is close to blind to the region that matters.
It should not be quoted as a calibration summary for this detector, and the
same objection applies to any detector at this prevalence.

At 200 bins the region that matters becomes legible, and the miscalibration
there is substantially worse than the stream-wide 3.6x:

| Bin | Events | Positives | Predicted | Observed | 95% CI | Ratio |
|---|---|---|---|---|---|---|
| 195 | 580 | 1 | 0.0013 | 0.0017 | [0.0003, 0.0097] | calibrated |
| 196 | 580 | 1 | 0.0031 | 0.0017 | [0.0003, 0.0097] | calibrated |
| 197 | 580 | 1 | 0.0125 | 0.0017 | [0.0003, 0.0097] | **7.4x over** |
| 198 | 580 | 8 | 0.0936 | 0.0138 | [0.0070, 0.0270] | **6.8x over** |
| 199 | 580 | 115 | 0.6712 | 0.1983 | [0.1679, 0.2327] | **3.4x over** |

The top bin's interval `[0.168, 0.233]` excludes its prediction of `0.671` by a
wide margin. So the over-confidence is not diffuse — it is concentrated in
exactly the scores that trigger alerts and gate automated action, which is what
makes Finding 15's threshold table the operative measurement rather than any
single-number calibration score.

### A robustness bug found by testing this

Writing tests for the binning surfaced a real defect, distinct from the above.
When a single score is repeated across most of the stream — exact ties rather
than merely small values — every quantile from 0 to 0.9 returns that same value.
They de-duplicated to a single interval, and the whole report collapsed to
**one bin containing every event**, whose "predicted" and "observed" are just
the stream-wide means. Not a wrong number so much as no measurement, with
nothing in the output indicating it.

This corpus did not trigger it, because its low scores are distinct tiny floats
rather than identical ones. A quantised or clipped score channel would trigger
it immediately. `_equal_frequency_edges` now recovers the lost bins by
repeatedly splitting the most populated interval at its most balanced interior
boundary, so a dominant tie block settles into its own bin while the
informative region above it is subdivided. Covered by
`test_survives_a_heavily_tied_score_distribution`.

No recalibration is applied. Isotonic or Platt scaling would fix the scale, but
with 126 test positives concentrated in a single bin the fit would be estimated
from too little data to trust, and the ranking — which is what the alert queue
actually consumes — would be unchanged.

---

## Finding 17 — The live console displayed detections the model had not made

**Severity: critical for any demonstration. Fixed, server and client.**

Found while tracing the production detection path to build the prevention
harness. In `api/main.py`, the `/api/v1/live/events` endpoint loaded
`artifacts/synthetic/ground_truth_manifest.json` at startup and, for every
event whose *user* was a named synthetic attacker, rewrote the WebSocket
broadcast: risk clamped to at least 0.92, alert flag forced on, severity
therefore "critical". The comment explained the intent — "so the dashboard
always shows the correct detection even when the model memory is cold."

The console then did the same thing again on its own side:
`isAttack = alerted || isKnownAttacker || critical`, so a labelled attacker was
painted red whatever the score. Between the two, a viewer watching a synthetic
attack saw a critical detection **whether or not anything had fired**.

### Scope, established rather than assumed

| Path | Affected? |
|---|---|
| HTTP response from `/api/v1/live/events` | No — `return result` is the service's own output |
| Alert store, alert counts, evaluation reports | No — persisted at the un-boosted threshold |
| WebSocket payload → live console | **Yes** |
| Client rendering of any event with a ground-truth label | **Yes** |

So every *number* in this project remained honest, including the 650-alert
count verified earlier. What was dishonest was the one surface a reviewer
actually watches. The override predates this session — it is present in the
archived source — and is the kind of "demo aid" that survives precisely because
the counts it sits next to are correct.

### The fix

Detection and ground truth are now two separate things on both sides:

- The payload is built by `scored_event_payload()`, a pure function that
  carries the service's own risk, alert flag and severity (via the shared
  `severity_for` banding, replacing a duplicated inline copy). Ground truth
  travels as `chain_id` / `is_ground_truth_attacker` — a **label** beside the
  score, not a replacement for it.
- The console computes `isAttack` from the model's verdict alone and renders a
  labelled attacker the model did not flag as **`GT · MISSED`**, amber and
  dashed, distinct from a detection.

The second half is the point. A console that cannot show a miss cannot show
detection quality; it can only show that attacks exist. With Finding 14
establishing that the model misses every attack from a host it has not seen,
a display that hid misses would have hidden the most important thing about the
model.

Pinned by `test_console_honesty.py` (payload equals service output for a known
attacker at 0.03, 0.41 and 0.97; a miss is labelled as a miss; a source-level
guard against the override pattern) and by
`test_the_console_does_not_paint_ground_truth_as_detection`.

---

## Finding 18 — Precision at a fixed gate is not a property of the gate

**Severity: high. The gate is now derived with provenance; the deeper result is
that precision was the wrong quantity to fix.**

Phase 4 set out to replace the literal `0.85` auto-execution gate with one
derived from a precision target. Deriving it on validation — the partition the
alert thresholds are derived on, so no operating constant is fitted to test —
and then checking it on the sealed test period produced this:

| Target (Wilson lower bound, validation) | Threshold | Validation precision | Test alerts | Test precision | Test 95% CI |
|---|---|---|---|---|---|
| ≥ 50% | 0.4481 | 55.1% | 423 | **26.5%** | [22.5%, 30.9%] |
| ≥ 75% | 0.8777 | 80.5% | 198 | **53.5%** | [46.6%, 60.3%] |
| ≥ 90% | not achievable | | | | |
| *(old literal 0.85)* | 0.8500 | 78.0% [72.6%, 82.6%] | 211 | 50.7% | [44.0%, 57.4%] |

Every gate loses 25–30 points of precision between the tuning period and the
sealed one, with non-overlapping intervals. The 75% gate ships (`0.877729`,
`detection/gates.py`) because it ratifies the old gate's validation behaviour
with a derivation behind it and changes almost nothing operationally — but it
ships with its realised test precision recorded beside its target, and a test
that re-derives every number from the committed fixture.

*Addendum (Finding 24):* this table is on the raw model probability. The
response layer compares the fused risk, so the gate was re-derived on that
quantity: 0.846394, the same 251 validation alerts at 80.5%, test precision
53.2% [46.3%, 60.0%] at 8.11 benign per 10k. The decay this finding is about
is unchanged.

### Why it decays: three factors, decomposed per day

Training ends on day 10. Per day thereafter:

| Day | Partition | Benign events | Benign above gate | per 10k | Attacks | Attacks above gate | Precision |
|---|---|---|---|---|---|---|---|
| 10 | validation | 27,677 | 7 | 2.53 | 0 | 0 | — |
| 11 | validation | 27,369 | 2 | 0.73 | 0 | 0 | — |
| 12 | validation | 38,810 | 40 | 10.31 | 207 | 202 | 83% |
| 13 | test | 40,639 | 31 | 7.63 | 75 | 69 | 69% |
| 14 | test | 39,268 | 32 | 8.15 | 25 | 17 | 35% |
| 15 | test | 35,981 | 29 | 8.06 | 26 | 20 | 41% |

**1. The false-positive floor is set by the day, not the attacker.** On attack
days the gate admits a near-constant 29–40 benign events; on the two quiet
days it admits 2 and 7. Those quiet days have ~27k events against 36–40k —
a weekend against weekdays — and the floor is ~4× higher on busy days. This
is not collateral from the attacker's activity: only 7 of day 12's 40 false
positives touch an attacked host or attacker account, against a 73% baseline
for all benign traffic that day. Busy days simply produce more novel pairs and
more benign fan-out.

**2. Attack volume varies eightfold.** 207, 75, 25, 26 attacks per day. With a
~32-event floor, precision is *arithmetically* 86%, 70%, 44%, 45% even if the
model scored every attack perfectly. Most of the decay in the table is this.

**3. The model itself decays, moderately.** All of these attacks come from
host 8426, so this is the same attacker on successive days. The share of its
events above the gate: 0.99, 0.97, 0.68, 0.80. Real, but the smallest of the
three effects.

### Two further things the per-day view exposes

- **Every validation attack is on one day.** Days 10 and 11 hold no attacks;
  all 207 fall on day 12. Every validation-derived threshold in this project —
  the alert thresholds, the operating points, and now the gate — is therefore
  tuned to a single day of one attacker's activity. The bootstrap intervals do
  not know this, because resampling events within a day cannot widen an
  interval to cover days that are not there.
- **PR-AUC decays faster than the gate does:** 0.982, 0.917, 0.639, 0.683
  across days 12–15. A retraining cadence measured in days, not weeks, is what
  this corpus implies — with the caveat that it is one attacker on four days.

### What changes

Precision is an *outcome*: the floor the gate admits, times whatever attack
volume the day brings. The controllable quantity is the floor — benign events
above the gate per 10,000 — and that is now recorded on the gate as provenance
(5.22/10k on validation, 7.94/10k on test) with a test that re-derives it. If
the gate is ever re-derived, that rate is the number to hold; a precision
target will be met or missed by whatever the attacker does that day.

The literal `0.85` survives only as a **display band** (`critical`) and a
playbook *recommendation* threshold, both documented as such in
`detection/gates.py`. They used to share a number with the execution gate,
which made "critical" read as "acted on automatically". They no longer do.

---

## Finding 19 — The playbook endpoint recorded executions that never happened

**Severity: high for the audit trail. Fixed by giving the product one execution
path.**

`POST /api/v1/playbooks/{name}/run` produced records like *"executed: Isolated
C1 from the network"* and *"executed: Credentials reset for C1"* — for every
step whose risk bar the caller's supplied risk cleared, including the
irreversible credential reset at 0.9, with no approval and no connector. The
function's own docstring called it "deterministic and side-effect-free", which
was true: it performed nothing. It merely *said* it had, in a store the console
renders as an execution history.

This sat beside the response layer (`detection/response.py`), whose contract —
irreversible actions never automatic, disruptive ones only with approval — is
enforced by test. Two response paths with different safety semantics, and the
lax one is the one an operator's button reaches. It is also exactly where a
real connector would have been wired first.

### What ships now

`response/` is the single path through which any action is carried out:

- **Connectors** (`directory`, `network`, `endpoint`, `monitoring`) turn each
  catalogued action into the literal command — `Disable-ADAccount -Identity
  'U66@DOM1'`, a `New-NetFirewallRule` on the destination, an EDR isolate call
  — with its revert where one exists. Every command is reviewable to the
  character before anything is armed, and tested to the character.
- **Backends** are the only seam to the world. The default records the plan
  and performs nothing. `PowerShellBackend` exists, is constructed only on
  purpose, and refuses to spawn a process unless armed.
- **The executor** makes the plan's partition binding at the moment of
  execution: an approval-required action waits for an `Approval` naming that
  alert and that action; an irreversible action waits for one regardless of
  what any plan or caller says (the catalogue outranks the plan); the same
  dispatch is never carried out twice; every dispatch — including the ones
  that ran nothing — leaves a record with the command, the outcome, the
  approver and the revert.

`execute_playbook` now routes through it. A step's status is what the executor
reports: `dry_run` (planned, recorded, not performed — the default),
`pending_approval`, `failed`, or `executed` — and **the only way to produce the
word "executed" is a backend that ran the command.** The API request carries
`approved_actions` and an `approver` for the steps a person releases. The
console labels each step with its real status; planned and pending steps are
no longer counted as actions taken.

### What the executor caught on its first run

Routing the containment playbook through real connectors surfaced a semantic
hole the old code had papered over: `force_reauth` against a **host** has no
account to act on, so the old *"Forced re-authentication issued for C1"* meant
nothing. The connector now gives it a real meaning — log every interactive
session off that host — and states, on every session-invalidation command, the
on-premises limitation that issued Kerberos tickets stay valid until they
expire. That is what `force_reauth` can honestly do without a credential reset.

### Validation status, plainly

The command plans are correct by specification — the documented cmdlets and
API calls for each operation — and have **not** been run against a live
directory, because this environment has no lab domain. That is precisely why
the dry-run backend is the default and the executing one is opt-in. Open item
8 (a lab Active Directory) is what closes this.

---

## Finding 20 — The model does not memorise identity. It learned one campaign.

**Severity: revises the mechanism in Finding 14. The contamination conclusion
stands and is sharpened; the memorisation explanation is rejected.**

Finding 14 established that 99.8% of test PR-AUC comes from host 8426 and
offered the mechanism as per-node memory memorising the host. Reading the model
more carefully before testing that: `update()` writes only the user and
destination memories, and 8426 never appears as a destination, so its origin
memory row is the initial zeros at every event. That channel *cannot* carry
identity. And the users behind its attacks are not attack-only either — user 76
has 3,511 benign events.

So the question was put to the trained model directly: score the whole stream
once, and at every timestamp group score it again under interventions before
the single real update. All conditions see byte-identical memory trajectories
and differ only in what the scorer was allowed to read. The baseline reproduces
the committed cache to 5e-7, which validates the harness.

### Score-time ablation (test partition, 126 attacks, 121 from host 8426)

| Condition | Test PR-AUC | 95% CI | 8426 recall @alert | 8426 above gate | Benign FP/10k |
|---|---|---|---|---|---|
| baseline | 0.8210 | [0.759, 0.875] | 94.2% | 87.6% | 34.5 |
| origin memory zeroed | 0.5919 | [0.506, 0.674] | **94.2%** | **87.6%** | 822.8 |
| user memory zeroed | 0.7726 | [0.707, 0.831] | 93.4% | 85.1% | 40.0 |
| destination memory zeroed | 0.4688 | [0.382, 0.565] | 90.9% | 81.0% | 719.2 |
| **all memory zeroed** | 0.3894 | [0.309, 0.473] | **81.8%** | 67.8% | 969.8 |
| `src_host_historical_degree` → median | 0.6603 | [0.586, 0.731] | **95.0%** | 86.8% | 55.9 |
| `src_host_unique_dst_1h` → median | 0.7811 | [0.717, 0.843] | 89.3% | 74.4% | 18.8 |
| both of the above | 0.7360 | [0.667, 0.806] | 87.6% | 66.9% | 27.4 |
| destination-context features → median | 0.8235 | [0.763, 0.878] | 95.0% | 86.0% | 29.5 |
| all five entity-degree features → median | 0.6710 | [0.597, 0.746] | 78.5% | 54.5% | 16.0 |

Read the third column, not the first. PR-AUC collapses in the memory
conditions because *benign* scoring collapses — zeroing a channel makes every
ordinary event look never-seen, and false positives go from 35 to 800+ per
10k. What happens to the attacker is the question, and the attacker barely
moves:

- **Zeroing origin memory changes 8426's recall by exactly nothing** (94.2% →
  94.2%), as it must — the row was already zeros. Identity through that
  channel is not merely absent from the model's reasoning; it is absent from
  its inputs.
- **Neutralising `src_host_historical_degree`** — the feature Phase 1a flagged
  as the dominant separator (Cohen's d = 2.84) and my stated candidate for an
  identity proxy — leaves 8426 recall at **95.0%**. That hypothesis is
  rejected.
- **With every memory channel zeroed**, 82% of 8426's attacks still clear the
  alert threshold. With five entity-degree features neutralised at once, 79%
  still do.

No single channel, and no small group of them, is what the model reads.
Detection of this campaign is **distributed across the behavioural features
and robust to removing any of them**. That is what learned behaviour looks
like, not what a lookup looks like.

### So what did it learn?

One campaign. Host 8426 is the only host in the corpus that mounts a large,
fast fan-out — 303 training events reaching 184 distinct destinations under 51
harvested accounts, most of them novel pairs, from a host whose out-degree
climbs into the hundreds. Every one of the 27 features that separates its
attacks from benign traffic (novel pair, destination rarity, fan-out per hour,
inbound quietness of the target, cumulative degree) describes *that pattern*.
The model learned the pattern well and redundantly. It has seen exactly one
instance of it.

This is why the five attacks from other hosts are missed: Phase 1a showed they
do not exhibit the pattern (`is_new_pair = 0`, `pair_seen_before = 1`, fan-out
below the benign mean). And it is why Finding 21's synthetic campaigns — eight
hops, from ordinary workstations, at intervals from 15 seconds to an hour — are
detected 20% of the time: they are smaller and, mostly, slower than the one
pattern the model knows, and the model has no second example to generalise
from.

### What this changes in Finding 14

- **Stands:** the evaluation is contaminated. One host is one campaign is one
  pattern, and no number measured on it estimates performance on a different
  attacker. The 0.8210 → 0.0019 collapse is real.
- **Rejected:** the mechanism as stated — "a model with per-node memory can
  score well by memorising that host ID". This model does not. The
  `ENTITY_CONTAMINATION_WARNING` and `evaluation/generalisation.py` docstrings
  describe the *risk* correctly for the class of model and are kept; the claim
  that this checkpoint realises it is withdrawn.
- **Sharpened:** the remedy is not a regulariser against identity. It is a
  second attack pattern in training. Nothing in the architecture stops the
  model generalising; the corpus gives it nothing to generalise *from*.

The training-time counterpart (a memoryless variant trained from scratch under
the production recipe) is consistent with this: at epoch 10 of 16 it stands at
validation PR-AUC 0.777 against the production run's 0.805 at the same epoch —
memory contributes, but modestly, and the behavioural features carry most of
the detection. Final figures follow when the run completes.

---

*Addendum:* the training variants this finding queued are reported in
Finding 26 — without memory the model generalises across attackers (0.38
PR-AUC on the non-8426 test attacks against 0.002 with memory), at a
headline cost within run-to-run variance.

---

## Finding 21 — Against attackers it has not seen, the stack detects one campaign in five, and prevents almost nothing

**Severity: critical for any prevention claim. Measured, not estimated.**

The prevention instrument (`docs/PREVENTION_INSTRUMENT.md`) ran 100 campaigns —
two families × ten inter-hop intervals × five replicates, eight hops each —
from ordinary workstations with benign history, over a three-day synthetic
continuation of the corpus, with the feature engine and TGN memory warmed
through the validation boundary and the production composition doing the
scoring. This is the deployment condition: an attacker whose host has ordinary
history behind it.

| Operating point | Campaigns detected | Median first alert | Hops prevented (campaign) | Hops prevented (account) | Benign auto-actions / 10k |
|---|---|---|---|---|---|
| `noisy_or` (shipped) | **21 / 100** | hop 4 | 0.75% | 0.37% | 4.98 |
| `tgn_only` | 20 / 100 | hop 4 | 0.75% | 0.37% | 5.66 |

By family, `noisy_or`:

| Family | Detected | Median first alert | Prevented (campaign) | Prevented (account) |
|---|---|---|---|---|
| chain | 13 / 50 (26%) | hop 4 | **0.0%** | 0.0% |
| fan-out | 8 / 50 (16%) | hop 5 | 1.5% | 0.8% |

### Who detected what

Attributing each detected campaign to the rule floor (max risk exactly 0.60)
or to the model (above it):

| Family | Interval (s) | Detected | By the chain rule | By the model |
|---|---|---|---|---|
| chain | 15, 60 | 5 + 5 | **10** | 0 |
| chain | ≥ 120 | 3 / 40 | 0 | 0 (scored 0.33–0.60) |
| fan-out | all | 8 / 50 | 0 | 8 |

**Every detected chain was caught by the deterministic rule; the model detected
no chain by itself.** The model caught about one fast fan-out in five. The
chain rule fires at the attacker's fifth move — three pivot links must precede
the event — and cannot fire at all above 100 s between hops, since three
links then exceed its 300 s window (verified: fires at hop 4 for ≤ 100 s
intervals, never at ≥ 120 s).

### The evasion curve

| Seconds between hops | 15 | 60 | 120 | 240 | 300 | 360 | 600 | 900 | 1800 | 3600 |
|---|---|---|---|---|---|---|---|---|---|---|
| Detection rate | 60% | 60% | 10% | 20% | 10% | 30% | 10% | 0% | 10% | 0% |

A patient attacker who waits two minutes between moves walks past the rule;
beyond fifteen minutes essentially nothing fires. This is the same corpus
limitation as Finding 20 seen from the other side: the model learned one large,
fast fan-out and has no second pattern to generalise from.

### Why chains prevented is exactly zero, and what it costs to change

The chain rule floors risk at 0.60. The execution gate is 0.878 (and was 0.85).
So a chain the rule catches is *alerted* and never *acted on*: the rule exists
to catch what the model misses, and the gate then discards it. Pricing the
policy that raises the floor to the gate, on the same scored events under the
same gate:

| | Shipped (floor 0.60) | Floor at gate (0.878) |
|---|---|---|
| Chain hops prevented (campaign) | 0.0% | **2.8%** |
| Campaigns auto-actioned | 2 | 6 |
| Benign events auto-actioned | 51 | **51** |
| Benign users hit | 51 | **51** |

The policy is free in benign cost — benign chain-rule events never carry a
*high* attribution confidence, so they still do not clear `plan_for` — and
modest in benefit, for the same reason: only 4 of the 10 rule-caught chains
had high-confidence attribution at the hop that fired. The confidence
requirement, not the risk gate, is the binding constraint. That is a product
decision with a measured trade-off and belongs to the operator; the instrument
makes it a number rather than an argument.

### An error caught by the instrument's own determinism

The first comparison of these two policies showed benign auto-actions *falling*
from 55 to 51 when the floor rose — impossible, since a floor only raises
scores. Two in-process runs of the harness were byte-identical and two
cross-process runs matched to twelve decimals, so it was not nondeterminism.
It was that the "shipped" baseline had been run at 17:05 with `plan_for`'s old
0.85 default and the policy run at 17:53 after the gate moved to 0.878: two
variables changed, not one. The baseline was re-run under the current gate
before the table above was written. The harness's exact reproducibility is what
made the confound visible.

---

## Finding 22 — Four of six technique signatures do not fire on the behaviour they name

**Severity: critical for the console's ATT&CK badges. Measured for the first time.**

Six signatures had never been measured against a labelled instance of their
technique; their published "validation" was a benign firing rate. Each was
injected — twelve scenarios per behaviour, built from ATT&CK's description of
what the adversary *does*, with the rule's thresholds deliberately not
consulted — into a three-day warm synthetic continuation (102,375 benign
events, 24.8 alerts/10k, which is on budget), and measured three ways:

| Technique | Behaviour injected | Injected | Alerted | Detection recall | Attribution recall | Benign false attributions / 10k | Precision |
|---|---|---|---|---|---|---|---|
| T1110 | password guessing (12 attempts), spraying (15 accounts) | 436 | **0** | **0.0%** | 2.8% | 0.39 | 75.0% |
| T1087 | remote system enumeration, 24 novel hosts in minutes | 288 | 183 | 63.5% | 38.2% | 0.39 | 96.5% |
| T1078 | valid credential from a foreign workstation, small hours | 36 | 2 | 5.6% | 27.8% | 0.00 | 100% |
| T1550.003 | service tickets with no authentication, foreign account | 48 | 3 | 6.2% | **0.0%** | 0.00 | 0% |
| T1550.002 | NTLM from a Kerberos account, foreign workstation | 48 | 9 | 18.8% | **0.0%** | 0.00 | 0% |
| T1078.002 | machine account logging on interactively | 36 | 1 | 2.8% | 86.1% | **22.76** | **11.7%** |

*Detection recall*: injected events that alerted at all. *Attribution
recall*: named correctly at medium or high confidence. *Precision*: of
everything the engine called this technique, the share that was.

### What each row means

- **Brute force is not detected.** Not one of 436 guessing and spraying events
  crossed the alert threshold. The tactic engine names T1110 on 12 of them,
  but attribution has no path into the fused risk, so the product stays
  silent. The signature's failure-rate ramp is tuned for sustained rates a
  careful attacker never produces.
- **Discovery is the one that works** — 63.5% detected, 96.5% precise — but
  135 of 288 events were attributed to *another* technique (fan-out reads as
  lateral movement). Defensible, and wrong on the label half the time.
- **Valid-account abuse** is named on 10 events and alerts on 2. A correct
  label the operator never sees is not a detection.
- **Pass-the-ticket and pass-the-hash never attribute their own technique.**
  Both are self-gated on estate statistics (TGT coverage, Kerberos share)
  meant to suppress logging-gap false positives; on this estate the gate
  suppresses the technique instead. 11 and 9 events respectively were named
  as something else.
- **Machine-account misuse attributes 86% of its injections — and 233 benign
  events.** A "0.25% benign firing rate", which is what the project had
  published, sounds small until it is beside 31 true positives: the badge is
  wrong seven times in eight.

### Consequence

The console paints seven ATT&CK badges. One is validated with labels (T1021),
one works on injected behaviour (T1087, with the wrong name half the time),
and four are labels the engine produces for no measured reason. Until fixed or
retired, `/api/v1/tactics` should carry these numbers beside each signature —
which is what "honest ATT&CK dispositions" has to mean.

---

## Finding 23 — The live path could not run with the state it needs

**Severity: critical for the product. Found by running it; fixed.**

Starting the API with the warm state Finding 9 says a deployment must run with
— the feature engine and TGN memory backfilled over 543,615 events — and
streaming the console's own demo through `/api/v1/live/events` froze the
service: `/health` stopped answering within a minute. A thread dump showed the
event loop inside `copy.deepcopy` of the feature engine.

Every live batch deep-copied the entire engine and both entity dictionaries to
obtain rollback-on-failure, then swapped the copies in on success. Against a
cold engine that is milliseconds; against a warm one it is minutes. And
`live_events` was declared `async def`, so the copy ran *on the event loop*
and blocked every other request for its duration. The product's demo worked
only because the demo ran cold — the condition the product is documented as
being 46% worse in.

### The fix, and the invariant it keeps

The transactional guarantee matters: if the model refuses a batch after the
features were computed, the engine's rolling state and the model's memory would
disagree about what happened, permanently. It is kept, at a cost proportional
to the batch instead of the estate:

- `CausalFeatureEngine.checkpoint(events)` copies exactly the entries a batch
  can reach — its users, hosts and pairs, across every dict-shaped container
  the engine and its trackers hold, found by introspection so a container
  added later is covered without being listed — and `rollback()` restores or
  deletes them. Pinned by snapshot equality after rollback, not spot checks.
- `StableIdMap.mark()` / `rollback()` forget identifiers encoded since the
  mark; ids are assigned from the dict's length, so the rollback is a slice.
- `live_events` is now a plain `def`, run in the threadpool.

Same load, same warm state: `/health` and the response endpoints answer in
~100 ms where they had timed out at 20 s. Nine tests cover the checkpoint,
including "features must not outlive a refused batch" driven through the real
live engine with a refusing model.

---

## Finding 24 — The evaluated product and the deployed product were not the same product

**Severity: critical for every published number. Found by running the pipeline end to end; fixed, and now pinned by a check that runs the product from raw text to a responding API.**

Nothing in 650 passing tests exercised the pipeline as an operator runs it:
raw LANL text through `ingest`, `features`, `evaluate baselines`, `train`,
the scored cache, the evaluation report, `backfill`, the API process, the live
gateway, automatic response, a restart. `scripts/e2e_pipeline.py` now does
exactly that (`docs/END_TO_END.md`), each stage the product's own entry point
run as a subprocess, and finishes by streaming the run's own test partition
through the live gateway and comparing every channel of every event against
what the offline evaluation computed for the same event. The first run found
five defects. None was visible from unit tests, because each lived in the
seam between two components that were individually correct.

### 1. The offline corpus contained traffic the deployed path refuses

53.8% of LANL authentication events are local logons: source host equals
destination host. The offline ingest kept them; the live gateway and the
Windows collector refuse them ("source and destination hosts must resolve to
different entities"). So the model was trained on, and every rolling feature
of every other event was shaped by, traffic that can never reach it in
production — train/serve skew at the corpus level, invisible because the two
paths are never fed the same file.

Measured on the bounded 900,000-second window used for the end-to-end run:

| | Rows |
|---|---:|
| Raw rows read | 176,520,330 |
| Local logons (dropped) | 95,025,843 (53.8%) |
| Sampled out (stride 448) | 81,311,671 |
| Kept | 182,815 |
| Red-team events matched | 316 |
| Red-team events that were local logons | **0** |

No labelled attack is a local logon, so dropping them costs no positive.
`ingest auth` now drops them by default and records the count in its report;
`--keep-self-loops` reproduces corpora built before this change. The shipped
checkpoint and every published number were produced on the old corpus — the
figures stand as the evaluation of *that* model, but a retrained model on the
corrected corpus is open item 19.

### 2. The evaluation scored a pivot channel the product does not compute

`explicit_signals` takes a `chain_tracker`; without one it falls back to the
any-source test the module's own docstring says "fires on 47% of benign
traffic and should not be relied on". Four call sites assembled the signal
state by hand, and three of them disagreed with the product:

| Path | Pivot definition it used | Windowed |
|---|---|---|
| Live gateway (`api/live.py`) — **the product** | same-account chain, fan-out fallback | yes |
| Prevention instrument | same-account chain, fan-out fallback | yes |
| Scored cache → evaluation report, gate derivation | **any-source** | yes |
| Training pipeline → fused validation threshold | **any-source** | **no** |

Rebuilding the committed cache with one shared implementation
(`SignalTracker`, now the only way any path advances the signal state):

| | Any-source pivot (old fixture) | Product pivot (new fixture) |
|---|---:|---:|
| Rows whose `pivot` changed | — | 250,264 (46.0%) |
| Benign events at `pivot = 1.0` | 48.51% | **2.41%** |
| Attack events at `pivot = 1.0` | 76.89% | 76.89% |
| Noisy-OR validation PR-AUC | 0.9790 | 0.9792 |
| Noisy-OR test PR-AUC | 0.8041 [0.7397, 0.8664] | 0.8048 [0.7410, 0.8671] |
| Linear test PR-AUC | 0.5753 | 0.5773 |
| 25 FP/10k threshold derived on validation | 0.324207 | 0.324207 |
| Test operating point at the published 0.329195 | 513 alerts, 114 attacks | 513 alerts, 114 attacks |

The published figures barely move because the fitted pivot reliability is
0.05: the calibration had already learned that the any-source channel carried
nothing. That is the point — the numbers survived by luck of a weight, not
because the evaluation measured the product. The attacks' `pivot = 1.0` share
is unchanged because it comes from the fan-out term, not from chaining; the
corpus contains no chain the rule fires on (248 benign events flagged, 4.57
per 10k, zero attacks), consistent with Finding 13.

### 3. The execution gate was derived on a number the response layer never sees

`plan_for` compares the alert's fused risk — noisy-OR of the channels, raised
to the chain-rule floor. Finding 18 derived the gate on the raw model
probability. At the top of the ranking the two quantities order the same 251
validation events, so the 75% target was met by the same alerts; but the
threshold that expresses it differs, because a fused risk is bounded by
0.95 × probability:

| Derived on | Gate | Validation alerts / precision / lower bound | Test alerts | Test precision | Benign per 10k (val / test) |
|---|---:|---|---:|---|---|
| raw model probability (shipped until now) | 0.877729 | 251 / 80.5% / 75.1% | 198 | 53.5% [46.6%, 60.3%] | 5.22 / 7.94 |
| shipped gate *applied to* the fused risk (what production did) | 0.877729 | — | 187 | 56.2% [49.0%, 63.1%] | — |
| **fused risk with floor (now)** | **0.846394** | 251 / 80.5% / 75.1% | 201 | 53.2% [46.3%, 60.0%] | 5.22 / 8.11 |

`detection/gates.py` now records the quantity beside the constant and
`test_the_gate_matches_its_derivation` re-derives it with the product's own
`fuse_risk` and `apply_rule_floor`. Finding 21's policy table was priced at a
floor of 0.878; at 0.846 the trade is the same in kind and is not re-run here.

### 4. Two product defects on the path from "verified" to "restarted"

- **`dataset verify` destroyed its own provenance.** The default quick scan
  rewrote the manifest with quick-level entries, after which `train` refused
  the corpus for lacking a full scan. A quick verification now keeps a
  full-scan entry whose hash it has just confirmed unchanged.
- **`/api/v1/feature-state/save` persisted half the state.** It wrote the
  feature engine and not the model's node memory, so a restart restored
  features advanced to now against memory frozen at onboarding day — a state
  no run ever produced, on a product whose Findings 9 and 10 are about
  exactly this coupling. It now writes both halves under one lock and reports
  when no memory path is configured.

### 5. The default training recipe is not the one the shipped model used

`graphsentinel train tgn` reads `configs/model_tgn.yaml`; the shipped
checkpoint came from `configs/model_tgn_v3_high_accuracy.yaml`, which differs
in five settings (60-second time buckets, dropout, weight decay, the
positive-weight cap, corpus-specific split fractions) and trains an order of
magnitude faster. `docs/TRAINING_AND_PIPELINE.md` documented commands and
config files that do not exist. The end-to-end run uses the v3 recipe with
its own split and records both; the documentation now names the real
commands.

### What the check pins now

On the synthetic corpus (24,036 raw rows, 8,326 local logons, 36 red-team
events, two epochs on CPU), for the 2,357 events of the test partition
streamed through the live gateway against the offline cache of the same
events: novelty, burst, pivot, the model probability and the fused risk agree
with a maximum absolute difference of **0.0**; PR-AUC 0.8779 live and 0.8779
offline. Two things that were assumed are now measured: the inference session
advances memory per timestamp group on both paths, so request and block
boundaries do not change a probability; and the chronological split never
splits a timestamp group, so the backfilled state hands off cleanly to the
stream.

The real-corpus run is recorded below and in
`artifacts/e2e/lanl_900k/E2E_REPORT.md`.

### The real corpus, end to end

`artifacts/e2e/lanl_900k`: the first 900,000 seconds of LANL at stride 448,
the v3 training recipe with a 70/15/15 split, eight epochs on the RTX 3050,
70 minutes in total after the 35-minute ingest.

| Stage | Result |
|---|---|
| ingest | 176,520,330 raw rows → 182,815 events (95.0 M local logons dropped), 316 red-team; 11,779 hosts, 19,496 users |
| baselines | validation PR-AUC: logistic 0.9137, rule 0.3768, rarity 0.3314, isolation forest 0.2231 |
| train | split 127,970 / 27,422 / 27,423 events with 50 / 165 / 101 attacks; raw model validation PR-AUC 0.5366, fused 0.7638; **not promoted** (the logistic baseline is 0.377 better) — the gate did its job, and the check serves the retained candidate, recorded as such |
| report | test PR-AUC noisy-OR 0.6038 [0.5202, 0.6960], linear 0.6756 [0.5882, 0.7574], `tgn_only` 0.5656 [0.4800, 0.6601]; 25 FP/10k threshold 0.669315; the generalisation section flags host 8274 at 100% of test PR-AUC — Finding 14's shape on a different window |
| backfill | 155,392 events replayed; 22,088 entities with warm memory |
| serve | started warm and undegraded; 27,423 test events in 55 requests at 315 events/s; 85 alerts (31.0 per 10k), 55 of 101 attacks caught at 64.7% precision |
| agreement | novelty, burst, pivot: max delta 0.0; model probability 2.68e-7 (CUDA offline, CPU live); fused risk 2.51e-7; PR-AUC 0.603796 live vs 0.603798 offline |
| response | 349 dispatch records, 208 unattended dry-runs, 141 awaiting approval; one approval released; arming refused |
| restart | 85 alerts, 350 records, 140 pending intact; settled approval refused on replay; features and memory restored with the same coverage |

With fifty training positives from one early campaign the model does not beat
a logistic regression on the same features, and the promotion gate refuses
it. That is the right outcome for this window and it is not the point of the
check; the point is that every number the served product computed for
27,423 real events is the number the offline evaluation computed for them.

---

## Finding 25 — A novel-hop chain rule, allowed to act, prevents 18× more than the shipped configuration — and the shipped rule's published cost was a sampling artefact

**Severity: the largest change to what the product prevents, and a correction to Finding 13. Measured on the sampled corpus, on the prevention instrument, and — for the first time — on an unsampled day; the defaults follow the full-rate measurement, and the worst hour is bounded by construction.**

Finding 21 left prevention at 0.75% of attacker hops for two reasons that
were never measured against alternatives: the chain rule fired only at the
attacker's fifth move (four hops in 300 s), and its floor (0.60) sat below
the execution gate, so even a caught chain was alerted and never acted on.
`scripts/chain_rule_study.py` prices the design space — three or four hops,
windows from 300 s to an hour, counting any hop or only *novel* hops (moves
to a host the account has never reached; `is_new_pair` when this was
measured, the tracker's own success-only history since Finding 27, which
corrected the test twice and re-priced the shipped rule) — under two
policies: `alert_only` (raise to 0.60, the shipped behaviour) and
`unattended` (the tactic engine asserts T1021 at high confidence, because a
same-account multi-hop chain is lateral movement by definition, and the risk
is raised to the execution gate, so the session kill follows without a
person). Each cell is measured on the labelled corpus and on the prevention
instrument (100 campaigns from ordinary workstations, warm state, the
production composition, the TGN scored once and cached so the rule and the
policy are the only things that change).

### On the sampled corpus and the instrument

Unattended policy unless stated; the shipped configuration until now in the
first row.

| Rule | Policy | Sampled corpus benign/10k | Campaigns detected | Chains | First alert | Hops prevented | Benign session kills/10k | Users hit |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 4 hops / 300 s / any | alert_only (shipped until now) | 4.57 | 21 | 13/50 | hop 4 | **0.75%** | 5.46 | 56 |
| 4 hops / 300 s / any | unattended | 4.57 | 21 | 13/50 | hop 4 | 4.5% | 6.73 | 61 |
| 4 hops / 300 s / novel | unattended | 0.00 | 21 | 13/50 | hop 4 | 4.4% | 5.46 | 56 |
| 4 hops / 600 s / novel | unattended | 0.00 | 26 | 18/50 | hop 4 | 6.2% | 5.46 | 56 |
| **4 hops / 1,800 s / novel** | **unattended (now shipped)** | **0.06** | **44** | **36/50** | **hop 4** | **13.9%** | **6.15** | **58** |
| 3 hops / 300 s / novel | unattended | 0.00 | 26 | 18/50 | hop 3 | 8.1% | 5.46 | 56 |
| 3 hops / 600 s / novel | unattended | 0.00 | 36 | 28/50 | hop 3 | 13.1% | 5.56 | 57 |
| 3 hops / 1,800 s / novel | unattended | 0.26 | 49 | 41/50 | hop 3 | 20.8% | 6.54 | 59 |
| 3 hops / 1,800 s / any | unattended | 369 | 50 | 42/50 | hop 3 | 21.9% | **316.85** | 136 |
| 3 hops / 3,600 s / any | unattended | 713 | 54 | 46/50 | hop 3 | 24.9% | **669.03** | 187 |

"Benign session kills/10k" is the unattended action's false-positive rate on
the instrument; the model alone accounts for 5.46 (Finding 21's number) and
everything above it is the rule's price. Two things are visible already:
acting on the rule is what turns detection into prevention (under
`alert_only` every row prevents 0.75%, whatever the rule catches), and
novelty is what makes acting safe (the same three hops in 1,800 s cost 317
per 10,000 when any hop counts and 6.54 when only never-reached hosts
count, with the detection barely changed).

On that evidence the three-novel-hop rule looked like the choice. It is
not, and the reason is the most important thing this finding found.

### At full rate the sampled numbers do not survive — including Finding 13's

Every benign-cost figure this project had published for a chain rule was
measured on a corpus sampled at one event in several hundred. Sampling
thins every account's sequence, so almost no benign multi-hop pattern is
observable in it: a rule that needs four moves by one account inside five
minutes almost never sees four of that account's moves. An unsampled day
of LANL (7,263,653 events after local logons; `artifacts/e2e/fullrate_day1`)
replayed through the same rules, benign events flagged per 10,000 by hour
of the day (hour 0 is cold: the engine has no history at all):

| Rule | Hour 0 | Hour 2 | Hour 7 | Hour 12 | Hour 18 | Hours 20–23 | Users/hour, 20–23 | Whole day |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 hops / 300 s / any (Finding 13's "4.6 per 10k") | 947 | 986 | 1,540 | 695 | 693 | **759** | 2,529 | 855 |
| 4 hops / 300 s / novel | 253 | 21 | 317 | 17 | 0.4 | 2.7 | 4 | 62 |
| 4 hops / 600 s / novel | 293 | 24 | 446 | 21 | 1.8 | 3.8 | 5 | 85 |
| **4 hops / 1,800 s / novel** | 430 | 72 | 745 | 46 | 10 | **5.9** | 7 | 147 |
| 3 hops / 300 s / novel | 403 | 76 | 511 | 44 | 15 | 17.5 | 49 | 112 |
| 3 hops / 600 s / novel | 466 | 97 | 663 | 57 | 19 | 22.3 | 57 | 145 |
| 3 hops / 1,800 s / novel | 715 | 211 | 1,013 | 110 | 37 | 37.7 | 88 | 237 |

- **The rule shipped since Finding 13 flags 760 benign events per 10,000 at
  full rate, all day, 2,500 accounts an hour.** Its "4.6 per 10,000, within
  the 25 budget" was true of the sampled corpus and of nothing else. As an
  alert floor at 0.60 it would have flooded any full-rate deployment; the
  product never ran at full rate, which is why nobody saw it. Finding 13's
  conclusion — that a same-account chain is the right discriminator —
  stands; its cost table is withdrawn.
- **Novelty is what makes a chain rule usable at full rate**, by two orders
  of magnitude, and it *improves with history*: the share of benign events
  that are new account-host pairs falls from 13.7% in the cold first hour to
  0.4% by the last, and the novel rules fall with it (the any-hop rule does
  not fall at all). With weeks of history behind it, as a deployment must
  have (Findings 9 and 10), the steady-state rate is lower than the last
  hours of a cold day; how much lower is open item 21.
- **Three novel hops is too cheap a bar at full rate** — 18–38 per 10,000
  and 50–90 accounts an hour after a day of history; four novel hops in
  1,800 s is 5.9 per 10,000 and 7 accounts an hour, comparable with the
  model's own unattended rate, for 13.9% of hops prevented against the
  three-hop rule's 20.8%. That is the shipped default. (Both re-priced
  under the precise hop test in Finding 27: 0.23 and 0.09 per 10,000 in the
  same late hours, 21.5% and 14.6% of hops prevented; the default stands.) The three-hop rule
  remains one environment variable away for a deployment that has warmed
  with weeks of history and measured its own rate first
  (`scripts/chain_rule_hourly.py`).

### Bounded by construction

The full-rate numbers also say that *no* rate here is known well enough to
be the only thing between an alert and an automatic logout — the model's
5.46 per 10,000 is a sampled-density figure too. The response coordinator
therefore holds an unattended budget: at most 20 unattended disruptive
actions per sliding hour estate-wide, and one per account per hour, both
configurable; when the budget refuses, the action is recorded as awaiting
approval with the reason, exactly as an action the catalogue reserves for a
person. In the worst regime the product degrades to alert-only plus 20
re-login prompts an hour; in the measured regime the budget never binds
(the instrument's three days produced about one unattended action an hour).
The console shows the budget, what it has used, and what it has demoted.

### The price, stated plainly

On the instrument, for every 10,000 events the shipped configuration now
logs out 6.15 benign sessions instead of 5.46 — 0.69 more, every one an
account that walked into four hosts it had never touched inside half an
hour; over three days, two more users. On an unsampled cold day it would
log out up to 20 an hour — the budget's number — while the rule's own rate
falls from hundreds per 10,000 to single digits as the day's history
accumulates. The rule flags no labelled attack on the corpus (its attacks
are fan-out from a beachhead, not chains; Finding 13), and 0.06 per 10,000
of the sampled corpus's benign events.

### What this does not settle

- The steady-state full-rate cost with weeks of history (open item 21); one
  day's trend is a bound, not a measurement.
- The model's own unattended rate at full rate, for the same reason.
- An attacker who reuses hosts the account has legitimately reached defeats
  the novelty test by construction; the fan-out channels and the model are
  what remain for that attacker, and Finding 21's numbers for them stand.
- The synthetic campaigns are eight hops long; prevented fraction scales
  with campaign length, and a four-hop intrusion is over before the rule
  can fire.

### What shipped

`detection/policy.py`: `ChainRuleConfig` (hops, window, novelty) and
`ChainRulePolicy` (`alert_only`, `unattended`), both read from the
environment; the live engine builds the tracker from the rule and lets the
tactic engine assert T1021 only under the unattended policy; the detection
service raises to the policy's floor; the coordinator's `UnattendedBudget`
bounds the hour. Defaults: `4hops-1800s-novel` under `unattended`, 20 per
hour, one per account per hour. `ChainPivotTracker` also lost an
O(accounts) scan per event that made full-rate replay impossible. The
prevention instrument runs the same objects and its report names the rule
and policy it measured; the production report was regenerated under the
defaults and the previous one kept as `production_alert_only_4hops`.

---

## Finding 26 — Trained without memory, the model generalises across attackers; trained with it, it learns the one host

**Severity: high for the architecture. The paired comparison Finding 20 promised; three retrained variants on the full corpus, rescored through the same session as the shipped checkpoint.**

Finding 20 zeroed channels at *score* time and found the shipped model does
not read identity. The training-time question — what the model would have
learned without those channels at all — needed retraining, and Phase 1 had
three variants queued: a **control** (the shipped recipe, re-run), a
**memoryless** model (`use_memory=False`: the GRU memory is neither read nor
written; the model sees only the 27 causal features and the time encoding),
and **held-out-8426** (the shipped recipe with host 8426's 303 training
events given zero loss weight, leaving 13 training positives). Each ran 16
epochs on the RTX 3050 with the v3 recipe and was rescored over the corpus
with the scored-cache builder, so every number is the raw model probability
measured exactly as the shipped checkpoint's was
(`artifacts/experiments/phase1_variants`).

| Variant | Validation PR-AUC | Test PR-AUC | 95% CI | Test PR-AUC without host 8426 | Share of metric from 8426 | Mean score on the *other* test attacks | Benign FP/10k |
|---|---:|---:|---|---:|---:|---:|---:|
| shipped | 0.9798 | 0.8210 | [0.759, 0.875] | 0.0019 | 99.8% | 0.023 | 34.5 |
| control (same recipe, re-run) | 0.9742 | 0.7512 | [0.686, 0.813] | 0.0022 | 99.7% | 0.010 | 34.4 |
| **memoryless** | 0.9747 | 0.8020 | [0.740, 0.858] | **0.3808** | **52.5%** | **0.602** | 37.8 |
| held-out 8426 | 0.5747 | 0.1899 | [0.126, 0.272] | 0.0423 | 77.8% | 0.261 | 4.7 |

Paired on the same resampled test events: control − memoryless = −0.051
[−0.095, −0.010], significant; the memoryless model beats its own control.

### What it says

- **Memory is how the model learned the one host.** With memory the model's
  score on the five test attacks that are *not* host 8426 averages 0.01–0.02;
  without memory it averages 0.60, and the metric on those attacks goes from
  0.002 to 0.38. Node memory gives the network a per-entity state it can fit
  to one campaign's rhythm; deprived of it, the network has to explain the
  labels with behaviour — new pairs, fan-out, rate — and behaviour transfers
  to the attacks it never saw. This is the mechanism behind Finding 14, now
  shown from the training side: the contamination is not in the data alone,
  it is in what memory lets the model do with the data.
- **The headline barely changes.** 0.821 with memory, 0.802 without, on a
  test set where 121 of 126 attacks are the host both models find. The
  number this project has been careful never to quote alone is the one
  number that cannot distinguish the two models.
- **Run-to-run variance is 0.07 on the headline.** The control is the
  shipped recipe on the same data and lands at 0.751 against 0.821; their
  intervals overlap. Any single-run difference smaller than that is noise on
  this corpus, and Finding 12's paired-bootstrap discipline is the only
  reason the memoryless comparison can be called significant at all.
- **Without the one host there is nothing to learn from.** Thirteen
  positives train a model that reaches 0.19; the held-out variant is the
  cleanest statement yet that this corpus contains one campaign.

### What it does not say

The memoryless model's 0.38 on the other attacks is five events; the
interval on that figure is wide enough to hold most of the unit interval,
and the benign cost is 10% higher. It is a mechanism finding, not a
deployment recommendation. The deployment question — whether to ship
memoryless, or a mixture, once a second attack pattern exists in training —
is exactly what the second-pattern experiment (Finding 28) is for, and it
should be run in both configurations.

---

## Finding 27 — A system that stops at the session kill is hoping; the loop that verifies and escalates is what makes prevention hold

**Severity: the difference between an action and a prevention system. Built as a closed loop; the value of each part measured; the one "obvious" precision improvement measured and rejected; the rule's own hop test found imprecise twice by replaying the product against its demo attacker, corrected, and re-priced at full rate (26-fold cheaper, nothing lost).**

`force_reauth` is the only thing the product does to an account without a
person, and it is the containment most likely to fail: an on-premises
Kerberos ticket already issued stays valid until it expires, cached
credentials survive a logoff, and an attacker holding either keeps moving.
Every prevention figure in Findings 21 and 25 assumed the kill works. This
finding stops assuming.

### The loop

`response/incidents.py` and the coordinator now run one loop per account:

1. **Contain** — the alert's unattended action runs, under the budget, and
   the account is under observation for 1,800 s.
2. **Verify** — if inside that window the same account qualifies for an
   unattended action *again* (a second confident detection by the model or
   the chain rule — the same evidence that justified the first; a weaker
   follow-up alert does not count), the containment demonstrably did not
   hold.
3. **Escalate** — the system runs `lock_account` on its own authority:
   reversible, inside the hourly budget, once per account per window,
   recorded with the evidence (`authority: escalation`). It never reaches an
   irreversible action, whatever the configuration; the executor refuses.
4. **Revert** — the lock is lifted automatically after 7,200 s with the
   command's own revert unless an analyst keeps it, or the account moves
   again; an analyst can lift it at any time. The blast radius of a wrong
   escalation is one account for one window. The window was one hour until
   23 Sep 2026 and is now two: an hour is shorter than the inter-hop
   interval of the slow campaigns in the evasion curve, so a lock could
   expire while the attacker was still mid-campaign and merely waiting.

The loop runs on two clocks, and which one matters. The window is measured
on *event time* — the attacker's clock — so a replayed day that arrives in
seconds of wall time, or a batched hour that arrives in one call, escalates
exactly as a live stream would; the first version measured it on the wall
clock and would have escalated any two confident detections a replay
delivered inside thirty minutes, whatever their true spacing. The
auto-revert is scheduled on *wall time*, so a lock applied during a replay
is not lifted the moment it is applied. Eleven tests pin the loop, including
that a weak follow-up does not escalate, that the window bounds it on event
time, that an escalation cannot authorise `reset_credentials`, and that
keep and lift work over the API.

### What it is worth, measured

The instrument now models the kill's effectiveness: with probability *e*
the first unattended kill stops the campaign; otherwise the attacker keeps
moving and, with escalation on, the next hop that would itself qualify for
an unattended action inside the window triggers the lock, which stops the
campaign for certain. Shipped configuration (`4hops-1800s-novel`,
`unattended`), 100 campaigns, campaign semantics:

| Session kill works | Hops prevented, no escalation | With the loop | Campaigns escalated |
|---:|---:|---:|---:|
| 100% | 14.6% | 14.6% | 0 |
| 75% | 11.5% | 13.6% | 8 |
| 50% | 8.8% | 12.5% | 14 |
| 25% | 5.2% | 11.0% | 22 |
| 0% | 0.0% | 9.2% | 36 |

(Figures under the corrected rule and instrument described below; the first
measurement, under the rule as it was, read 13.9 / 12.9 / 11.8 / 10.8 / 9.0
with the same escalation counts.) When the kill always works the loop is
inert, which is the correct property of a verify step. As the kill weakens,
prevention without the loop falls linearly to nothing; with it, two thirds
of the value survives even a kill that never works, because a moving
attacker keeps producing the evidence that triggers the lock. The true effectiveness of a session kill against a
ticket-holding attacker on a given estate is not known and is the number a
deployment should measure first; the loop makes the answer matter less.

### The precision improvement that was measured and rejected

The obvious way to make the rule's automatic action "more precise" is to
demand corroboration: act unattended only when the chain rule fires *and*
the model already scored the event over the alert threshold — two
independent signals. It is implemented (`GRAPHSENTINEL_CHAIN_RULE_POLICY=corroborated`)
and it is not the default, because the instrument prices it:

| Policy | Campaigns detected | Chains | Hops prevented | Benign session kills/10k |
|---|---:|---:|---:|---:|
| alert_only | 45 | 36/50 | 0.8% | 5.46 |
| unattended (shipped) | 45 | 36/50 | 14.6% | 5.46 |
| corroborated | 10 | 1/50 | 0.8% | 5.46 |

(Under the corrected rule and instrument, `artifacts/prevention/chain_rule_study`;
the first measurement, under the rule as it was, read 44 / 36 / 13.9% / 6.15
for the shipped policy and 12 / 4 / 1.0% / 5.46 for corroboration.)
Corroboration removes 35 of the 36 chains the rule catches and saves
nothing: at the instrument's sampled density the rule's unattended action
costs no benign session kill beyond the model's own. The rule is valuable precisely because
it is independent of the model: Finding 21 showed the model detects no chain
on its own, so requiring its agreement hands the decision back to the
component that cannot make it. Precision here comes from the rule's own
novelty test and from the loop's verification step, not from asking two
detectors that see different things to agree.

### What shipped

`response/incidents.py` (`IncidentTracker`), the coordinator's loop (`tick`,
`keep_escalation`, `revert_escalation`, `incident_view`), `authority` on
every execution record, `revert_action` in the executor, three API endpoints
(`/api/v1/response/incidents`, `/keep`, `/revert`), the console's
Prevention Loop panel with keep/lift, the instrument's effectiveness model
(`loop` in every prevention report), and the `corroborated` policy as an
option. Defaults: escalation on, window 1,800 s, auto-revert 7,200 s. Also:
`ChainPivotTracker` owns its novelty history and answers the rule's strict
question through `is_chain_hop`; the instrument reserves each account's
destinations across campaigns; training writes its best state to disk as it
goes and finishes from it after a device fault (`interrupted` in the
report), because a transient CUBLAS failure at epoch 13 of 16 had discarded
the second-pattern run.

The precision fix that failed logons do not count as hops changed the
fixture's signal columns (`scripts/refresh_cache_signals.py`, sha
`e6ce1f09945a6b93`): `pivot` moved on 247 rows, `chain` from 248 flagged
events to none (the corpus's attacks are fan-out, and every benign chain the
old 300 s any-hop rule flagged fails the novel-hop test or leaned on a failed
logon), `novelty`, `burst` and `tgn` untouched. The regenerated evaluation
report moved by 0.0001 in one interval bound (noisy-OR test PR-AUC 0.8048
[0.7411, 0.8671]); every threshold, operating point and the execution gate
are unchanged.

### The rule's novelty test, corrected twice

Replaying the demo stream through the served product after the loop shipped
found the chain rule silent on the demo's own eight-hop attacker. The
attacker guesses a password once or twice before every hop. The rule's
"novel hop" test was `FeatureRecord.is_new_pair`, and the feature engine —
correctly, for the model's purposes — counts a failed attempt as a sighting
of the account-destination pair, so every successful hop that followed a
failure was "not new", no hop was ever novel, and the rule never fired. A
detector that an attacker defeats by failing first is not precise; it is
worse than the loose one. The tracker now judges novelty from its own
history of *successful* reaches (`ChainPivotTracker._reached_ever`), which
the failures never enter. `test_a_guessed_password_does_not_make_the_hop_familiar`
pins the attacker; the demo replay produces the kill at the attacker's fifth
move, the lock 24 s later at the sixth, and one further alert while the lock
holds.

Pricing the corrected tracker at full rate exposed the second imprecision.
The chain flag was `continues_chain`: the account has three novel hops behind
it inside the window and is moving on from a host it reached. That is true of
*every* event the account produces from a reached host for the rest of the
window — a service account that made three novel hops and then keeps
authenticating from those hosts to the servers it always uses is flagged on
each of them (135 events from one account in hour 23 of the full-rate day).
The rule's question is stricter: is *this event* the fourth novel hop — a
successful authentication, from a host the account reached, to a host it has
never successfully reached. `ChainPivotTracker.is_chain_hop` asks that;
`continues_chain` remains the pivot channel's looser question. On the
unsampled day (`scripts/chain_hop_strictness.py`, 7.26 M events, cold
start):

| Current event must be | Whole day | Hours 6–11 | Hours 12–17 | Hours 18–23 |
|---|---:|---:|---:|---:|
| anything (`continues_chain`, Finding 25's flag) | 114.4 /10k | 261.6 | 26.2 | 4.86 (28 account-hours) |
| a successful authentication | 113.7 | 259.8 | 26.2 | 4.86 |
| **a successful hop to a never-reached host (shipped)** | **4.30** | **9.91** | **0.95** | **0.09 (8 account-hours)** |

A 26-fold reduction in benign cost, with no loss on chains: a chain campaign
is by construction a walk into never-reached hosts, so its fourth novel hop
fires the strict test exactly when it fired the loose one. The first re-run
of the instrument lost one chain of 36, and the loss was the instrument's:
it compromises the same widely-used credential in 42 of its 100 campaigns,
and a later campaign on that account walked into hosts an earlier one had
already reached — not novel under a cumulative novelty test, and a violation
of the generator's own contract that every destination is new for the
account. `plan_campaign` now reserves each account's destinations across the
stream. Under the corrected rule and instrument: 45 of 100 campaigns
detected (36 of 50 chains, at the attacker's fourth move; 9 of 50 fan-outs),
**14.6% of hops prevented** (27.8% of chain hops), and the unattended action
runs on **5.46 benign events per 10,000** — the model's own rate: on the
instrument's three days at sampled density the rule adds no benign session
kill at all (it added 0.69 per 10,000 before the correction). On the sampled
corpus every variant of the rule flags exactly zero events — the corpus
cannot rank them, which is why the full-rate day is the only place a rule
change is priced (Finding 25). The test fixture is bit-identical under the corrected tracker
(sha `e6ce1f09945a6b93`), so no evaluation number moved. The reach history
the novelty test rests on is cumulative and, like the rest of the signal
state, not yet persisted with the warm snapshot (open item 20): after a
restart every host is novel again and the rule's first hours cost what the
cold day's first hours cost — 5–10 per 10,000 — inside the budget, until
the history rebuilds.

The whole design space was re-priced under the corrected tracker
(`artifacts/prevention/chain_rule_study`, `chain_rule_hourly_3.json`). On
the instrument every novel-hop rule now costs exactly the model's own 5.46
unattended actions per 10,000 — none adds a benign session kill — so the
choice between them is prevention against full-rate cost alone:
`3hops-1800s-novel` prevents 21.5% of hops (41 of 50 chains at the third
move) for 0.23 per 10,000 in the last six hours of the cold day and 7.9
over the whole of it; the shipped `4hops-1800s-novel` prevents 14.6% (36 of
50 at the fourth) for 0.09 and 4.3; `4hops-300s-novel` prevents 4.5% for
0.03 and 2.2. The default stands at four hops: precision first, and the
three-hop rule is one variable away for an estate that has measured its own
rate.

---

## Finding 28 — A second attack pattern in training makes the model a generator detector: near-perfect on the synthetic campaigns, half as good on the real one

**Severity: the experiment every prior finding asked for, and its answer is that the obvious fix does not ship. Two runs; the real sealed test decides.**

Findings 20, 21 and 26 all ended at the same wall: the corpus holds one
campaign, from one host, in one pattern, so the model cannot learn what
lateral movement is in general — only what that campaign looked like — and
the instrument's fan-out campaigns go undetected because nothing like them
was ever in training. The remedy proposed in each was to put a second
pattern in training. `scripts/train_second_pattern.py` does exactly that:
60 labelled campaigns (30 chains, 30 fan-outs, the full 15–3,600 s interval
grid, 480 events) from 60 ordinary workstations disjoint from the
instrument's, injected into the *training window only*; split boundaries
pinned to the shipped run's timestamps so the sealed test period is
unchanged and unseen; the v3 recipe on the RTX 3050; the result scored on
the real sealed test through the same cache builder as the shipped model
and run through the 100-campaign instrument, warm.

### Run 1 — early stopping took it at epoch 7

| | Shipped model | Trained with the second pattern |
|---|---:|---:|
| Training positives in the loss | 316 | 796 |
| Epochs / best epoch | 16 / 16 | 7 / 2 (patience 5) |
| Validation PR-AUC, noisy-OR (evaluation report) | 0.9792 | 0.9033 |
| **Real sealed test PR-AUC, noisy-OR** | **0.8048 [0.7411, 0.8671]** | **0.4030 [0.3179, 0.4905]** |
| Real sealed test PR-AUC, model only | 0.8210 [0.7639, 0.8784] | 0.4097 [0.3251, 0.4967] |
| Recall at the 25 FP/10k threshold, real test | 90.5% (518 alerts) | 56.4% (375 alerts) |
| Test contamination by host 8426 | 99.8% | 99.6% (0.4097 → 0.0015) |
| Instrument: campaigns detected | 45 / 100 | **94 / 100** |
| — chains, median first alert | 36 / 50 at hop 4 | 47 / 50 at hop 1 |
| — fan-outs, median first alert | 9 / 50 at hop 5 | 47 / 50 at hop 2 |
| — campaigns at 1,800 s / 3,600 s between hops | 1 / 0 of 10 each | 9 / 5 of 10 |
| Instrument: hops prevented (shipped rule, unattended) | 14.6% | 27.8% |
| Instrument: benign alerts / unattended kills per 10k | 30.8 / 5.46 | 39.8 / 0.49 |

Read one column and the experiment is a triumph: the model now sees both
families, fires at the attacker's first or second move, catches the slow
attackers that no window rule can, and does it with a tenth of the
unattended cost. Read the other and it is a regression that halves the
product's performance on the only real attack it has: sealed-test PR-AUC
from 0.80 to 0.40, recall at the operating budget from 90% to 56%.

Both columns are true, and together they say what the model learned. The
training campaigns and the instrument's campaigns come from the same
generator — the same behaviour sampler, the same destination weighting, the
same fixed inter-hop intervals — on different hosts and accounts. A model
that fires on hop 1 of a synthetic chain, before any movement has happened,
is recognising the generator's signature in a single event, not lateral
movement; and having spent its capacity on 480 events of that signature, it
scores the one real campaign worse than a model that never saw them. The
instrument, once its generator is in training, stops being an
unseen-attacker test and becomes a training-set test. Every instrument
number in Findings 21, 25 and 27 is an unseen-attacker number only for a
model that never trained on the generator; for this one they are not.

### Run 2 — without early stopping

Run 1's validation curve peaked at epoch 2 and drifted down; a run that
crashed at epoch 13 (the transient CUBLAS fault that motivated the training
recovery in Finding 27) had reached 0.876 at epoch 12 on a slightly
different injection. Undertraining could account for part of the real-test
collapse, so the same experiment was run with `--patience 16`, taking the
best of all sixteen epochs.

| | Run 1 (patience 5) | Run 2 (patience 16) |
|---|---:|---:|
| Epochs / best epoch | 7 / 2 | 16 / 12 |
| Validation PR-AUC, noisy-OR (evaluation report) | 0.9033 | 0.9293 |
| **Real sealed test PR-AUC, noisy-OR** | **0.4030 [0.3179, 0.4905]** | **0.5027 [0.4191, 0.5900]** |
| Real sealed test PR-AUC, model only | 0.4097 | 0.4937 [0.4080, 0.5821] |
| Recall at the 25 FP/10k threshold, real test | 56.4% (375 alerts) | 73.8% (569 alerts) |
| Test contamination by host 8426 | 99.6% | 100.0% (0.5027 → 0.0001) |
| Instrument: campaigns detected | 94 / 100 | 100 / 100 |
| — chains, median first alert | 47 / 50 at hop 1 | 50 / 50 at hop 1 |
| — fan-outs, median first alert | 47 / 50 at hop 2 | 50 / 50 at hop 1 |
| — campaigns at 1,800 s / 3,600 s between hops | 9 / 5 of 10 | 10 / 10 of 10 |
| Instrument: hops prevented (shipped rule, unattended) | 27.8% | 37.4% |
| Instrument: benign alerts / unattended kills per 10k | 39.8 / 0.49 | 31.5 / 4.98 |

Validation PR-AUC by epoch, run 2: 1: 0.740, 2: 0.806, 3: 0.799, 4: 0.751, 5: 0.735, 6: 0.731, 7: 0.732, 8: 0.723, 9: 0.786, 10: 0.734, 11: 0.771, 12: 0.817, 13: 0.735, 14: 0.774, 15: 0.741, 16: 0.724.

Sixteen epochs move both columns in the same direction as before, further.
The validation curve never settles — it oscillates between 0.72 and 0.82
with its best at epoch 12, against the shipped run's monotone climb to
0.98 — and the best epoch's model reaches 0.50 [0.42, 0.59] on the real
sealed test: better than run 1's 0.40, still far below the shipped model's
0.80 [0.74, 0.87], with intervals that do not touch. On the instrument it
is now perfect: 100 of 100 campaigns at the attacker's *first* hop, chains
and fan-outs alike, including every campaign at an hour between hops, with
the unattended cost back at the model's ordinary rate. Detecting a fan-out
at its first move — one event, from an ordinary workstation, to one new
host, before any fanning has happened — is not recall on lateral movement;
it is recall on the generator. Undertraining explained a quarter of the
real-test gap and none of the conclusion.

### What this settles

- **The mixture as constructed must not ship.** The real sealed test is the
  arbiter and it moved the wrong way in both runs. A second pattern helps
  only if it is a second *real* pattern, or synthetic movement whose
  generator is independent of the one that measures it.
- **The instrument and the training injection need different generators.**
  Until then the instrument cannot evaluate any model that trained on it.
  Real red-team traces (the OTRF captures that already run through
  `windows-json`, the corpus's own second red-team day if one is ever
  labelled) are the honest option; a second synthetic generator with its own
  timing, behaviour and destination model is the fallback. Open item 23.
- **The shipped checkpoint stays.** Its 0.80 is one campaign (Finding 14);
  its instrument numbers are the ones a deployment should expect from a
  model that has not seen the attacker's style, which is the case that
  matters.

Artefacts: `artifacts/experiments/second_pattern` (run 1) and
`artifacts/experiments/second_pattern_p16` (run 2), each with the injection
manifest, training report, scored cache, evaluation report and prevention
report; `scripts/train_second_pattern.py`.

---

## Finding 29 - the horizon that decided what to rank, not only what to keep (23 Sep 2026)

**Question.** A console sweep asked a simple question of the served product:
with 218 alerts on a replayed demo stream, how many suspicious paths does
`/api/v1/paths` hold? The answer was **zero**, and the Suspicious Paths
workspace had been empty for every batched deployment since the live gateway
was built.

**Where it was.** `StreamingPathTracker.preview` computes a cutoff of
`forward_window_seconds x max_hops` (9,000 s) behind the *last* event of the
request. That cutoff belongs to the carry-forward history: nothing older can
still be extended by a future request, so nothing older needs keeping. It was
also being applied to the set handed to the ranker. For a live stream whose
requests cover a few seconds those are the same set. For anything batched
they are not: the demo replays 25,038 events in requests of 2,000, each
spanning about 43,000 s of event time, so roughly four fifths of every
request was discarded before ranking - including events that formed complete
paths with their own neighbours inside the same request.

**Evidence it was the horizon and not the ranker.** The ranker, given the
three eligible edges of the demo's four-hop chain (risks 0.8464, 0.8464,
0.8464; C5554 -> C1137 -> C988 -> C4483), returns three paths immediately.
The same events, sent through the gateway, produced none.

**Fix.** Rank the whole request; keep the horizon for what is carried
forward. A cap (50,000 eligible events) confines the depth-first extension in
a pathological request to its most recent slice, which is the behaviour every
request had before. Re-replaying the demo yields 15 paths, the top one being
the ATK-002 pivot chain over five hosts at mean edge risk 0.846,
new-relationship ratio 1.000, pivot density 0.750.

**What it cost to not notice.** Path ranking is the product's only structural
detector - the one that does not depend on the model's probability - and it
was silently contributing nothing to any batched or replayed deployment. The
alert-level numbers in every report are unaffected (a ranked path is an
additional view, not an input to fusion), but the ranked-path evidence
attached to an alert was empty wherever this bit. Two smaller defects from
the same sweep: Escape closed two of the console's four drawers, and the
stream demo swallowed the gateway's 409 refusals instead of printing them.


**Addendum: the demo's identities, and what the demo actually shows.** The
same sweep found the demo stream named through the wrong dictionary. The
stream stores integer ids; the generator assigned them with
`id_maps_lanl_bounded`, the API named them with the serving dictionary
`id_maps_lanl_1m_cuda`, and an id means a different account in each (80 is
`U66@DOM1` in one, `C791$@DOM1` in the other). Every identity in the demo was
renamed. Detection kept working on the renamed stream -- the moves were still
internally consistent, and the renamed ATK-001 even produced the run's
highest alert -- which is why it went unnoticed; but the manifest's ground
truth no longer described the stream, and the model was being shown
identities whose warm history belonged to someone else. Named correctly, on a
fresh server, one replay: the chain-shaped attack (ATK-002) is caught by the
chain rule, locked by the loop and ranked as the only suspicious path; the
two fan-out attacks are missed. That is the product's measured shape -- the
chain rule is precise on chains and blind to fan-out by construction, and
the model catches few fan-out campaigns (9 of 50 on the instrument) -- now
visible in the demo instead of disguised by it.

---

## Finding 30 - on a second, independent dataset the ranking transfers and the threshold does not (24 Sep 2026)

**Question.** Every number before this one comes from the LANL corpus. Does the
shipped product -- LANL-trained checkpoint, LANL-calibrated threshold, no
retraining -- detect lateral movement in someone else's logs?

**Data.** OTRF Security-Datasets, `datasets/atomic/windows/lateral_movement/host`:
29 public recordings (16.9 MB zipped) of real Windows Security telemetry from a
small lab domain (`theshire.local`: WORKSTATION5, WORKSTATION6, WORKSTATION7 and
the domain controller MORDORDC), each capturing one adversary moving laterally
with a known tool -- Empire (PsExec, SMBExec, WMI, WMIC, DCOM, MSBuild,
PSRemoting, a service DLL hijack), Covenant (SharpSC, SharpWMI, DCOM, remote
copy, PSRemoting, WMI and DCOM DLL hijacks), Mimikatz Zerologon and a
PurpleSharp Active Directory playbook.

**Method.** Everything goes through the product's own code: `--format auto`
recognised every recording as Windows Security JSON, the Windows adapter read
it, and every event was scored by a served API
(`scripts/otrf_evaluate.py`) from the shipped warm state, on a separate
database. Ground truth is `data/raw/otrf/ground_truth.json`: one label per
recording, each justified by a quote from OTRF's own metadata (the attacker's
console transcript). An attack event authenticates from the attacker's
workstation into the host the attacker's command targets, as the named account
where one is named. Six recordings were excluded before scoring and are counted,
not guessed: no metadata (2), no target named (3), a different lab (1). In two
more the attack produced no authentication edge at all. That leaves **21
recordings, 77 attack events and 118 benign events**. Two clean runs produced
identical outcomes, risks and ranks for all 29 recordings.

**Result** (`scripts/otrf_summary.py`, `artifacts/otrf/`):

| | value |
|---|---|
| Recordings detected at the shipped threshold (0.3292) | **2 of 21** (PurpleSharp playbook 0.961; Empire WMIC backdoor 0.734) |
| Benign events alerted at that threshold | 13 of 118 |
| Attacker's event ranked first in its recording | 10 of 18 (chance: 6.31) |
| ROC-AUC, attack vs benign, pooled | **0.66** [0.56, 0.75] (bootstrap over recordings) |
| ROC-AUC within a recording, mean | 0.79 over 18 recordings |

**Reading.** There is real signal -- the interval on the pooled AUC stays above
0.5, and within one recording the attacker's logons usually outscore the lab's
ordinary traffic -- but it is weak, and the shipped operating point does not
travel: 19 of 21 single-hop attacks score between 0.01 and 0.27, under a
threshold calibrated on LANL's score distribution. The two recordings that were
caught are the two busiest (a multi-target WinRM, share-enumeration and brute
force playbook; a WMIC backdoor with repeated authentication), and they are
also where the benign alerts are. Three causes, each already documented on
LANL, compound here: every OTRF identity is out of the frozen dictionary, so
the model reasons from shared OOV memory (Finding 14 measured the entity-
disjoint gap); each recording is one hop, so the chain rule, the product's
precise unattended trigger, cannot fire by construction (it needs four); and
a threshold is a property of a score distribution, which moves between estates
(Finding 18 measured it moving between LANL days).

**What changes.** The claim "works on any authentication log" is true of
*reading* one and false of *alerting correctly on it out of the box*. The
product's guidance already says to warm up on an estate's own history and
re-derive the gate before arming; this is the measurement behind that
sentence, on data the project has never touched. Two identity defects surfaced
on the way and are fixed: Windows' IPv4-mapped IPv6 spelling
(`::ffff:172.18.39.5`) and every loopback spelling now fold to one host
(`ingestion/windows.canonical_host`); a host that appears by name in one event
and by IP in another is still two nodes, which no log-only resolver can fix
without inventing identity.

**Open.** Retrain on a second corpus and re-derive the threshold on its own
validation split; OTRF's recordings are too short (minutes each) to train on,
so that needs a larger public corpus or an estate's own logs.

---

## Harness errors that produced convincing wrong answers

**Two runs, two variables (Finding 21).** A policy comparison showed benign
auto-actions falling when a floor was raised. The runs had been made before
and after the execution gate changed; the harness's exact reproducibility is
what exposed it. Rule: a comparison is only valid when everything but the
variable under test is pinned, including defaults that changed between runs.

Recorded because both looked like findings.

**Batched window updates hid every intra-batch pivot.** The first tuning
harness updated the pivot window in 4,096-event batches. At this event rate a
batch spans ~10,000 seconds — far wider than the 1,800s window — so no pivot
inside a batch was ever visible, and a chain completing in 268 seconds produced
exactly zero pivots. The resulting "pivot has 0% recall" was initially a
property of the harness. It only became a real finding after the harness was
made strictly per-event and causal, and the number held.

**Bypassing checkpoint normalisation.** (Earlier in the project.) An
evaluation harness built batches directly from raw parquet columns and skipped
the `feature_center`/`feature_scale` normalisation stored in the checkpoint,
producing ROC-AUC 0.457 and the conclusion that the model was broken. Routing
the same events through `InferenceSession.preview()` restored correct
behaviour.

The general lesson is that a measurement disagreeing with expectation should
first be suspected of being a measurement bug. Both of these would have been
published as findings.

---

## Validation status

| Technique | Ground truth | Benign firing rate |
|---|---|---|
| T1021 Lateral Movement | **Yes** — 649 labelled events | 1.41% |
| T1110 Brute Force | No | 0.00% |
| T1087 Discovery | No | 2.53% |
| T1078 Valid Account Abuse | No | 28.61% |
| T1550.003 Kerberos Abuse | No | 8.51% |
| T1078.002 Machine Account Misuse | No | 0.25% |
| T1550.002 NTLM Downgrade | No | 0.00% |

Only T1021 has labels behind it. For the rest, firing rate describes
**noisiness, not correctness** — and `T1078` at 28.6% is a candidate for the
same treatment T1021 received, since a technique that fires on a quarter of
benign traffic is very unlikely to be right about all of it.

No per-class precision or recall is claimed for any unvalidated technique.
`describe_validation()` and `GET /api/v1/tactics` both report this distinction
so it cannot be lost downstream.

---

## Open work

1. ~~Isolate the training/serving skew~~ — done, Findings 9 and 10. It was
   never serving skew: one engine, cold state. 12 of 27 features never
   converge; restart discarded them entirely. Snapshot/restore now ships.
   **Remaining:** build the backfill tool that produces the onboarding
   snapshot from historical logs, and re-run Finding 8's comparison with a
   warm engine to confirm the gap closes.
2. ~~Recalibrate noisy-OR~~ — done and **shipped** (Findings 7 and 12). The
   blocker was Finding 8's claim that the TGN was broken online; verified
   false. Default operator is now noisy_or at threshold 0.329195.
3. ~~Tighten T1078~~ — done, Finding 5. 28.6% → 3.21%.
4. ~~Kerberos signature~~ — done, Finding 6. 8.5% → 2.04%.
5. ~~Rebuild the synthetic generator~~ — done, `simulation/` and
   `docs/PREVENTION_INSTRUMENT.md`. Benign traffic is resampled from measured
   behaviour; attacker hosts are ordinary workstations with benign history;
   campaigns carry ground truth in hops. Results: Findings 21 and 22.
6. ~~Split the `pivot` channel~~ — done, Finding 13. Set-membership is now a
   same-account chain rule; fan-out remains the continuous fallback.
7. **Audit for other dictionary-bound constants** (Finding 11). The tactic
   rules are fixed; anything else comparing a learned index to a literal has
   the same defect.
8. **Validate the Windows adapter against a live Security log.** It is tested
   against fixtures reproducing the exact EventData layout, but reading the
   real log needs elevation this session did not have — so it is
   correct-by-specification, not correct-by-observation.
9. ~~Build entity-disjoint evaluation into the harness~~ — done,
   `evaluation/generalisation.py`; emitted in every evaluation report as a
   measurement. Finding 20 then tested the mechanism directly: the model does
   not memorise identity, it learned one campaign.
10. ~~Re-derive the auto-execution gate~~ — done, `detection/gates.py` and
   Finding 18. Derived on validation, realised test precision and false-positive
   rate recorded beside it, re-derived by test. The deeper result: precision at
   a fixed gate is not stable across days; the false-positive floor is.
11. **Stop reporting ECE for this detector** (Finding 16). It is invariant to
   bin count at this prevalence and blind to the decision region. The threshold
   table is the measurement that should appear in operator-facing output.

12. ~~Let a rule-detected chain reach the unattended action, or decide not to~~
   — done, Finding 25. The rule now asserts T1021 at high confidence and
   raises the risk to the gate (`unattended` policy, the default); the whole
   design space was priced first, then re-priced at full rate. Prevented
   hops 0.75% → 13.9% for +0.69 benign session kills per 10,000 on the
   instrument, bounded by the coordinator's budget whatever the rate.
13. **A second attack pattern in training** (Finding 20). The model learned one
   campaign and detects 20% of campaigns that differ from it in size or speed.
   The generator can now produce labelled campaigns from ordinary hosts; the
   experiment is to train with them and re-measure on the held-out grid.
14. ~~Widen the chain window, or add a slow-chain rule~~ — done, Finding 25:
   the shipped window is 1,800 s (was 300 s), on novel hops. **Remaining:**
   nothing fires at an hour between hops; a per-account slow-walk rule over
   a day is the next candidate, and its benign cost must be measured at
   full rate, where Finding 25 showed the sampled corpus is worthless for
   pricing a chain rule.
15. **Fix or retire the signatures Finding 22 shows do not fire on their own
   technique.** A signature whose recall on ATT&CK-described behaviour is near
   zero is a label the console paints for no measured reason.
16. ~~Route every operator action through `response/`~~ — done. Every
   persisted alert is now dispatched automatically through the coordinator
   (`docs/AUTOMATIC_RESPONSE.md`); the playbook endpoint and the per-alert
   response endpoint share the executor. Deciding who may arm a backend
   remains a deployment decision.
17. **Let the tactic verdict reach the fused risk, or stop badging on it**
   (Finding 22). The engine names brute force on 12 events that never alert:
   attribution has no path into the score, so a correct label can be
   invisible. Either a confident attribution should contribute evidence to
   the fused risk (with its measured false-attribution rate as the cost), or
   badges should be shown only on alerted events.
18. **Re-examine the estate-level gates on the Kerberos signatures**
   (Finding 22). Pass-the-ticket and pass-the-hash never attribute their own
   technique on this estate because the logging-gap guards suppress them.
   Measure the guards' thresholds against the estate's real TGT coverage and
   Kerberos share rather than the assumed 50%.
19. **Retrain the production checkpoint on the corrected corpus** (Finding
   24). Every published number evaluates a model trained with 54% local
   logons the deployed path never sees. The pipeline now produces the
   corrected corpus by default; the shipped checkpoint, the fixture and the
   findings that cite them describe the old one until a full-corpus retrain
   replaces it. The end-to-end run on the bounded window is the template.
20. **Persist the windowed signal state with the warm snapshot** (Finding
   24). `SignalTracker` (the 300 s chain window and the 1,800 s
   recent-destination window) is rebuilt cold at start; it converges within
   thirty minutes of traffic, which the end-to-end check tolerates and
   measures. Saving it beside the feature snapshot would remove the only
   allowance the check makes.
21. **Measure the chain rule's benign cost at full rate with warm history**
   (Finding 25). One unsampled *cold* day is measured and the rate is still
   falling at its end; the steady state after weeks of history, across days
   of the week (Finding 18 showed the false-positive floor varies by day),
   is the number an operator should be given, and the model's own unattended
   rate needs the same measurement.
22. **Adapter validation against real exports** (`docs/DATA_SOURCES.md`).
   Six formats parse their documented samples and four carry the synthetic
   corpus through the whole pipeline; none has yet met a production export
   from its system. The OTRF Security-Datasets lateral-movement captures are
   the first public fixture to run through `windows-json`.
23. **An attack generator independent of the instrument's** (Finding 28).
   Training on the instrument's own generator makes the model a detector of
   that generator and halves its real-test performance; the instrument then
   measures the training set. A second pattern in training needs either real
   red-team traces or a synthetic generator with its own timing, behaviour
   and destination model, and the instrument must keep the one the model
   never saw.
