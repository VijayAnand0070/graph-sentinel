# GraphSentinel — Training, Feature Contract & Pipeline

Companion to `docs/GraphSentinel-Training-and-Pipeline.pdf`. Every number here is read
from the artifacts committed alongside the checkpoint, not typed by hand.

| | |
|---|---|
| Model | `tgn-auth-causal-v1-bb20801e0b40` |
| Checkpoint | `artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt` |
| Checkpoint SHA-256 | `61b304b3a607b68e6eab6d0b7ce8f0e26fb38576317d7de01d0d2dc7e08875c4` |
| Entity dictionary | `artifacts/id_maps_lanl_1m_cuda` (sha `f1113022cbd0ed13…`) |
| Training report | `artifacts/metrics/tgn_lanl_545k_split_v3_training-candidate-c6912ac36724.json` |
| Baseline report | `artifacts/metrics/baselines_lanl_545k_split.json` |
| Parameters | 107,585 |

---

## 1. Headline result

> **Correction.** This document previously reported test PR-AUC **0.5789** as the
> model's performance. It is not. `_fused_scores` in the training pipeline runs the
> model's output through risk fusion *before* any metric is computed, so 0.5789
> measures the deployed **pipeline**. The baselines are scored raw — `fuse_risk`
> appears nowhere in `evaluation/experiments.py` — so a fused pipeline was being
> compared against unfused detectors.
>
> Reconstructing the published figure from the same model output plus the original
> linear fusion gives **0.5725**, within 0.0064 of 0.5789, which accounts for the
> difference. Both numbers are correct; they measure different things.

Primary metric is **PR-AUC**, not accuracy. At 0.109% prevalence, predicting "benign"
for everything scores 99.89% accuracy and detects nothing.

All figures below are **raw detector scores**, compared like for like.

> **Read this before quoting any number in this section.** The test partition's
> attacks originate almost entirely from a single source host that carries zero
> benign events in training, so a detector can score highly by memorising that
> host ID rather than by recognising attack behaviour. Holding that host out
> collapses test PR-AUC from **0.8210 to 0.0019** [0.0017, 0.0038] — 99.8% of
> the metric. The comparisons below remain valid as *relative* rankings, since
> every detector including the baselines has access to the same shortcut, but
> **none of these absolute values is an estimate of field performance against an
> unseen attacker.** This is a property of the corpus, not a defect in the
> implementation. See `DETECTION_RESEARCH_FINDINGS.md`, Finding 14.

| Detector | Test PR-AUC | 95% CI |
|---|---|---|
| **TGN (model)** | 0.8210 | [0.7639, 0.8784] |
| Logistic | 0.2463 | [0.1818, 0.3273] |
| Rule | 0.0706 | [0.0428, 0.1106] |
| Isolation Forest | 0.0406 | [0.0205, 0.0837] |
| Rarity | 0.0072 | [0.0050, 0.0124] |

All five detectors were re-run to produce these intervals, and the point estimates
reproduce the committed baseline report to floating-point precision (max deviation
2.8e-17). 2,000 stratified bootstrap resamples; the test partition holds only
**126 attacks**, so the intervals are wide and no point estimate should be quoted alone.

### Model against each baseline, paired

| Comparison | Difference | 95% CI | Significant |
|---|---|---|---|
| tgn - logistic | +0.5747 | [+0.4917, +0.6483] | **yes** |
| tgn - rule | +0.7505 | [+0.6887, +0.8026] | **yes** |
| tgn - isolation_forest | +0.7804 | [+0.7147, +0.8353] | **yes** |
| tgn - rarity | +0.8139 | [+0.7566, +0.8702] | **yes** |

Paired on identical resampled events, so the difference does not inherit the variance
of comparing two independent intervals. Every comparison is significant.

On validation logistic is competitive; on the sealed test partition it collapses to
0.2463 while the model holds at 0.8210 — **3.33× the best baseline**
(envelope **2.33×–4.83×**), not the 2.35×
previously stated, which divided a fused score by a raw one. The envelope is
deliberately conservative: worst-case model interval over best-case baseline interval
and the reverse, which is wider than a proper ratio interval.

The 3.33x margin is a real and significant result *on this corpus*, and it is
also the clearest illustration of the contamination above: the TGN's advantage
over the baselines comes substantially from having a node memory that can hold
a per-host representation, which is precisely the faculty that memorises the
attacker host. A ratio measured where that shortcut is unavailable would be
much smaller, and this corpus has too few off-host attacks (5) to estimate it.

### For the deployed pipeline, not the model

| Operator | Threshold | Test PR-AUC | 95% CI |
|---|---|---|---|
| `linear` (original) | 0.3613 | 0.5753 | [0.4940, 0.6542] |
| `noisy_or` (default) | 0.3242 | 0.8041 | [0.7391, 0.8663] |
| `tgn_only` | 0.2968 | 0.8210 | [0.7634, 0.8781] |

Fusion is retained although the raw model ranks best: it provides per-channel
attribution, graceful degradation without a checkpoint, and a place for deterministic
rules to raise a floor. That is a trade, not an accuracy improvement.

Read the ROC column with suspicion: logistic posts 0.9931 ROC-AUC with a 0.2463
PR-AUC. ROC-AUC is dominated by the 115,866 benign events and stays high while an
unusable number of false positives sit above the true ones.

### Why it was not auto-promoted — and why that was wrong

The gate is *"candidate beats the best declared baseline"* on **validation** PR-AUC.
As published it compared the model's **fused** score (0.9132) against the best
baseline's **raw** score (0.9163): improvement −0.003023, `eligible: false`.

Compared consistently — raw against raw — the model scores **0.9798** against the same
0.9163, an improvement of **+0.063534**. **The candidate would have passed.** It was
rejected by 0.003 on a comparison that cost it 0.067.

The gate now compares like with like and records both figures, since the fused score is
what the deployed pipeline produces and an operator needs both. The rejection in the
committed training report stands as a fact about that run, not a judgement about the
model.

---

## 2. Split — chronological and attack-aware

| Partition | Events | Attacks | Prevalence | Role |
|---|---|---|---|---|
| Train | 333,551 | 316 | 0.095% | fit weights |
| Validation | 94,072 | 207 | 0.220% | early stop + threshold |
| Test | 115,992 | 126 | 0.109% | sealed, scored once |

543,615 events, 649 red-team, 63,397 entities. Random splitting would leak the future
into the past; the cut is strictly chronological so each partition holds complete
campaigns.

---

## 3. TGN training

Each entity carries a **64-dim memory vector**. An event produces a 27-dim message;
elapsed time since the entity was last seen is encoded through a **harmonic time
encoder** into 16 dims, so "3 seconds later" and "3 days later" are genuinely different
inputs. Message + both endpoint memories + time encoding feed a 96-unit hidden layer
that emits the risk logit; a **GRU** writes the updated memory back.

> **Score-before-update.** The model scores an event using memory as it stood *before*
> that event, then writes the update. Reversing those two lines would let the network
> see the event it is predicting. Enforced in `TemporalGraphNetwork.step()`, asserted by
> a regression test.

| | | | |
|---|---|---|---|
| memory_dim | 64 | epochs | 16 |
| time_dim | 16 | patience | 5 |
| hidden_dim | 96 | learning_rate | 0.001 |
| message_dim | 27 | weight_decay | 0.01 |
| dropout | 0.15 | positive_weight_cap | 120.0 |
| num_nodes | 63,397 | seed | 1729 |
| oov_user_buckets | 4,096 | time_bucket_seconds | 60 |
| oov_host_buckets | 16,384 | FP/10k budget | 25 |

Trained on **CUDA**. Validation PR-AUC rose from 0.675 to 0.913 over the 16 epochs, with
small dips at epochs 4, 7 and 9; the best epoch is the last, so early stopping (patience 5)
never triggered and the model had not plateaued when the budget ran out.

`time_bucket_seconds=60` batches events in 60-second groups instead of one batch per
distinct timestamp: a measured **20.7× training and 16.9× inference speedup**, with the
score-before-update guarantee intact (within a bucket, memory is still read before any
write).

**A device fault does not lose the run.** The best state so far is written to
`<checkpoint>.best-so-far` on the CPU the moment it is reached. If a later
epoch raises — a transient `CUBLAS_STATUS_EXECUTION_FAILED` on the RTX 3050
once discarded twelve epochs of a two-hour run — training ends from that
state, finishes validation, threshold selection and the sealed test on the
CPU with a fresh model, publishes the checkpoint as usual, and records
`interrupted: "epoch 13 raised RuntimeError: …"` in the report; a report
without that field ran every epoch it lists. A fault before any epoch has
completed is still fatal. The `.best-so-far` file is removed once the
checkpoint is published.

### Results

Two different things, kept apart. The **pipeline** column is what the committed training
report records (model output after linear fusion). The **model** column is the raw model,
which is what the baseline comparison in section 1 uses.

| Metric | Pipeline (val) | Pipeline (test) | Model (val) | Model (test) |
|---|---|---|---|---|
| PR-AUC | 0.9132 | 0.5789 | **0.9798** | **0.8210** |
| ROC-AUC | 0.9928 | 0.9515 | — | 0.9990 |
| Brier | 0.0265 | 0.0275 | — | — |
| Precision@10 | 1.00 | 1.00 | — | — |
| Recall@1000 | 0.986 | 0.897 | — | — |
| FP per 10k | 16.7 | 23.1 | — | 34.6 |

The pipeline figures were produced at threshold **0.4543**, chosen on validation as the
lowest value keeping false positives inside the 25-per-10,000 budget. That threshold
belongs to the **linear** operator; the current default (`noisy_or`) carries its own
calibrated threshold of 0.3242, and pairing an operator with another's threshold silently
changes the alert rate. On test, the ten highest-risk events are all
genuine attacks, and 89.7% of attacks appear in the top 1,000 of 115,992 events — a
99.1% reduction in what an analyst must read.

---

## 4. The 27-feature contract

Computed in `src/graphsentinel/features/causal.py`, frozen as
`feature_contract_sha256`. Every feature derives from an event's **past only**, through
a rolling window — no aggregate may include the event being scored or anything after it.

**Event attributes** — what the authentication was
1. `success` — did it succeed
2. `auth_type_id` — Kerberos / NTLM / negotiate
3. `logon_type_id` — network / interactive / service / batch
4. `orientation_id` — LogOn / LogOff / TGS / TGT

**Timing** — when, and how long since last time
5. `hour_sin` — hour on a circle, so 23:00 and 00:00 are adjacent
6. `hour_cos` — second half of that encoding
7. `delta_user_log` — log seconds since this user last authenticated anywhere
8. `delta_pair_log` — log seconds since this exact user-host pair last appeared

**Relationship novelty** — has this pairing been seen
9. `user_seen_before`
10. `pair_seen_before`
11. `is_new_pair` — first time this user reached this host; the strongest single
    lateral-movement signal in the set
12. `pair_frequency_1h`
13. `pair_rarity` — `1/sqrt(pair_total + 1)`

**Fan-out** — is the account spreading
14. `user_unique_dst_5m`
15. `user_unique_dst_1h`
16. `user_unique_dst_24h`
17. `user_auth_rate_5m`
20. `user_new_dst_ratio_1h` — share of this hour's destinations that were new;
    separates a busy admin from one reaching new ground

**Failure patterns**
18. `user_failure_rate_15m`
19. `failures_before_success_15m` — the signature of guessing that finally landed

**Host-side view**
21. `src_host_unique_dst_1h`
22. `dst_inbound_users_1h`
23. `destination_novelty`

**Graph structure**
24. `user_historical_degree`
25. `src_host_historical_degree`
26. `dst_historical_degree` — a low-degree host suddenly receiving traffic is a
    different story from a domain controller doing so

**Composite**
27. `rare_logon_score` — unusual logon type × unusual hour

All four baselines are fit on these identical 27 columns, which makes the comparison a
like-for-like test of the architecture rather than of feature engineering.

---

## 5. The exact pipeline

| # | Stage | Module | Artifact |
|---|---|---|---|
| 1 | Ingest (labels, entity dictionary, local logons dropped) | `ingestion/auth.py`, `ingestion/id_map.py` | `interim/*.parquet`, `id_maps/*.json`, ingestion report |
| 2 | Causal features | `features/causal.py` | `features/*.parquet`, feature report with contract hash |
| 3 | Split | `evaluation/splits.py` | in the baseline and training reports |
| 4 | Baselines | `models/baselines.py`, `evaluation/experiments.py` | `baselines_*.json` |
| 5 | TGN training and promotion gate | `models/training.py`, `models/training_pipeline.py` | candidate checkpoint, training report |
| 6 | Scored cache and evaluation report | `scripts/build_scored_cache.py`, `evaluation/report.py` | `fusion_cache.parquet`, `evaluation_report.json` |
| 7 | Warm state | `onboarding/backfill.py` | `feature_state.json.gz`, `tgn_memory.npz` |
| 8 | Serving | `models/serving.py` + `api/` | live alerts, automatic response |

The commands, as the CLI actually takes them (the training recipe is chosen
through `GRAPHSENTINEL_MODEL_CONFIG`; the shipped checkpoint used
`configs/model_tgn_v3_high_accuracy.yaml`, not the package default):

```bash
python -m graphsentinel ingest auth --output data/interim --id-maps artifacts/id_maps     --report artifacts/reports/ingestion_auth.json --sample-stride 448 --end-timestamp 900000
python -m graphsentinel features build --input data/interim --output data/processed/features_v1     --report artifacts/reports/features_v1.json
python -m graphsentinel evaluate baselines --input data/processed/features_v1     --feature-report artifacts/reports/features_v1.json --output artifacts/metrics/baselines_v1.json
GRAPHSENTINEL_MODEL_CONFIG=configs/model_tgn_v3_high_accuracy.yaml python -m graphsentinel train tgn --input data/processed/features_v1     --feature-report artifacts/reports/features_v1.json --id-maps artifacts/id_maps     --checkpoint artifacts/models/tgn-production.pt --report artifacts/metrics/tgn_training.json     --baseline-report artifacts/metrics/baselines_v1.json --device cuda
python scripts/build_scored_cache.py --data data/processed/features_v1     --checkpoint artifacts/models/tgn-production.pt --report artifacts/metrics/tgn_training.json     --out artifacts/fusion_cache.parquet
python -m graphsentinel evaluation-report --cache artifacts/fusion_cache.parquet --output docs
python -m graphsentinel backfill --input data/processed/features_v1 --output artifacts/state     --checkpoint artifacts/models/tgn-production.pt
python -m graphsentinel.api.run --port 8060
```

`scripts/e2e_pipeline.py` runs exactly this sequence and asserts each stage
(`END_TO_END.md`).

Seed 1729 throughout. Four independent SHA-256 digests — dataset, feature contract,
entity dictionary, training run — so any number here can be re-derived or falsified.

---

## 6. Risk scoring at serve time

The TGN probability is **not** the alert score. It is one of four components fused by an
explicit weighted formula, chosen over a learned fusion head so every alert decomposes
into terms an analyst can read and challenge:

```
risk = 0.55 · tgn_probability
     + 0.20 · pair_novelty     # first time this user reached this host?
     + 0.15 · burst_rate       # auth volume vs. this entity's own norm
     + 0.10 · pivot_depth      # hops from the entity's usual neighbourhood
```

**Attributable** — each term's contribution is shown per alert.
**Degradable** — without a checkpoint the same formula runs with the TGN term
redistributed; a response header states which mode produced the score.
**Auditable** — a weight changes by policy in seconds; a learned head would need
retraining.

> **Training/serving skew.** The checkpoint stores `feature_center` and `feature_scale`,
> and `InferenceSession` applies them before every forward pass. Verified the hard way:
> a harness that built batches from raw parquet columns and bypassed that normalisation
> produced ROC-AUC 0.457 and made the model look broken. Routing the same events through
> `InferenceSession.preview()` restored correct behaviour.

---

## 7. Response — what can actually stop the attack

Three graduated playbooks (`GET /api/v1/playbooks`), matched to confidence rather than
to a single alarm. At this prevalence, auto-isolating on every alert would disrupt more
legitimate work than attacks.

| Playbook | When | Actions, in order |
|---|---|---|
| `monitoring` | Low confidence. Watch, don't act. | `increase_monitoring` → `notify_soc` |
| `investigation` | Moderate. Gather evidence without disrupting the user. | + `force_reauth` |
| `containment` | Confirmed compromise. | + `block_network_path` → `isolate_host` → `reset_credentials` |

Cheap, reversible actions come first. `force_reauth` is the first action an attacker
feels — a stolen ticket stops working while a legitimate user sees one extra prompt.
Only at confirmed compromise does it reach `isolate_host`, which stops lateral movement
outright but also stops whatever real work that host was doing.

**Why early detection is worth so much.** Lateral movement is a chain; each hop depends
on the one before. Breaking any single link stops everything downstream. In the capture
analysed here the attacker traversed `C3034 → C1020 → C209 → C1139 → C5554 → C1137` in
268 seconds. A `force_reauth` after the second hop would have ended the campaign four
hosts early.

**Preventive controls the feature set implies.** Several features are high-signal
precisely because the behaviour should be rare, which points at controls worth having
regardless of any model:

- `is_new_pair`, `destination_novelty` → **network segmentation**, so most user-host
  pairs are impossible rather than merely unusual
- `failures_before_success_15m` → **lockout thresholds and MFA**, turning a successful
  guess into a blocked one
- `user_unique_dst_5m` → **rate limits** on authentication fan-out
- `rare_logon_score` → **restrict interactive logons** on servers

---

## 8. Known limitation (measured, not theoretical)

Replaying the labelled chain above through the deployed scorer:

| hop | risk |
|---|---|
| C3034 → C1020 | 0.0015 |
| C1020 → C209 | 0.1202 |
| C209 → C1139 | 0.1354 |
| C1139 → C5554 | 0.1479 |
| C5554 → C1137 | 0.1576 |

Against a decision threshold of 0.4543. **On the live path this chain is missed**, and
`/api/v1/paths` correctly reports no suspicious path. The `pivot` signal fires on four
of five hops, but the TGN term carries 0.55 of the fusion weight and scores these hops
near zero.

The path ranker is not at fault — replaying the same stream with the pivot signal
weighted up yields 65 paths, including red-team chains. This points at the **fusion
weighting on the online feature engine**, not the model architecture, and is the
clearest next piece of work.
