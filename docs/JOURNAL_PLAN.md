# Journal paper: what must be true before any number is published

Status 2026-09-28. Nothing below has been retrained yet; this is the plan and
the validity problems it answers.

## Facts established so far

1. **A linear model beats the TGN on the corrected corpus.** On the corrected
   LANL slice (local logons dropped; `artifacts/e2e/lanl_900k`, 182,815 events,
   101 test attacks), test PR-AUC: logistic regression on the 27 causal
   features **0.956** (ROC-AUC 0.999), TGN **0.681**, rule 0.548, rarity 0.288,
   isolation forest 0.244 (`metrics/baselines_v1.json`, `metrics/tgn_training.json`).
   The promotion gate refused the TGN. *Clarification (2026-09-30):* the 0.681 is
   `test_metrics` of the training pipeline, which is computed on `_fused_scores`
   (the linearly fused pipeline). The raw TGN probability on the same test
   partition is **0.566** [0.480, 0.660] (`docs/evaluation_report.json`,
   `tgn_only`; recomputed from `fusion_cache.parquet`, no tied scores), linear
   fusion 0.676, noisy-OR 0.604.
2. **LANL has four attacker hosts, and one is 94% of the labels.**
   `redteam.txt.gz`: 749 events; C17693 701, C22409 26, C19932 19, C18025 3.
   Per day: d1 10, d2 15, d5 21, d8 273, d12 209, d13 81, d14 35, d15 26, d26 26,
   d29 16 (others < 10). Host-level generalisation on LANL rests on 48 events.
3. **The stride-sampled corpus is a validity risk for every model.** The ingest
   keeps every red-team event and 1 in N benign events (N = 448 in the corrected
   slice). That inflates prevalence (so PR-AUC and precision are not field
   numbers), and features are computed on the sampled stream: attackers keep
   their complete history while benign users keep 1/N of theirs, so windowed
   counts and novelty differ between the classes partly *because of sampling*.
   The chain rule's cost was already shown to be ~100x off on the sampled
   corpus (Finding 25). Until E1 below is run, the 0.956 may be inflated.
4. **External data: the ranking transfers weakly, the threshold does not.**
   OTRF (Finding 30): 2 of 21 attacks at the shipped threshold; pooled ROC-AUC
   0.66 [0.56, 0.75].

## Experiments, in order

- **E1 - sampling-artefact test (run first).** Compute the 27 features at full
  rate for a window that holds attacks (days 8 and 12-13 hold 563 of the 749),
  and compare each model's ranking of the attack events among *all* events
  with its ranking on the stride-sampled features. If the gap is large, every
  sampled-corpus number in the project is an upper bound and says so.
- **E2 - valid corpus.** Features always at full rate; sample benign events
  only *after* feature computation (training efficiency); record the sampling
  weight; report prevalence-weighted precision / PR-AUC (benign weight = N)
  alongside ROC-AUC and false positives per 10k benign events.
- **E3 - models on identical inputs and split.** rule, rarity, isolation
  forest, logistic, gradient-boosted trees (new, the baseline a reviewer will
  ask for), TGN with 3 seeds; paired bootstrap on identical resamples; one
  chronological split plus per-attacker-host recall.
- **E4 - generalisation.** Hold out attacker hosts where the counts allow;
  OTRF zero-shot for every model, and adaptation with held-out folds (warm-up
  on the lab's own history; threshold re-derived on calibration recordings,
  tested on the others).
- **E5 - literature.** Position against Hopper, Euler and TGN-based
  lateral-movement detectors (protocol differences stated, not hidden).

## Compute on this laptop (RTX 3050 6 GB, 16 GB RAM)

Full-rate LANL is ~8 M events/day after local logons are dropped; reading
900,000 s of `auth.txt.gz` takes ~35 min; the v3 TGN recipe takes ~100 min per
run on ~545k events. Full-rate TGN training over weeks is out of reach; E1 and
E2 bound the model inputs at full rate and subsample only what enters training.
