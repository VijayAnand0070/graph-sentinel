# GraphSentinel — Evaluation Report

Generated from GraphSentinel 0.9.0 on Python 3.13.5.

## Protocol

- Threshold derived on **validation** only, at a 25.0 per 10,000 false-positive budget
- Test partition scored **once**, with everything frozen
- 2,000 stratified bootstrap resamples, seed 1729
- Comparisons **paired** on identical resampled events
- Ties: positives ranked last within equal scores

## Partitions

| Partition | Events | Attacks | Prevalence |
|---|---|---|---|
| train | 333,551 | 316 | 0.0947% |
| validation | 94,072 | 207 | 0.2200% |
| test | 115,992 | 126 | 0.1086% |

## Detectors

| Detector | Threshold | Val PR-AUC | **Test PR-AUC (95% CI)** | Test ROC-AUC | FP/10k | Recall |
|---|---|---|---|---|---|---|
| `linear` | 0.3605 | 0.9061 | **0.5773** [0.4983, 0.6564] | 0.9694 | 33.4 | 0.8889 |
| `noisy_or` | 0.3242 | 0.9792 | **0.8048** [0.7411, 0.8671] | 0.9872 | 34.8 | 0.9048 |
| `tgn_only` | 0.2968 | 0.9798 | **0.8210** [0.7639, 0.8784] | 0.9990 | 34.6 | 0.9048 |

## Paired comparisons

| Comparison | Difference (95% CI) | Wins | Significant |
|---|---|---|---|
| noisy_or - linear | +0.2275 [+0.1725, +0.2863] | 100.0% | **yes** |
| tgn_only - noisy_or | +0.0162 [+0.0060, +0.0305] | 100.0% | **yes** |
| tgn_only - linear | +0.2437 [+0.1878, +0.3013] | 100.0% | **yes** |

## Entity-disjoint evaluation

Attacking entity: `src_host_id`. Scored on **`tgn_only`**, the best detector above.

**Attack-only entities in training:** `8426` (303 events), `8989` (3 events). An entity that never appears benign in training is a perfect separator, so a model with per-entity memory can score well on it without representing attack behaviour.

| Entity held out | Attacks removed | Attacks left | PR-AUC without | 95% CI | Lift | Cost |
|---|---|---|---|---|---|---|
| `8426` | 121 | 5 * | 0.0019 | [0.0017, 0.0037] | 44.8x | 99.8% |
| `11807` | 3 | 123 | 0.8395 | [0.7844, 0.8888] | 791.6x | -2.2% |
| `10002` | 2 | 124 | 0.8323 | [0.7721, 0.8843] | 778.5x | -1.4% |

`*` too few attacks remain to estimate the residual reliably.

> CONTAMINATED: entity 8426 accounts for 99.8% of test PR-AUC (0.8210 -> 0.0019). Absolute figures from this partition are not estimates of performance against an unseen attacker. Only 5 attacks remain after the holdout, which is below the 20 needed to estimate the residual reliably -- the collapse is established, its exact magnitude is not.

## Reading this

Best test PR-AUC: **`tgn_only`** at 0.8210.

> The test partition holds few attacks, so intervals are wide and point estimates must not be quoted alone. ROC-AUC is reported for comparability only: detectors differing by ~0.23 PR-AUC differ by ~0.03 ROC-AUC on this data.

### Entity contamination — read before quoting any number above

> These are relative comparisons, not field-performance estimates. The test partition's attacks originate almost entirely from one source host that carries zero benign events in training: one host, one campaign, one pattern. Holding it out collapses test PR-AUC from 0.8210 to 0.0019 [0.0017, 0.0038]. Ablation shows the shipped model did not memorise the host (Finding 20) -- it learned that campaign's behaviour and has no second example -- but the evaluation cannot tell the two apart, which is the point. Detector-vs-detector differences remain valid; no absolute number here should be quoted as expected performance against an unseen attacker. See docs/DETECTION_RESEARCH_FINDINGS.md, Findings 14 and 20.
