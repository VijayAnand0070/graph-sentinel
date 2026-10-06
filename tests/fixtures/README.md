# Test fixtures

## `fusion_cache.parquet` (9.2 MB)

Every fusion input, scored once per event over the full labelled LANL corpus.
It is the single source behind three things that must not drift apart:

| Consumer | What it takes from the cache |
|---|---|
| `tests/test_generalisation.py::test_the_known_corpus_result_is_reproduced` | pins Finding 14 — one host accounts for 99.8% of test PR-AUC |
| `tests/test_gates.py::test_the_gate_matches_its_derivation` | re-derives the auto-execution gate (`detection/gates.py`) on the fused risk with the chain-rule floor |
| `python -m graphsentinel evaluation-report --cache tests/fixtures/fusion_cache.parquet` | regenerates `docs/EVALUATION_REPORT.md` and `docs/evaluation_report.json` |
| research studies in `docs/DETECTION_RESEARCH_FINDINGS.md` (Findings 7, 12–16, 18, 24) | every calibration, threshold and holdout number |

Because the committed evaluation report and the regression test read the same
file, a reader who doubts a figure in the report can re-derive it, and the test
will fail if a change moves it.

### Schema

543,615 rows, chronological. One row per authentication event.

| Column | Meaning |
|---|---|
| `idx` | position in the chronological replay; partitions are contiguous ranges of it |
| `event_id`, `timestamp` | from the corpus |
| `label` | 1 for a red-team event, 0 otherwise (649 positives) |
| `src_host_id`, `dst_host_id`, `src_user_id` | learned dictionary indices from `artifacts/id_maps_lanl_1m_cuda` |
| `tgn` | model probability, scored **before** the event updates memory |
| `novelty`, `burst`, `pivot` | explicit signals from `detection/signals.py`, advanced per timestamp group by `SignalTracker` — the same object the live gateway advances, so `pivot` is the same-account chain / fan-out channel the product computes (not the any-source test the first cache scored; Finding 24) |
| `chain` | whether the shipped chain rule fired on the event (`4hops-1800s-novel`, successful hops only; zero events on this corpus — its attacks are fan-out, not chains); the rule floor is applied by consumers, not stored. `scripts/refresh_cache_signals.py` recomputes the signal columns in seconds when the rule changes, leaving `tgn` untouched |
| `partition` | `train` (333,551 / 316 attacks), `validation` (94,072 / 207), `test` (115,992 / 126) |

`corroboration` is absent: it is zero in the offline path and the report holds
it at zero to stay faithful to deployment.

### Provenance

| | |
|---|---|
| Checkpoint | `artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt` (model `tgn-auth-causal-v1-bb20801e0b40`) |
| Entity dictionary | `artifacts/id_maps_lanl_1m_cuda` — bound by hash; `auth_id_map_sha256` of that directory is `f1113022cbd0ed13…`, matching the checkpoint's `entity_dictionary_sha256` |
| Split indices | `artifacts/metrics/tgn_lanl_545k_split_v3_training-candidate-c6912ac36724.json` |
| Features | `data/processed/features_lanl_545k_split` |
| Builder | `scripts/build_scored_cache.py` |
| SHA-256 of this file (first 16) | `e6ce1f09945a6b93` (2026-09-19, signal columns refreshed under the shipped rule; earlier: `38e392be9525f23b`, any-source pivot: `ef39086364c99a54`) |

The dictionary binding matters: `id_maps_lanl_bounded` hashes to `d0265931…` and
does **not** match. Scoring through the wrong dictionary silently remaps every
entity and was an earlier harness error in this project.

Scoring is strictly chronological with score-before-update, through
`InferenceSession` so the checkpoint's stored feature normalisation applies. The
TGN forward pass is submitted in blocks of at least 4,096 events that never
split a timestamp group; inside the session memory advances group by group, so
block boundaries do not change a probability (the end-to-end check pins this:
`docs/END_TO_END.md`). The explicit signals advance **per timestamp group**
through `SignalTracker`, exactly as the live gateway advances them; a per-batch
update would hide every intra-batch pivot, a mistake made once and recorded
under "Harness errors" in the research findings.

### Regenerating

```bash
python scripts/build_scored_cache.py
```

Takes ~23 minutes on CPU (29 minutes limited to four threads). Verified
2026-09-17 by rebuilding from scratch and comparing column by column, and
again 2026-09-18 when the pivot channel was changed to the product's
definition (Finding 24):

| Column group | Reproduction (2026-09-18 rebuild against the previous fixture) |
|---|---|
| `idx`, `event_id`, `timestamp`, `label`, entity ids, `partition` | bit-identical |
| `novelty`, `burst` | bit-identical |
| `pivot` | **46.0% of rows differ by design**: benign events at `pivot = 1.0` fall from 48.51% to 2.41%; attack events unchanged at 76.89% (their 1.0 comes from the fan-out term) |
| `chain` | new; 248 benign events flagged (4.57 per 10k), no attack |
| `tgn` | max abs difference **7.45e-7** — torch CPU floating-point nondeterminism, not a logic difference |
| published fused figures | noisy-OR test PR-AUC 0.8041 → 0.8048, linear 0.5753 → 0.5773, `tgn_only` unchanged; the 25 FP/10k threshold derived on validation is unchanged at 0.324207 and the test operating point is identical (518 alerts, 114 attacks) |
| the execution gate | re-derived on the fused risk with the floor, which is what the product compares: 0.877729 on the raw probability → 0.846394; same 251 validation alerts at 80.5% precision |

The 2026-09-19 refresh (`scripts/refresh_cache_signals.py`, Finding 27)
recomputed only the signal columns, under the shipped rule and with failed
logons no longer counting as hops:

| Column | 2026-09-19 refresh against the 2026-09-18 fixture |
|---|---|
| `novelty`, `burst` | bit-identical |
| `pivot` | 247 rows changed (the chain term of the channel no longer counts failed hops; max change 1.0) |
| `chain` | 248 flagged → **0**: the corpus's attacks are fan-out, and every benign chain the 300 s any-hop rule flagged fails the novel-hop test or leaned on a failed logon |
| `tgn` | untouched |
| published fused figures | noisy-OR test PR-AUC 0.8048 [0.7411, 0.8671] (lower bound moved by 0.0001), linear 0.5773 unchanged, `tgn_only` unchanged; thresholds and the test operating point unchanged |
| the execution gate | unchanged at 0.846394; same 251 validation alerts at 80.5% |

The two later corrections to the rule the same day (novelty from the
tracker's own success-only history; the current event must itself be a
novel successful hop — Finding 27) left the file bit-identical: on this
sampled corpus no variant of the rule flags any event, which is why rule
changes are priced on the unsampled day instead.

So the recipe is correct, but the model column is not bit-reproducible across
torch builds. **That is why the fixture is committed rather than regenerated
on demand:** a regression pinned against a freshly scored cache would be flaky
at the 1e-6 level, while one pinned against a committed file is deterministic.

If you regenerate from a **different** checkpoint, expect
`test_the_known_corpus_result_is_reproduced` to fail — the fixture pins a
measurement of one specific model, and the failure is the test telling you the
measurement has moved and the findings that cite it need re-deriving.

### Why it lives under `tests/` rather than `artifacts/`

`artifacts/**` and `data/**` are gitignored, so anything placed there exists on
one machine only. This file exists so that a regression can be pinned against
real scored data in any checkout, which requires it to be tracked. 8.7 MB is the
cost of that guarantee.
