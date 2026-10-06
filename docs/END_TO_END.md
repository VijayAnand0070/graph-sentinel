# The end-to-end pipeline check

One command runs the product from raw LANL text to a served, responding API and
asserts, stage by stage, that what each stage leaves behind is what the next one
needs — ending with the deployed path reproducing the offline evaluation number
for number on the run's own held-out events.

```bash
# the real corpus, bounded (about an hour: 35 min of it reading 176M raw rows)
python scripts/e2e_pipeline.py --raw-dir data/raw/lanl --run-dir artifacts/e2e/lanl_900k \
    --end-timestamp 900000 --sample-stride 448 --epochs 8 --device cuda

# a synthetic LANL-format corpus (about seven minutes on CPU)
python scripts/e2e_pipeline.py --synthetic --run-dir artifacts/e2e/synthetic --epochs 2
```

Every stage is the product's own entry point run as a subprocess — the
`graphsentinel` CLI, `scripts/build_scored_cache.py`, the API process — wired
together through the same environment variables an operator sets. Nothing is
re-implemented in the check; a stage that passes here passes because the
product's code path did. Stages whose artefacts exist are reused, so a run
interrupted after the long ingest resumes from the feature build; `--fresh`
rebuilds everything. Each run writes `e2e_summary.json` and `E2E_REPORT.md`
into the run directory, with every subprocess log under `logs/`.

## What is asserted

| Stage | Entry point | Must hold |
|---|---|---|
| verify | `graphsentinel dataset verify` | manifest carries full-scan provenance for both core files |
| ingest | `graphsentinel ingest auth` | rows written, red-team matched, chronological, **no local logons**, parquet rows equal the report |
| features | `graphsentinel features build` | one feature row per ingested row; contract hash present |
| baselines | `graphsentinel evaluate baselines` | validation PR-AUC for every baseline |
| train | `graphsentinel train tgn` | a checkpoint that loads under the serving contract and matches the run's entity dictionary (promotion recorded, not required) |
| score | `scripts/build_scored_cache.py` | every partition scored; attacks present in validation and test |
| report | `graphsentinel evaluation-report` | bootstrap intervals for every detector |
| backfill | `graphsentinel backfill` | feature state and model memory through the validation boundary |
| serve | `graphsentinel.api.run` | see below |

The serve stage starts the API on the backfilled state, checks `/ready` reports
nothing degraded, then forwards the run's **test partition** — decoded back to
names through the run's own id maps — through `graphsentinel.live_adapter`,
exactly as a collector would. It then requires:

- the gateway accepted every event and rejected no batch;
- for the same events, the live path and the offline scored cache agree on
  **novelty, burst, pivot and the model probability** (≤ 1e-5) and on the
  **fused risk with the chain-rule floor**; pivot may differ only inside the
  first thirty minutes, while the windowed signal state — not part of the warm
  snapshot — fills;
- every alert is persisted, every alert produced dispatch records, a pending
  approval can be released by a named approver, arming a dry-run backend is
  refused (409), and every console and research endpoint answers 200;
- saving state persists **both** halves (feature engine and model memory);
- after a restart on the same database and saved state, alerts, dispatch
  records and pending approvals are intact, the settled approval cannot be
  replayed (404), and the service restores warm with the same coverage.

Live precision and recall on the test slice are reported beside the offline
PR-AUC; they are the same events scored the same way, so the two agree.

## What it found the first time it ran

Five defects, none visible from unit tests, all fixed (Finding 24 in
`DETECTION_RESEARCH_FINDINGS.md`):

1. **Train/serve skew in the corpus.** 53.8% of LANL events are local logons
   (source host equals destination host). The offline ingest kept them; the
   live gateway refuses them. The model was trained on, and the rolling
   features shaped by, traffic the deployed path can never see. The ingest
   now drops them (`--keep-self-loops` reproduces old corpora), and no red-team
   event is one.
2. **Evaluate/serve skew in the pivot channel.** The scored cache behind the
   evaluation report, the gate derivation and the training pipeline's fused
   threshold each assembled the pivot state by hand — two of them with the
   any-source test the code itself documents as firing on 47% of benign
   traffic, one of them unwindowed — while the gateway used the same-account
   chain. `SignalTracker` is now the single implementation on every path.
3. **A quick `dataset verify` silently downgraded the manifest** to
   quick-scan entries, after which `train` refused the corpus.
4. **`/api/v1/feature-state/save` persisted half the state**: features, not
   the model memory, so a restart restored features newer than the memory.
5. **The execution gate was derived on the raw model probability**, while
   the response layer compares the fused risk with the chain-rule floor; it is
   now derived on that quantity (0.846394) and records which one it is.

Two more were documentation and defaults: the default training recipe is not
the one the shipped checkpoint used (the check runs the real recipe and
records it), and the training guide listed commands that do not exist.

The check also pinned two things that were assumed: the inference session
advances memory per timestamp group on both paths, so request and block
boundaries do not change a probability; and the chronological split never
splits a timestamp group across partitions, so the backfilled state hands off
cleanly to the live stream.

## Results

Synthetic corpus (24,036 raw rows, 8,326 local logons dropped, 36 red-team;
two epochs on CPU):

| Channel | Max abs delta live vs offline |
|---|---:|
| novelty, burst, pivot, model probability, fused risk | 0.0 |

Live on the 2,357-event test slice: 13 alerts, 10 of 12 attacks caught, 3
false alerts; PR-AUC 0.8779 live and 0.8779 offline on the same events. 42
dispatch records (26 unattended dry-runs, 16 awaiting approval), one approval
released, restart intact.

Real corpus (`artifacts/e2e/lanl_900k`, 2026-09-18): the first 900,000
seconds at stride 448 — 176.5 M raw rows, 95.0 M local logons dropped,
182,815 events, 316 red-team — the v3 training recipe with a 70/15/15 split,
eight epochs on the RTX 3050, 70 minutes after the 35-minute ingest.

| | |
|---|---|
| Baselines (validation PR-AUC) | logistic 0.9137, rule 0.3768, rarity 0.3314, isolation forest 0.2231 |
| TGN | raw validation PR-AUC 0.5366, fused 0.7638; **not promoted** (50 training positives from one campaign) — the retained candidate is served and recorded as unpromoted |
| Evaluation report | test PR-AUC noisy-OR 0.6038 [0.5202, 0.6960], linear 0.6756, `tgn_only` 0.5656; threshold 0.669315 at 25 FP/10k; host 8274 accounts for 100% of test PR-AUC |
| Live | 27,423 test events in 55 requests at 315 events/s, warm and undegraded; 85 alerts (31.0 per 10k); 55 of 101 attacks caught, 30 false alerts |
| Agreement | novelty, burst, pivot 0.0; model probability 2.68e-7 (CUDA offline, CPU live); fused risk 2.51e-7; PR-AUC 0.603796 live vs 0.603798 offline |
| Response | 349 dispatch records: 208 unattended dry-runs, 141 awaiting approval; one released; arming refused |
| Restart | 85 alerts, 350 records, 140 pending intact; replayed approval refused; 22,088 warm memory nodes restored |

Full report: `artifacts/e2e/lanl_900k/E2E_REPORT.md`; findings in
`DETECTION_RESEARCH_FINDINGS.md`, Finding 24.

## Running it under pytest

```bash
GRAPHSENTINEL_E2E=1 python -m pytest tests/test_e2e_pipeline.py -q
```

The corpus writer and the report renderer are tested unconditionally; the full
run is opt-in because it takes minutes.
