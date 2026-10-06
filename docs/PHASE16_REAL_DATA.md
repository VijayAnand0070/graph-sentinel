# Phase 16 — real-data activation and accuracy engineering

Phase 16 turns the implemented detector into an auditable candidate-release workflow. It does
not treat synthetic demonstrations as accuracy evidence and it does not download restricted data.

## One-time data registration

Download `auth.txt.gz` and `redteam.txt.gz` through the LANL source process, keep the downloads
outside this repository, and register immutable copies:

```powershell
python -m graphsentinel dataset register --source D:\downloads\lanl --require core
python -m graphsentinel dataset register --source D:\downloads\lanl --require core `
  --execute --full-scan
```

Registration never overwrites an existing raw file. A later verification compares both complete
compressed-file hashes with the initial manifest and fails closed if either file changed.

## Run from the product

Start the API, open `http://127.0.0.1:8000/#training`, and select **Start Phase 16 pipeline**.
The equivalent API request is:

```http
POST /api/v1/phase16/start
Content-Type: application/json
X-API-Key: <deployment key, when configured>

{"max_events":250000,"epochs":24,"patience":5,"device":"auto"}
```

Monitor `GET /api/v1/phase16`. The response separates source provenance, stage state, job
progress, split evidence, rare-event metrics, promotion gates, and checkpoint lineage.

## Enforced stage order

1. Full gzip, schema, timestamp-order, malformed-row, and SHA-256 verification.
2. Chunked typed normalization and exact red-team label joining.
3. Score-before-update causal feature generation and feature-contract hashing.
4. Rule, rarity, Isolation Forest, and class-weighted logistic baseline experiments.
5. TGN training with class weighting, train-only robust normalization, and early stopping on the
   same fused validation objective used for promotion.
6. Validation-only threshold selection under the false-positive budget.
7. One sealed chronological holdout evaluation.
8. Serving-contract preflight and atomic production publication with disk rollback.

The UI presents seven lifecycle stages by combining validation and holdout evaluation with the
training stage taxonomy. Equal timestamps cannot cross splits. The model checkpoint is bound to
the dataset, feature contract, entity dictionary, configuration, split, seed, and code version.
It also records deterministic OOV user/host bucket capacity so new live entities are scored in a
bounded namespace instead of changing the frozen training dictionary.
The versioned `configs/model_tgn.yaml` is loaded with an exact-field schema; API/CLI epoch and
patience controls are the only run overrides, and feature-width or invariant drift fails closed.

## Failure and retry behavior

- A shared filesystem lease prevents the Phase 16 and legacy training APIs—or separate API
  processes—from mutating model artifacts concurrently.
- Every state transition is atomically journaled. A process restart converts an unfinished job
  into an explicit interrupted failure; it never guesses that a checkpoint means success.
- Matching normalized and feature artifacts are reused after their provenance chain is checked.
  Partial or mismatched artifacts fail closed and must be archived by an operator.
- Candidates and their reports are stored under job-specific run directories. A rejected
  candidate remains available for analysis and cannot replace the production report or model.
- A corrupt or unsupported journal is preserved and blocks execution instead of being silently
  overwritten.

## Accuracy interpretation

PR-AUC, Recall@K, Precision@K, false positives per 10,000 events, Brier score, and the selected
threshold are reported separately for validation and the sealed test. Promotion requires the
candidate to beat the strongest declared validation baseline and satisfy the validation alert
budget. These numbers become meaningful only after the real labeled dataset finishes. They are
not a guarantee of performance on another enterprise, whose identities, topology, telemetry,
attack prevalence, and analyst capacity will differ.

For the complete LANL corpus, ingestion and feature construction are streamed, but the current
experiment runner materializes the selected training cohort in memory. The product defaults to
250,000 events and enforces `GRAPHSENTINEL_MAX_IN_MEMORY_EVENTS` (2,000,000 by default). Use
`max_events` to bound
an exploratory run to available RAM, then validate that the chosen chronological cohort contains
positive and negative examples in train, validation, and test. A full-corpus out-of-core trainer
remains a separate scale-out upgrade; the product fails explicitly when a defensible split cannot
be created rather than publishing a misleading metric.
