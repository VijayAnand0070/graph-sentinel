# GraphSentinel

GraphSentinel is a temporal-graph cybersecurity system for detecting lateral movement in
enterprise authentication telemetry. It keeps detection deterministic and model-based, then
uses an optional LLM only to summarize a bounded evidence bundle.

The implementation follows the supplied project blueprint in dependency order. The target is
the blueprint's **distinction-level** scope: authentication and red-team ground truth first,
then a Temporal Graph Network (TGN), path ranking, enrichment, evidence-grounded triage,
API/dashboard, evaluation, and reproducible deployment.

## Current phase

The repository now contains the Phase 0-16 advanced implementation foundation: raw-data controls,
streaming normalization, causal security features/EDA, chronological splits, temporal graph
primitives, baselines, a trainable temporal-memory detector, fusion/path ranking,
evidence-grounded triage, durable alert storage, typed APIs, checkpoint serving, monitoring,
chronological replay, a graph-first console, retry-safe live ingestion, rollback-safe hot model
promotion, ATT&CK coverage engineering, guided threat hunts, related-entity investigation
timelines, a reproducible baseline experiment runner, and a durable real-data-to-production
accuracy pipeline. Phase 16 verifies immutable source hashes, safely reuses matching artifacts,
runs four declared baselines, trains against the fused validation objective, opens the sealed
holdout once, and promotes only through an atomic rollback boundary. Components are
synthetic-data verified; formal academic performance gates still require the real LANL core
files. Large LANL files are intentionally never committed or modified in place. See
[docs/PHASE_STATUS.md](docs/PHASE_STATUS.md) for the evidence-backed phase state.
The operator workflow and accuracy-interpretation rules are in
[docs/PHASE16_REAL_DATA.md](docs/PHASE16_REAL_DATA.md).
The current official-product comparison and prioritized gap analysis is in
[docs/PRODUCT_BENCHMARK.md](docs/PRODUCT_BENCHMARK.md).

## Quick start

Python 3.11 or 3.12 is recommended.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[all,dev]"
python -m graphsentinel doctor
python -m pytest
```

## Run the demo console

The repository includes a small trained model and saved state (about 17 MB), so the console runs
without downloading LANL:

```powershell
python run_demo.py
```

Then open http://127.0.0.1:8010. Response actions run in dry-run mode: every lock is planned and
audited, nothing is executed. When the system locks an account it writes an incident report, shown under
**Automatic Response** and saved to `artifacts/reports/soc/` as Markdown and JSON (set
`GRAPHSENTINEL_SOC_REPORT_DIR` to change the folder). AI-written incident reports additionally need `pip install -e ".[agent]"`
and a local Ollama server with the `qwen3.5:4b` model; without them a deterministic report is used.

## Obtain and register LANL data

Download the five files through the official LANL dataset page. The site requests intended-use
information before making download links available, so GraphSentinel does not scrape or bypass
that step. For the core implementation, `auth.txt.gz` and `redteam.txt.gz` are sufficient.

Place downloaded files in a separate directory and register them into immutable raw storage:

```powershell
# Preview actions; does not write anything.
python -m graphsentinel dataset register --source D:\downloads\lanl --require core

# Copy, validate the entire decompressed stream, and write data/raw/lanl/manifest.json.
python -m graphsentinel dataset register --source D:\downloads\lanl --require core --execute --full-scan

# Re-run a read-only integrity audit later.
python -m graphsentinel dataset verify --require core --full-scan

# After registration: normalize (local logons -- source host == destination host, 54% of
# LANL -- are dropped, because the live gateway refuses them), then build auth-causal-v1
# features and security EDA.
python -m graphsentinel ingest auth
python -m graphsentinel features build

# E1/E2 baseline matrix with validation-only threshold selection.
python -m graphsentinel evaluate baselines
```

## Private Hugging Face storage

Hugging Face Hub can store the verified dataset and model artifacts; it does not replace the
TGN or provide free training compute. GraphSentinel uploads raw data only after both LANL core
files pass the complete contract scan and have an immutable SHA-256 manifest.

```powershell
python -m pip install -e ".[hub]"
hf auth login

# Always creates or reuses a private dataset repository.
python -m graphsentinel dataset hub-push `
  --repo-id YOUR_HF_USERNAME/graphsentinel-lanl-private

# Restore to staging without overwriting protected files; every hash is checked.
python -m graphsentinel dataset hub-pull `
  --repo-id YOUR_HF_USERNAME/graphsentinel-lanl-private `
  --destination artifacts/downloads/lanl-hub
```

Authentication is read from Hugging Face's local credential store. GraphSentinel deliberately
has no command-line token option, which prevents access tokens from leaking through shell
history or process listings. After a restore, use the normal dry-run and full-scan registration
commands above before training.

## Run the detection API

Use persistent SQLite storage for a professional single-node deployment:

```powershell
$env:GRAPHSENTINEL_DATABASE = "artifacts/graphsentinel.db"
$env:GRAPHSENTINEL_THRESHOLD = "0.75"
$env:GRAPHSENTINEL_API_KEY = "replace-with-a-secret-manager-value"
graphsentinel-api --host 127.0.0.1 --port 8000
```

The production analyst console is available at `http://127.0.0.1:8000/` and OpenAPI
documentation at `http://127.0.0.1:8000/docs`. The console includes an interactive temporal
attack graph, priority queue, ranked paths, evidence inspection, grounded triage, analyst status
workflows, runtime health, and responsive desktop/mobile layouts. The scoring API accepts
validated TGN/novelty/burst/pivot/corroboration components. The live gateway computes the causal
message and TGN component internally when a trained checkpoint and its exact frozen entity
dictionary are loaded.

For production deployments, set `GRAPHSENTINEL_API_KEY` to protect all mutating endpoints and
provide it through the `X-API-Key` header, restrict browser origins with
`GRAPHSENTINEL_ALLOWED_ORIGINS`, mount durable storage, and load a frozen model through
`GRAPHSENTINEL_CHECKPOINT`. See [docs/PRODUCTION.md](docs/PRODUCTION.md).

## Train a production checkpoint

After dataset registration, ingestion, and causal feature generation, train the TGN with one
command:

```powershell
python -m graphsentinel train tgn `
  --input data/processed/features_v1 `
  --feature-report artifacts/reports/features_v1.json `
  --id-maps artifacts/id_maps `
  --checkpoint artifacts/models/tgn-production.pt `
  --report artifacts/metrics/tgn_training.json
```

The complete raw-to-production job can be started and monitored from **Data & Model Lab** in the
analyst console after only the two core raw files are registered. The console calls
`POST /api/v1/phase16/start` and monitors `GET /api/v1/phase16`; it shows provenance, every stage,
chronological split evidence, candidate-versus-baseline graphs, release gates, and checkpoint
lineage. Training
uses chronological timestamp-safe splits, train-only robust normalization, class-weighted loss,
early stopping on validation PR-AUC, validation-only alert-budget threshold selection, and a
single final test evaluation. The checkpoint is bound to the feature contract and entity
dictionary hashes and is loaded into the running detector only after the release gates pass.
Candidate validation occurs before disk publication; failed live installation restores the
previous production checkpoint. API and legacy training jobs share a cross-process lease, job
state is journaled atomically, interrupted runs recover as explicit failures, and candidate
artifacts are retained per run. The CLI also trains into a candidate and cannot overwrite the
production target when its promotion gate rejects the model.

## Any authentication log, not only LANL

The detector needs one thing from a log: *identity, from machine, to machine, when, success*. Seven
formats produce it today — Windows Security events as JSON (SIEM exports, winlogbeat, OTRF
Security-Datasets), Linux `sshd` `auth.log`, Zeek `kerberos`/`ntlm`, Microsoft Entra ID and Okta
sign-ins, any CSV/JSONL through a column map, and the LANL corpus — through one `ingest logs`
command and one live forwarder, with labels for any of them (`docs/DATA_SOURCES.md`):

```bash
python -m graphsentinel sources list
```

Or do not name the format at all. `--format auto` sniffs the file: formats with
an adapter are recognised by fields only they carry, and for an export nobody
has written an adapter for the column map is inferred from the header names, so
a CSV whose columns are `Client Workstation` and `Target Server` ingests with no
configuration. The guess, its confidence, the evidence it matched and every
warning are printed and written into the ingestion report; an explicit `--map`
always wins.

```bash
python -m graphsentinel sources sniff /path/to/export.csv
python -m graphsentinel ingest logs --format auto --input /path/to/export.csv
```

```bash
python -m graphsentinel ingest logs --format zeek --input ntlm.log --labels known_attacks.csv --output data/interim --id-maps artifacts/id_maps --report artifacts/reports/ingestion_logs.json
```

The end-to-end check runs the whole pipeline through each adapter (`--synthetic --source-format zeek`).

## Detect live authentication activity

Send chronological timestamp groups from an approved SIEM, Windows Event collector, identity
provider, Zeek pipeline, or EDR to the authenticated live endpoint:

```http
POST /api/v1/live/events
X-API-Key: <configured secret>
Content-Type: application/json

{"batch_id":"siem-auth-12:offset-8401","events":[{"timestamp":1786542000,"user":"alice@example.org","source_host":"WS-104","destination_host":"DC-02","auth_type":"Kerberos","logon_type":"Network","orientation":"LogOn","success":true,"corroboration":0.7,"source":"windows-security"}]}
```

For an append-only normalized JSONL export:

```powershell
python -m graphsentinel live --input D:\telemetry\auth-live.jsonl `
  --api-url http://127.0.0.1:8000 --api-key $env:GRAPHSENTINEL_API_KEY --follow
```

The gateway computes the same causal features used in training and sends results directly into
the alert queue, attack graph, path tracker, and evidence workflow. It consumes authentication
metadata only; passwords, tokens, packet payloads, and active network interception are not part
of the product contract. Stable batch IDs make exact in-process retries idempotent; conflicting
reuse is rejected. See [docs/LIVE_DETECTION.md](docs/LIVE_DETECTION.md).

Container deployment:

```powershell
docker compose up --build
```

The API is exposed on port `8000` and the analyst dashboard on port `8501`.

Replay the explicitly synthetic demonstration stream into a running API:

```powershell
python -m graphsentinel.replay examples/synthetic_replay.jsonl `
  --api-url http://127.0.0.1:8000 --acceleration 100
```

Run only the dashboard during development:

```powershell
$env:GRAPHSENTINEL_API_URL = "http://127.0.0.1:8000"
python -m streamlit run src/graphsentinel/dashboard/app.py
```

`--require all` additionally requires process, flow, and DNS sources. Registration refuses to
overwrite an existing raw file. A full scan computes SHA-256 over the compressed bytes while
validating every decompressed row, column count, timestamp, missing-value count, first row, and
last row. A quick scan validates only an initial bounded sample and is clearly marked partial.

Feature generation reads normalized partitions chronologically, scores all records at the same
timestamp against identical prior state, writes Zstandard Parquet to
`data/processed/features_v1`, and emits an immutable feature-contract hash with its EDA report.

## Design invariants

- Events are scored before their information updates rolling state or graph memory.
- All splits are chronological; no future aggregates can enter an earlier event's features.
- Raw compressed telemetry is append-never/overwrite-never application data.
- Red-team labels use exact `(time, user, source host, destination host)` tuple matching.
- Evaluation emphasizes PR-AUC, Recall@K, Precision@K, false positives per 10k, detection
  delay, and path hit rate—not raw accuracy.
- The LLM receives structured evidence, never unrestricted raw telemetry, and cannot remediate.
- Anything a model writes — per-alert triage and the per-account SOC handover report — must cite
  ids from the bundle it was given; what the system *did* is copied from the dispatch records, and
  an ungroundable draft is rejected and rewritten, or falls back to the deterministic writer.

## Repository layout

```text
configs/                 Versioned data/model/threshold policy
data/raw/lanl/           Immutable source files (ignored by Git)
data/interim/            Partitioned normalized authentication events
data/processed/          Versioned causal feature datasets
src/graphsentinel/       Installable application package
tests/                   Unit and contract tests
tests/fixtures/          The committed scored cache every published number derives from
artifacts/               Models, metrics, ID maps, and reports (ignored by Git)
docs/                    Phase gates, decisions, and schemas
```

## Implemented detection foundations

- `auth-causal-v1` features: temporal deltas, pair rarity, multi-window fan-out,
  failure-before-success, destination novelty, historical degree, and logon rarity.
- Timestamp-group-safe chronological splitting; validation/test partitions without red-team
  positives fail explicitly rather than silently producing misleading metrics.
- Typed temporal graph events and bounded recent-neighbor memory with score-before-update rules.
- Explainable rule and rarity baselines plus a class-weighted logistic baseline.
- Tie-aware PR-AUC/ROC-AUC, Precision/Recall@K, Brier score, false positives per 10k, and
  validation-only threshold selection under an analyst alert budget.
- Trainable TGN-style detector with harmonic time encoding, explicit node memory, mean message
  aggregation, GRU updates, chronological truncated backpropagation, gradient clipping, atomic
  checkpoints, and a PyTorch Geometric `TemporalData` adapter.
- Decomposable risk fusion and bounded, cycle-free, time-increasing multi-hop path ranking.
- Strict evidence/ATT&CK/triage schemas, deterministic offline triage, citation validation, and
  no remediation endpoint.
- An optional local-model agent (LangGraph over Ollama, opt-in with `GRAPHSENTINEL_TRIAGE_AGENT=1`)
  that writes per-alert triage and the per-account SOC incident report — the handover document
  saying what happened, what ran without a person, and what is waiting for one — under a citation
  contract the deterministic writer backs up.
- FastAPI service with atomic batches, request IDs, defensive headers, operational metrics, and
  optional SQLite WAL persistence.
- Native graph-first SOC console, versioned product APIs, Prometheus metrics, readiness checks,
  optional write authentication, analyst workflows, and ensemble confidence interpretation.
- Atomic model generations reset temporal inference, causal features, and path state together;
  candidate publication rolls back on failed live installation.
- Promoted checkpoints reserve deterministic OOV user and host buckets so previously unseen live
  entities can accumulate isolated temporal state; unseen categorical values map to the explicit
  unknown token and OOV usage is observable.
- Bounded retry receipts prevent duplicate state mutation for exact live-batch retries, while a
  security-posture endpoint reports write authentication, persistence, CORS, and worker safety.
- Detection engineering workspace with honest ATT&CK dispositions, telemetry gaps, guided hunt
  scopes, and related-entity investigation timelines with human response guardrails.
- Phase 16 Data & Model Lab with verified real/demo/unregistered provenance, seven-stage release
  timeline, accessible job progress, rare-event metric graphs, leakage checks, promotion gates,
  and dataset/dictionary/checkpoint lineage.
- Evaluation with intervals: stratified bootstrap, paired comparisons on identical resamples,
  calibration with Wilson bounds, and **entity-disjoint generalisation** (`evaluation/generalisation.py`)
  that re-derives the entity-contamination caveat as a measurement in every report.
- **Automatic response** (`response/`, `docs/AUTOMATIC_RESPONSE.md`): every persisted alert is
  dispatched unattended through one execution path. Connectors plan the literal command for every
  catalogued action; `force_reauth` is the only disruptive action that ever runs without a person,
  and only with high confidence above the derived gate; everything harsher waits for a named
  approval in the console; irreversible actions never run unattended; every dispatch is recorded
  whether or not it ran, survives restarts, and cannot re-fire. `dry_run` by default; arming a
  backend that performs nothing is refused.
- **The SOC handover report** (`explain/soc_report.py`, `docs/LLM_AGENT.md`): one account, every
  alert on it, what the system did without a person, what is waiting for one — written over a
  fact bundle, with every sentence citing a fact, the actions copied from the dispatch records,
  and an optional local model (LangGraph over Ollama) writing the prose behind the same citation
  contract the deterministic writer backs up. Console panel, JSON, and Markdown for a ticket.
- The auto-execution gate is derived, not chosen (`detection/gates.py`): a precision target on
  validation with its realised out-of-sample precision and false-positive rate recorded beside it,
  and a test that re-derives it from the committed scored cache.
- A prevention instrument (`simulation/`): campaigns and ATT&CK technique scenarios injected
  into a warm synthetic continuation of the corpus, scored by the production composition, and
  reported as detection latency in hops, prevented hops under stated semantics, benign cost,
  and an evasion curve. `scripts/measure_prevention.py`, `scripts/validate_techniques.py`.

## Automatic response, in one paragraph

Set `GRAPHSENTINEL_AUTO_RESPONSE=dry_run` (the default) and every alert is planned, recorded with
its command, and performed by nothing — the mode to run in until the plans have been reviewed.
`GRAPHSENTINEL_RESPONSE_BACKEND=powershell` plus an audited switch to `armed` runs them. A
same-account chain of four moves into hosts the account has never touched, inside half an hour,
triggers the session kill on its own, bounded to twenty unattended actions an hour and one per
account (Finding 25). If the account keeps moving after the kill — a second confident detection
inside thirty minutes — the system escalates once to a reversible account lock and lifts it two
hours later unless an analyst keeps it, a decision that is itself recorded so a restart cannot
undo it (Finding 27). Measured against 100 unseen-attacker campaigns the shipped stack now detects
45 at the attacker's fourth move and prevents 14.6% of hops, for no benign session kills beyond the
model's own on the instrument and 0.09 per 10,000 in the last hours of an unsampled day; the
configuration it replaced prevented 0.75% — and, it turned out, would have flagged 760 benign
events per 10,000 at full rate, a cost the sampled research corpus had hidden. The rule is precise
about what a hop is: a successful authentication into a host the account has never reached, so
an attacker who guesses a password before each move is caught on the same hop as one who does not,
and an account returning to a server it knows is not a chain (Finding 27).

## Check the whole pipeline end to end

One command runs the product from raw text to a served, responding API and asserts each stage,
finishing with the deployed path reproducing the offline evaluation number for number on the run's
own held-out events (`docs/END_TO_END.md`):

```bash
python scripts/e2e_pipeline.py --raw-dir data/raw/lanl --run-dir artifacts/e2e/lanl_900k --end-timestamp 900000 --sample-stride 448 --epochs 8 --device cuda
```

```bash
python scripts/e2e_pipeline.py --synthetic --run-dir artifacts/e2e/synthetic --epochs 2
```

The first run of it found that the evaluated product and the deployed product were not the same
product (Finding 24): the offline corpus kept traffic the gateway refuses, the evaluation scored a
pivot channel the product does not compute, the execution gate was derived on a number the
response layer never sees, a quick `dataset verify` erased the manifest's full-scan provenance,
and saving state persisted half of it. All five are fixed and the check now pins them.

## Read before quoting any performance number

The headline test PR-AUC of 0.8210 is 99.8% attributable to a single attacker host that is
attack-only in training; holding it out gives 0.0019 (Finding 14 in
`docs/DETECTION_RESEARCH_FINDINGS.md`). Detector-vs-detector comparisons on this corpus remain
valid; no absolute figure is an estimate of performance against an unseen attacker. The
evaluation report carries this caveat as a measurement, not a sentence. Every published number
also evaluates a checkpoint trained on the corpus *before* local logons were dropped (Finding 24);
retraining on the corrected corpus is open item 19.

## Data source

Alexander D. Kent, *Comprehensive, Multi-Source Cyber-Security Events*, Los Alamos
National Laboratory (2015), DOI: 10.17021/1179829.
