# GraphSentinel production operations

## Product surfaces

- `/` — responsive analyst console
- `/api/v1/overview` — aggregated threat posture
- `/api/v1/graph` — typed user/host attack graph
- `/api/v1/alerts` — searchable and filterable investigation queue
- `/api/v1/paths` — ranked time-respecting pivot paths
- `/api/v1/live/events` — authenticated live authentication ingestion
- `/api/v1/live/status` — live stream mode and counters
- `/api/v1/training/start` — bounded background TGN training
- `/api/v1/training/status` — training progress and promotion state
- `/api/v1/data/readiness` — dataset pipeline release gates
- `/api/v1/phase16` — real-data provenance, pipeline, evaluation, and promotion status
- `/api/v1/phase16/start` — start the gated raw-data-to-production lifecycle
- `/api/v1/security/posture` — authentication, CORS, persistence, and worker posture
- `/api/v1/detection-engineering` — ATT&CK coverage, telemetry gaps, and guided hunts
- `/api/v1/alerts/{alert_id}/context` — related timeline and technique assessments
- `/ready` — persistence-aware readiness probe
- `/metrics/prometheus` — Prometheus text exposition
- `/docs` — OpenAPI contract

## Required production configuration

```text
GRAPHSENTINEL_DATABASE=/durable/graphsentinel.db
GRAPHSENTINEL_CHECKPOINT=/models/tgn.pt
GRAPHSENTINEL_API_KEY=<secret supplied by a secret manager>
GRAPHSENTINEL_AUTH_SCOPE=all
GRAPHSENTINEL_ALLOWED_ORIGINS=https://soc.example.org
GRAPHSENTINEL_WORKERS=1
GRAPHSENTINEL_ID_MAP_DIR=/artifacts/id_maps
GRAPHSENTINEL_FEATURE_DIR=/data/processed/features_v1
GRAPHSENTINEL_FEATURE_REPORT=/artifacts/reports/features_v1.json
GRAPHSENTINEL_TRAINED_CHECKPOINT=/artifacts/models/tgn-production.pt
GRAPHSENTINEL_TRAINING_REPORT=/artifacts/metrics/tgn_training.json
GRAPHSENTINEL_PHASE16_STATE=/artifacts/runtime/phase16-state.json
GRAPHSENTINEL_PIPELINE_LEASE=/artifacts/runtime/model-pipeline.lease.json
GRAPHSENTINEL_MAX_IN_MEMORY_EVENTS=2000000
GRAPHSENTINEL_MODEL_CONFIG=/app/configs/model_tgn.yaml
```

The promoted checkpoint carries its validation-selected threshold. Set
`GRAPHSENTINEL_THRESHOLD` only for an explicit, reviewed operational override; otherwise the API
loads the checkpoint threshold automatically. If `GRAPHSENTINEL_CHECKPOINT` is not set, the API
loads the promoted `GRAPHSENTINEL_TRAINED_CHECKPOINT` when that file exists.

Live scoring also requires `GRAPHSENTINEL_ID_MAP_DIR` to contain the exact dictionaries whose hash
and capacities are recorded in the checkpoint. `/ready` returns `503` when a model is loaded
without that contract. Promotion preflights the candidate before publishing it and restores the
previous production file if live installation fails.

The temporal model and streaming path tracker are ordered, stateful services. Keep one worker per
partition and route an entity partition consistently. Horizontal deployments should move ordered
state to a dedicated stream processor instead of running independent workers over one event stream.

When an API key is configured, GraphSentinel protects every non-public API read and write by
default. Only the console shell/assets, `/health`, `/ready`, `/docs`, and `/openapi.json` remain
public. `GRAPHSENTINEL_AUTH_SCOPE=write` is a compatibility mode and must not be used where alert,
entity, hunt, model, or operational data is sensitive.

Terminate TLS at a trusted reverse proxy, prevent public access to SQLite and model artifacts,
rotate API keys, and forward structured request logs and Prometheus metrics to the approved
observability platform. The service deliberately exposes no automated containment endpoint.
The native console stores an entered API key only in browser session storage; use an
identity-aware proxy for multi-user production access.

## Accuracy and release gate

"High accuracy" is not a configuration switch. Release a checkpoint only after leakage-safe,
chronological validation on representative telemetry. Record PR-AUC, Recall@K, Precision@K,
false positives per 10,000 events, detection delay, path hit rate, and Brier score. Select the alert
threshold only on validation data under the real analyst budget, freeze it with the checkpoint,
then report test performance once. Synthetic demonstration scores prove system behavior only and
must never be presented as production accuracy.

## Rollout phases

1. Shadow: ingest a mirrored stream with no analyst paging and validate contracts and latency.
2. Calibration: label analyst outcomes, select thresholds, and document subgroup/error analysis.
3. Assisted operations: send alerts to a limited analyst cohort; triage remains advisory.
4. Production: enable the full queue with SLOs, drift monitoring, rollback checkpoints, and audit retention.
