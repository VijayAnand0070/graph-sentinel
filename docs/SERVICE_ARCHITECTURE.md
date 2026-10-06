# Detection and service architecture

## Detection flow

```text
chronological normalized events
  -> causal features (strictly prior timestamps)
  -> typed temporal graph events
  -> pre-update TGN probability
  -> explicit novelty / burst / pivot / corroboration channels
  -> decomposable weighted fusion
  -> bounded time-increasing host paths
  -> structured evidence + conservative ATT&CK mapping
  -> deterministic or approved-provider triage
  -> FastAPI analyst boundary
```

The service currently accepts already-computed risk components. This keeps its public contract
usable while model training is gated on the real dataset. A frozen checkpoint adapter will
replace the externally supplied TGN component after Phase 8 training; the service does not claim
`model_loaded=true` before that artifact exists.

## Temporal model guarantees

- `score(batch, state)` is side-effect free.
- `update(batch, state)` aggregates equal-time endpoint messages before one GRU update per node.
- Stream state is separate from learned parameters and can be reset/detached explicitly.
- Checkpoints contain architecture, weights, and experiment metadata.
- The PyG adapter preserves source, destination, time, message, label, origin host, and event ID.

## Service guarantees

- Pydantic rejects unknown fields and bounds strings, batches, scores, IDs, and counters.
- Batch results are committed atomically; conflicts do not partially update metrics or alerts.
- Paths require strictly increasing time, bounded windows/hops, minimum edge risk, and no cycles.
- Every triage statement cites evidence IDs; unknown citations and altered ATT&CK mappings fail.
- No endpoint executes containment or remediation.
- Responses include request IDs, `nosniff`, and `no-store` headers.
- Frozen checkpoints use restricted tensor loading, SHA-256 provenance, feature-version checks,
  strict architecture fields, and typed user/host capacity checks.
- Internal temporal inference previews memory changes and publishes them only after the alert/path
  repository transaction succeeds.
- Replay preserves complete equal-timestamp groups and supports accelerated dataset-relative time.
- The Streamlit dashboard consumes the public API rather than reading SQLite or model state.

The default repository is process-local for deterministic development. Setting
`GRAPHSENTINEL_DATABASE` activates the durable SQLite WAL adapter used by `compose.yaml`.
Configure one API worker with SQLite; use a future PostgreSQL adapter before multi-worker or
multi-node deployment.
