# GraphSentinel implementation roadmap

Each phase has a testable exit gate. A later phase may be scaffolded early, but it is not
considered complete until its gate passes.

| Phase | Deliverable | Exit gate |
|---:|---|---|
| 0 | Reproducible project and success contract | Package imports, configuration is versioned, tests/lint can run, metrics and leakage invariants are documented |
| 1 | LANL acquisition/storage controls | Core files can be registered without overwrite; manifest records provenance, hashes, row/schema/missing/time checks |
| 2 | Streaming normalization | Gzip input is chunked to Parquet, stable typed ID maps persist, exact red-team matches are non-zero, parser report is reproducible |
| 3 | Security-focused EDA | Aggregated reports answer fan-out, inter-event, pair rarity, failure-success, category rarity, and degree-change questions |
| 4 | Labels and temporal splits | Split is chronological, attack-aware only when documented, and automated leakage tests pass |
| 5 | Temporal graph stream | Typed user/host node IDs and chronological events feed a bounded recent-neighbor store |
| 6 | Causal feature engine | Every feature uses state strictly before the scored event; feature dictionary and tests exist |
| 7 | Baselines | Rule, rarity, Isolation Forest, and weighted logistic results share one evaluation protocol |
| 8 | TGN detector | Score-before-update invariant passes and a stable checkpoint beats a simple baseline on at least one ranking metric |
| 9 | Fusion and path ranking | Time-increasing bounded paths are ranked; TGN and fused scores remain separately evaluable |
| 10 | Explanations and ATT&CK | Observed, derived, and model evidence are distinct; mappings express confidence and avoid unsupported sub-techniques |
| 11 | LLM triage | Structured input/output, evidence references, uncertainty, no invention, and no remediation guardrail tests pass |
| 12 | API and dashboard | Chronological replay produces inspectable alerts, paths, timelines, and metrics through typed endpoints |
| 13 | Evaluation and ablations | E1-E8 matrix reports PR-AUC, Recall/Precision@K, FP/10k, delay, path hit rate, and calibration where feasible |
| 14 | Deployment/MLOps | Container, artifact registry, feature/model versions, latency and drift counters are reproducible |
| 15 | Product console and final verification | Graph-first SOC workflows and unit/data/model/API/guardrail/E2E/reproducibility tests pass; real-data demo/report/viva artifacts are complete |

## Phase 0 success contract

The primary prediction unit is an authentication event at time `t`. The primary output is a
risk value in `[0, 1]` plus explicit evidence; the secondary output is a ranked, temporally
valid suspicious path. The detector must beat a frequency/rule baseline on at least one
predeclared ranking metric and produce interpretable top alerts.

Every experiment records the configuration, code revision when available, source manifest,
feature version, time range, random seed, checkpoint identity, and metrics. Final test data is
used once after threshold and hyperparameter selection are frozen on validation data.

## Scope control

- Core: authentication + red-team labels, causal features, baselines, TGN, event alerts.
- Strong: core + path ranking, dashboard, explanations, and ablations.
- Target: strong + bounded process/flow/DNS enrichment, LLM triage, Docker/replay.
- Deferred research: heterogeneous TGN, contrastive pretraining, graph transformer,
  cross-dataset evaluation, feedback learning, and graph database persistence.
