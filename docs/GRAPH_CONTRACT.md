# Temporal graph contract

Graph version: `auth-temporal-v1`

- User IDs and host IDs remain typed in persisted artifacts. `NodeIdSpace` maps them into a
  collision-free homogeneous range only at model runtime.
- The modeled authentication edge is `SOURCE_USER -> DESTINATION_HOST`.
- The source host is retained as `origin_host_node` for host-to-host pivot and path analysis.
- Message values follow the immutable `MODEL_FEATURE_NAMES` ordering from the causal feature
  contract.
- A recent-neighbor query occurs before an event updates either endpoint.
- All events at the same timestamp query the same earlier state and are published together.
- Per-node history is bounded by a configurable neighbor cap and optional time window; the full
  enterprise graph is never materialized as a dense adjacency matrix.

These framework-neutral structures can feed PyTorch Geometric `TemporalData` once the tensor and
TGN phase begins, while their causality can be tested without a GPU dependency.

