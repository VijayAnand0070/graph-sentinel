# Live detection integration

GraphSentinel detects lateral movement from authentication telemetry delivered by existing,
authorized security sensors. It does not capture packets, inspect content, collect credentials, or
perform active network interception.

## Live contract

Publish one or more chronological events to `POST /api/v1/live/events`. Supply a stable `batch_id`
from the upstream partition and offset for retry safety. All events with the same timestamp must
be sent in one batch so none can influence another event at the same time.

Required fields are `timestamp`, `user`, `source_host`, `destination_host`, and `success`. Optional
fields are `destination_user`, `auth_type`, `logon_type`, `orientation`, `corroboration`, and
`source`. Corroboration is a bounded `[0, 1]` value derived by an approved upstream policy from
independent telemetry; it is not free text.

Typical mappings:

| Source | Timestamp | User | Source host | Destination host | Outcome |
|---|---|---|---|---|---|
| Windows Security 4624/4625 | event time | Subject/Target account | Workstation/IP resolved by inventory | Collector host | Event ID/status |
| Zeek `kerberos.log` | `ts` | client principal | client host | service host | request result |
| Identity provider | event time | actor | managed device | application/resource host | result |
| EDR/SIEM normalized auth | event time | account | initiating endpoint | remote endpoint | normalized status |

Resolve IP addresses through trusted asset inventory before publication when stable host identity is
required. Never place passwords, hashes, bearer tokens, tickets, command lines, or packet payloads
in any field.

## Ordering and delivery

- Partition streams consistently and preserve non-decreasing event time.
- Combine equal timestamps in one request.
- Retry an uncertain request with the identical `batch_id` and payload. The running gateway
  returns the original response without scoring or mutating state again. Reusing the ID with a
  different payload returns `409 Conflict`.
- Use TLS at the ingress proxy and configure `GRAPHSENTINEL_API_KEY` or an approved identity-aware
  proxy.
- Monitor `/api/v1/live/status`, `/ready`, and `/metrics/prometheus`.

The retry receipt cache is bounded to 10,000 batches and is process-local. A durable upstream
offset/checkpoint remains the source of truth across restarts; this service does not claim durable
exactly-once delivery. A request without `batch_id` retains strict chronological duplicate
rejection.

The included `graphsentinel live` JSONL adapter is suitable for controlled forwarders and demos.
At larger scale, map the same schema from Kafka, a SIEM HTTP output, or a partitioned stream
processor and retain ordering per entity partition.
In `--follow` mode it holds the current timestamp until a later timestamp is observed as a safe
watermark, so equal-time lines written separately are never split across requests.

## Detection modes

With a verified TGN checkpoint, the gateway emits raw causal messages to the temporal model and
fuses its probability with novelty, burst, pivot, and corroboration. Without a checkpoint, it uses
the explicitly labeled explainable fallback. Fallback results validate product flow and provide
basic heuristic detection; they are not evidence of trained-model accuracy.

A trained live model requires the exact frozen entity dictionaries named by its checkpoint hash.
Unknown entities are rejected instead of being assigned unsafe out-of-range IDs. Successful hot
promotion creates a new model generation and resets temporal memory, causal feature history, and
streaming path state at one locked boundary. The last accepted timestamp remains the ordering
watermark.
