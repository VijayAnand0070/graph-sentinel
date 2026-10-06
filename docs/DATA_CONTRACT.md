# LANL raw-data contract

Raw inputs are gzip-compressed, comma-delimited, headerless UTF-8/ASCII records. The token `?`
means missing/unknown. Timestamps are integer seconds relative to the dataset's undisclosed
epoch and should be non-decreasing in source order.

| File | Scope | Columns |
|---|---|---|
| `auth.txt.gz` | core | time, src_user, dst_user, src_host, dst_host, auth_type, logon_type, orientation, success |
| `redteam.txt.gz` | core | time, user, src_host, dst_host |
| `proc.txt.gz` | enrichment | time, user, host, process, action |
| `flows.txt.gz` | enrichment | time, duration, src_host, src_port, dst_host, dst_port, protocol, packets, bytes |
| `dns.txt.gz` | enrichment | time, src_host, resolved_host |

Registration is intentionally one-way: source files are copied to `data/raw/lanl`, existing
targets are never replaced, and validation creates a separate JSON manifest. No transformation
writes into raw storage.

The manifest's `validation_level` is either `quick` or `full`. Only `full` establishes total
row counts, last valid rows, complete missing-value counts, and global timestamp ordering.

