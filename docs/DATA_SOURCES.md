# Data sources: any authentication log

The detector reasons about one thing — *an identity, from one machine,
authenticated to another, at a time, and whether it worked*. Every log that
records that can feed it. The `sources/` package turns each format into that
one event; from the interim dataset onward (features, baselines, training,
backfill, serving, response) nothing knows which format the events came from.

```bash
python -m graphsentinel sources list              # what is supported
python -m graphsentinel sources describe zeek     # a sample of the format
```

| Format | What it reads | Source → destination | Notes |
|---|---|---|---|
| `lanl` | the research corpus (`ingest auth`) | src host → dst host | labels from `redteam.txt.gz` |
| `windows-json` | Windows Security events as JSON lines: SIEM exports, winlogbeat (`winlog.*`), OTRF Security-Datasets / Mordor | workstation or IP → the computer that logged the event (for 4769, the service the ticket was for) | 4624 / 4625 / 4768 / 4769 / 4776; XML via `ingestion/windows.py` |
| `ssh-auth` | Linux `sshd` lines from `auth.log` / `secure` | client address → the host that wrote the line | BSD stamps need `--assume-year`; the account has no realm |
| `zeek` | Zeek `kerberos.log` and `ntlm.log`, JSON lines or TSV | client address / claimed hostname → the service host of a TGS request, or the NetBIOS server name | a network sensor sees authentications the endpoints never log |
| `entra-signin` | Microsoft Entra ID (Azure AD) sign-in logs (Graph `signIns`: array, `value` envelope, or lines) | device name or IP → the resource / application | `status.errorCode == 0` is success |
| `okta` | Okta System Log | client IP → the application (session starts land on `OKTA`) | `user.session.start`, `user.authentication.*` |
| `tabular` | any CSV with a header, or JSON lines, through `--map` | whatever the map says | the escape hatch for a format nobody has written |

## Ingesting

```bash
python -m graphsentinel ingest logs --format zeek --input ntlm.log --input kerberos.log.gz \
    --output data/interim --id-maps artifacts/id_maps --report artifacts/reports/ingestion_logs.json \
    --labels known_attacks.csv          # optional: time,user,src_host,dst_host
```

The report says how many lines became events and why the rest did not, per
reason — an unexplained gap is how an integration goes wrong quietly. Events
are sorted by time (file order breaks ties), exact duplicates are dropped,
local logons (source host equals destination host) are dropped because the
live gateway refuses them, and each input's SHA-256 is recorded with one
digest over all of them as the dataset's provenance.

Training then takes that provenance instead of the LANL manifest:

```bash
python -m graphsentinel train tgn --input data/processed/features_v1 ... \
    --ingestion-report artifacts/reports/ingestion_logs.json
```

## Not naming the format at all

`--format auto` sniffs the file instead. Formats with a dedicated adapter are
recognised by fields only they carry (a Windows event id, Zeek's `id.orig_h`,
Okta's `eventType`, an Entra `userPrincipalName`, sshd's tag, a Zeek `#fields`
header). Anything else is a CSV or JSON-lines export nobody has written an
adapter for, and for those the **column map is inferred from the header
names**: a role token (`src`, `client`, `target`, `dest`) combined with a
thing token (`host`, `machine`, `computer`, `ip`), scored so the two host
columns settle against each other rather than by column order.

```bash
graphsentinel sources sniff /path/to/export.csv      # what it is, and the --map it would use
graphsentinel ingest logs --format auto --input /path/to/export.csv
```

A detection is a guess, so it is reported as one: `sources sniff` prints the
confidence, the evidence it matched and every warning -- a success column
whose values mean nothing to the parser, a log with no outcome column at all
(every event would be recorded as a success, and the chain rule counts
successful hops), a source and destination that are equal on every row. The
guess and its evidence are written into the ingestion report, so a dataset
whose format was sniffed carries the sniff. An explicit `--map` always wins.
Files that disagree about their format are refused rather than majority-voted.


## Forwarding live

```bash
python -m graphsentinel live --format ssh-auth --assume-year 2026 --input /var/log/auth.log \
    --api-url http://127.0.0.1:8000
```

A file in any format is sorted and forwarded in chronological batches that
never split equal timestamps. A continuous feed should be converted upstream
into the gateway's JSONL and followed with `--follow`, because the gateway's
clock only moves forward.

## Identity, the part that decides whether the graph is any good

Every adapter shares one canonicalisation (`ingestion/windows.py`):
`WS001.corp.local`, `WS001`, `ws001$` and `WS001$@CORP` are one host;
`CORP\alice`, `alice@corp.example` and `alice` + domain `CORP` are one account.
IP addresses are kept verbatim — reverse DNS would invent an identity rather
than resolve one — which means a sensor that only sees addresses (sshd, Zeek
without hostnames) produces address-named source nodes next to name-named
destinations. The graph still works; two spellings of the same machine are
two nodes, and a local logon recorded as `10.0.0.5 → WS05` is not recognised
as one. A host inventory that maps addresses to names is the fix, and it is an
operator's input, not something the product should guess.

## Labels for anything that is not LANL

A CSV of known-attack events, `time,user,src_host,dst_host`, plain or gzip,
with times as epoch seconds or ISO 8601. The user and host strings must be the
canonical forms the adapter produces (`alice@CORP`, `WS05`, `10.0.0.5`); the
`sources describe` sample shows what those are. Public labelled recordings in
the Windows JSON shape — the OTRF Security-Datasets lateral-movement
captures — load through `windows-json`; they are attack-only recordings and
belong overlaid on a benign baseline, not trained on alone.

## Verified end to end

`scripts/e2e_pipeline.py --synthetic --source-format <name>` renders the
synthetic corpus in that format and runs the whole pipeline through the
adapter: ingest, features, baselines, training with the report's provenance,
scoring, evaluation, backfill, serving, live detection with exact agreement
against the offline cache, automatic response and restart. Verified for
`zeek`, `ssh-auth`, `windows-json` and `tabular` (`docs/END_TO_END.md`); the
cloud adapters are unit-tested on their documented samples.

## Reading a log is not the same as alerting correctly on it

On a second, independent dataset -- 29 public OTRF Security-Datasets
recordings of real Windows lateral movement -- `--format auto` read every
recording, and the served product scored them from its shipped (LANL) state:
2 of 21 scorable attacks crossed the shipped alert threshold, while the
threshold-free separation was real but weak (pooled ROC-AUC 0.66, 95% interval
0.56-0.75). The threshold is a property of the estate it was calibrated on
(Finding 30). On a new estate: ingest with `--format auto`, run in dry run on
its own history, retrain, and re-derive the gate on its own validation data
before arming anything. The evaluation is reproducible:

```bash
python scripts/otrf_evaluate.py --data data/raw/otrf --api http://127.0.0.1:8020 --out artifacts/otrf
python scripts/otrf_summary.py
```
