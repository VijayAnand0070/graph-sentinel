# Deploying GraphSentinel: onboarding runbook

Onboarding is **not** "point it at the log stream and wait". Two halves of the
detection path carry cumulative state that forward traffic never rebuilds, so
a deployment that skips this runs at roughly **half its achievable detection
quality, permanently, with no error and no metric that changes.**

---

## Why backfill is mandatory

| State | Lives in | Behaviour when cold |
|---|---|---|
| Cumulative features | `CausalFeatureEngine` | 12 of the 27 features answer *"has this ever happened"*. `is_new_pair` reads 1 for every long-established relationship the process has not personally witnessed. |
| Node memory | `TGNInferenceSession` | `TGNState.initial()` zeroes a 63,397 × 64 tensor — asserting "nothing is known" about every entity at once. |

Neither self-heals. Measured against a full-history reference, after **200,000
events** of warm-up:

- `is_new_pair` is still **42% divergent**
- `dst_historical_degree` is still **65% divergent**
- only **0.3%** of events receive fully correct features

A cold engine cannot distinguish "this pair is new" from "I have not seen this
pair", and no quantity of forward traffic resolves that. Full measurements in
[DETECTION_RESEARCH_FINDINGS.md](DETECTION_RESEARCH_FINDINGS.md), Findings 9
and 10.

---

## The three steps

### 1. Backfill

Replay historical logs once to build the state. The replay uses the *same*
`CausalFeatureEngine` and `InferenceSession` as production, chronologically,
score-before-update — building state a different way than it will be used is
how a warm start becomes its own source of skew.

```bash
python -m graphsentinel.cli backfill --input data/processed/features_lanl_545k_split --output artifacts/state --checkpoint artifacts/models/tgn-lanl_545k_split_v3-candidate-c6912ac36724.pt
```

Add `--limit 40000` for a dry run first; 40,000 events takes about three
minutes on CPU and confirms the inputs are readable before committing to a
full pass.

Produces three artifacts:

| File | Contents | Format |
|---|---|---|
| `feature_state.json.gz` | cumulative feature-engine state | gzipped JSON |
| `tgn_memory.npz` | node memory, per-node update times, stream clock | numpy, `allow_pickle=False` |
| `backfill_manifest.json` | event count, coverage, SHA-256 of each artifact, source checkpoint | JSON |

Neither state file is a pickle. A security product should not load an
executable file at startup, and both formats are inert on read.

### 2. Configure restore

```bash
export GRAPHSENTINEL_FEATURE_STATE=artifacts/state/feature_state.json.gz
export GRAPHSENTINEL_TGN_MEMORY=artifacts/state/tgn_memory.npz
```

Both are optional. A missing snapshot starts cold — the previous behaviour —
but the fact is *reported* rather than inferred from degraded detection weeks
later.

The memory snapshot is refused if it belongs to a different checkpoint. Memory
vectors mean nothing to a network that did not produce them, and silently
loading another model's memory would be worse than starting cold.

### 3. Verify, then keep it fresh

```bash
curl -s http://127.0.0.1:8060/api/v1/feature-state
```

```json
{
  "known_pairs": 5250,
  "known_users": 1446,
  "known_source_hosts": 1483,
  "known_destination_hosts": 323,
  "restored_from_snapshot": true
}
```

`restored_from_snapshot: false` on a deployment that should be warm means the
path is wrong or the file is unreadable — check the server log for the
warning.

Re-snapshot periodically so a restart resumes from recent state rather than
from onboarding day:

```bash
curl -s -X POST http://127.0.0.1:8060/api/v1/feature-state/save
```

Writes are staged and renamed, so a crash mid-write cannot leave a truncated
snapshot that would restore as partial history and look like it worked.

---

## How much history to replay

More is better, and the returns do not plateau — the cumulative features are
still converging at 200,000 events. Practical guidance:

| Available history | Expect |
|---|---|
| < 1 week | Better than cold, but `is_new_pair` remains substantially wrong |
| 2–4 weeks | Reasonable operating point for most estates |
| 3+ months | Cumulative features approach their converged values |

Backfill is a one-off cost at onboarding: roughly **4 minutes per 100,000
events** on CPU including model memory, and it is trivially parallel across
customers.

---

## Operating it

### Is this instance healthy, and is it any good?

Two different questions, answered in two places.

```bash
curl -s http://127.0.0.1:8060/ready
```

```json
{
  "status": "ok",
  "model_loaded": true,
  "degraded": [
    "feature-state-cold: cumulative features were not restored from a backfill snapshot; 12 of 27 features are wrong until one is built"
  ]
}
```

`/health` answers *is the process up*. `/ready` answers *should it serve* —
and names any reason it is serving at reduced quality. A cold instance still
returns 200, deliberately: a first deployment with no backfill is legitimately
cold, and failing the probe would stop it starting. But cold costs **54% of
achievable PR-AUC while ROC-AUC moves only 0.9946 → 0.9992**, so nothing in
ordinary monitoring would reveal it. Naming it in readiness is what makes it
noticeable.

An instance reporting `degraded` in production has not been onboarded.

### Who did what

Every state-changing request is recorded. The response layer can disable
accounts, block network paths and isolate hosts, so "who asked for this" has to
be answerable afterwards — for incident review, for the customer's auditors,
and for the case where the product itself caused the outage.

```bash
curl -s "http://127.0.0.1:8060/api/v1/audit?high_impact_only=true&limit=50"
```

- **Append-only.** Entries are never rewritten. A log that can be edited is not
  evidence.
- **Actors are key fingerprints, never keys.** An audit log that leaks
  credentials turns a read-only compromise into a full one.
- **Reads are not audited.** A polling console would bury the entries that
  matter under thousands of GETs.
- **A failed write never fails the request.** It is counted, and
  `stats.degraded` goes true — a trail with holes is bad, but an outage caused
  by an unwritable log file is worse.

Set `GRAPHSENTINEL_AUDIT_LOG` to persist across restarts; without it the log
runs in memory only and `stats.persisted` says so.

---

## What this does not fix

Backfill warms the state a deployment *can* have. It does not give the model
site-specific training — the checkpoint is still whatever it was trained on,
and a customer's estate differs from the training corpus in ways no amount of
warm state addresses. Per-tenant training is a separate piece of work.

It also does not remove the need to validate detection quality at the
customer. A warm engine with a foreign model is a better starting point than a
cold one, not a finished product.
