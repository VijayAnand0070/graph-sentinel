# Automatic response

What GraphSentinel does about an alert without a person, what it waits for a
person to release, and how to turn it on.

## The one-paragraph version

Every alert the detection service persists is dispatched through the response
executor. On first contact the executor runs exactly one disruptive action
without a person — `force_reauth`, which invalidates the account's sessions
and costs a legitimate user one extra login prompt — and only when the
attribution confidence is *high* **and** the fused risk clears the derived
execution gate, or when the deterministic chain rule fires. It then watches
whether that worked: if the same account qualifies again inside the
escalation window, the system escalates once, on its own, to a reversible
account lock, and lifts it two hours later unless an analyst keeps it. Both are
bounded by an hourly budget. Everything harsher (`block_network_path`,
`disable_service_account`, `isolate_host`) is recorded as awaiting approval
and shown in the console; `reset_credentials` is irreversible and never runs
unattended under any configuration. Every dispatch, including the ones that
ran nothing, leaves a record with the literal command and the authority it
ran on.

## The loop: contain, verify, escalate, revert

A session kill is the cheapest containment and the one most likely to fail:
an on-premises Kerberos ticket already issued stays valid until it expires,
so an attacker holding one keeps moving. A system that stops at the kill is
hoping, not preventing. So the coordinator keeps watching the account:

1. **Contain.** The alert's unattended action runs (`force_reauth`), under
   the budget, and the account goes under observation for
   `GRAPHSENTINEL_ESCALATION_WINDOW_SECONDS` (default 1,800).
2. **Verify.** If, inside that window, the same account qualifies for an
   unattended action *again* — a second confident detection by the model or
   the chain rule, the same evidence that justified the first — the
   containment demonstrably did not hold. A weaker follow-up alert is not
   evidence and does not escalate.
3. **Escalate.** The system runs `lock_account` on its own authority:
   reversible, inside the budget (the hourly cap applies; the per-account
   cooldown does not, because this is a different rung on an account
   already acted on), once per account per window, recorded with the
   evidence it rests on (`authority: escalation`). An escalation never
   reaches an irreversible action, whatever the configuration.
4. **Revert.** The lock is lifted automatically after
   `GRAPHSENTINEL_AUTO_REVERT_SECONDS` (default 7,200 — two hours) with the command's
   revert (`Enable-ADAccount`), unless an analyst **keeps** it in the
   console, or the account moves again, which restarts the clock; an
   analyst can also **lift** it at any time. The blast radius of a wrong
   escalation is one account for one window.

Two hours, not one. The revert is the upper bound on how long a wrong lock
hurts, not a target, and an hour is shorter than both intervals that matter:
the gap between hops of the slow campaigns in the evasion curve (15 min to
1 h — a lock could expire while the attacker was simply waiting), and the
time an out-of-hours queue takes to reach a person. Two hours holds across
that gap and is still bounded and self-healing; every alert on a locked
account restarts the clock, so an active attacker never runs it out, and an
analyst can lift it in one click. Changed 23 Sep 2026; `7200` is a default,
not a constant.

The window is measured on event time — the attacker's clock — so a
replayed day or a batched hour escalates exactly as a live stream would; the
auto-revert and the budget run on wall time, so a lock applied during a
replay is not lifted the moment it is applied.

`GRAPHSENTINEL_ESCALATION=off` disables steps 2–4; a failed kill is then
alerted again and nothing further runs unattended. Measured on the
prevention instrument (Finding 27): with a session kill that always works the
loop changes nothing; with one that works half the time, escalation recovers
most of what the failed kills lose.

## Modes

| Mode | What happens on an alert | When to use it |
|---|---|---|
| `off` | Nothing is dispatched. The per-alert plan is still shown. | You want detection only |
| `dry_run` *(default)* | Every action is planned and recorded with its command; nothing is performed | Until the planned commands have been reviewed against your estate |
| `armed` | The executing backend runs the commands | After review, with a backend that can execute |

Arming a backend that performs nothing is refused, not silently accepted. Mode
changes take a named actor and are audited.

```bash
GRAPHSENTINEL_AUTO_RESPONSE=dry_run        # off | dry_run | armed
GRAPHSENTINEL_RESPONSE_BACKEND=dry_run     # dry_run | powershell
GRAPHSENTINEL_DATABASE=artifacts/graphsentinel.db   # records share the alert database
```

## The action ladder

| Action | Disruption | Runs unattended? | Reversible | Connector |
|---|---|---|---|---|
| `increase_monitoring` | 0 | always | yes | monitoring (in-process) |
| `notify_soc` | 0 | always | yes | monitoring (in-process) |
| `force_reauth` | 1 | **only** with high confidence and risk ≥ gate, or the chain rule | by the user signing in again | directory |
| `lock_account` | 3 | **only** as the one escalation after a failed containment, auto-reverted; otherwise approval | yes | directory |
| `block_network_path` | 3 | no — approval | yes | network |
| `disable_service_account` | 4 | no — approval | yes | directory |
| `isolate_host` | 5 | no — approval | yes | endpoint |
| `reset_credentials` | 4 | **never** | **no** | directory |

The partition is enforced twice: by `plan_for()` in the detection layer and
again by the executor at the moment of dispatch, where the action catalogue
outranks whatever any plan or caller says. `test_no_meaningfully_disruptive_
action_can_ever_auto_execute` sweeps every technique × confidence × risk.

## What the commands are

Every connector produces the literal command before anything is armed, and the
console shows it on every record:

| Action | Command (directory backend: PowerShell) |
|---|---|
| `force_reauth` (account) | log the account off the source host (`query user` → `logoff`), then `Revoke-MgUserSignInSession` |
| `force_reauth` (host only) | log every interactive session off the host |
| `lock_account` | `Disable-ADAccount -Identity '<account>'` — revert `Enable-ADAccount` |
| `block_network_path` | `New-NetFirewallRule` on the destination blocking the source — revert `Remove-NetFirewallRule` |
| `isolate_host` | EDR isolate API call — revert: release |
| `reset_credentials` | `Set-ADAccountPassword -Reset` with a generated secret and change-at-next-logon |

**Session invalidation, honestly:** on-premises Kerberos tickets already issued
remain valid until they expire. Killing sessions and revoking refresh tokens is
what can be done reversibly; invalidating tickets requires a credential reset,
which is why that action is irreversible and gated. Every `force_reauth`
command carries this limitation on its record.

## The execution gate

`force_reauth` runs unattended at fused risk ≥ **0.846394**. That number is
derived, not chosen: the lowest fused risk — the noisy-OR of the channels with
the chain-rule floor, the exact number `plan_for` compares — whose Wilson lower
bound on precision clears 75% on the validation partition
(`detection/gates.py`; 251 alerts at 80.5%). On the sealed test period the
same gate delivered 53.2% [46.3%, 60.0%] precision at 8.11 benign events per
10,000 above it. Precision at a fixed gate is not stable across days (Finding
18); the false-positive rate is the quantity to hold when re-deriving it. The
gate was first derived on the raw model probability (0.877729), which is not
the number the product compares; the end-to-end check caught that (Finding 24).

## The chain rule as a trigger

A same-account multi-hop chain is lateral movement by definition, so the
deterministic chain rule is a first-class trigger for the unattended action
(Finding 25). The shipped rule is **four novel hops in 1,800 seconds**: the
account has made three onward moves into hosts it had never successfully
reached, inside the window, and this event is a fourth — a successful
authentication from a host it reached to another host it has never reached.
Precisely that, and nothing looser (Finding 27): a failed logon is not a hop
and does not spend a host's novelty, so an attacker who guesses a password
before each move is caught on the same hop as one who does not; and an
account returning from a reached host to a server it already knows is not
chaining, so the rule fires on the hop, not on everything the account does
for the next half hour. Novelty is the rule's own history of successful
reaches, not the model's `is_new_pair` feature. When it fires the tactic
engine asserts T1021 at high confidence and the fused risk is raised to the
execution gate, so `force_reauth` follows without a person. Both halves are
configuration:

```bash
GRAPHSENTINEL_CHAIN_RULE=4hops-1800s-novel     # <hops>hops-<window>s-<any|novel>
GRAPHSENTINEL_CHAIN_RULE_POLICY=unattended     # alert_only | unattended
```

`alert_only` is the previous behaviour: the chain is raised to 0.60, shown,
and never acted on unattended. `3hops-1800s-novel` prevents more (21.5% of
hops against 14.6%, 41 of 50 chains at the attacker's third move) for 2.5×
the benign cost at full rate — 0.23 against 0.09 benign events per 10,000
in the last six hours of a cold day, 7.9 against 4.3 over the whole of it
(Finding 27) — which on an estate of this size is about six unattended
session kills an hour against two. The four-hop default is the precise one;
enable three hops on a deployment warmed with weeks of history that has
measured its own rate with `scripts/chain_rule_hourly.py` and decided the
trade is worth it.

## Bounded by construction

Every measured false-positive rate for the unattended action was taken at
the corpus's sampled density, and a cold unsampled day showed the chain rule
flagging hundreds per 10,000 in its first hours (Finding 25). So the
coordinator also holds a budget: at most `GRAPHSENTINEL_UNATTENDED_PER_HOUR`
(default 20) unattended disruptive actions in any sliding hour estate-wide,
and one per account per `GRAPHSENTINEL_UNATTENDED_COOLDOWN_SECONDS` (default
3,600). When the budget refuses, the action is recorded as awaiting approval
with the reason, and the console shows what the budget has used and demoted.
In the worst regime the product degrades to alert-only plus twenty re-login
prompts an hour; in the measured regime the budget never binds.

## What automatic prevention is worth, measured

The prevention instrument (`PREVENTION_INSTRUMENT.md`) runs 100 synthetic
campaigns from ordinary workstations through this stack, warm. Under the
configuration shipped until Finding 25 (four hops in 300 s, alert only) it
detected 21, at a median of the attacker's fifth move, and session
invalidation would have prevented 0.75% of hops. Under the shipped
configuration it detects 45 (36 of the 50 chains), at the attacker's fourth
move, and prevents **14.6% of hops** (28% of chain hops), for 5.46 benign
session kills per 10,000 events — the model's own rate; on the instrument's
three days the rule adds none (Finding 27). At full rate, after a single day
of history, the rule flags 0.09 benign events per 10,000 in the last six
hours (4.3 over the whole cold day; 9.9 in the cold morning), against 4.86
for the looser test it replaced and 760 for the rule shipped before Finding
25. Nothing fires at an hour between hops;
fan-out attackers and attackers who reuse hosts the account already knows
are still the model's to catch, and the model is bounded by a corpus with
one campaign in it (Findings 20 and 21).

## The SOC incident report

Per-alert triage explains one detection. The handover needs the other unit:
one account, every alert on it, what the system already did, and what is left
for a person. `explain/soc_report.py` builds that as a **fact bundle** --
alerts, dispatch records, the escalation and its evidence, each with an
`F-nnn` id -- and writes a report over it under the same contract triage uses:

* every narrative statement must cite fact ids from this bundle;
* the actions, the severity, the window and the host list are **copied** from
  the records, never authored -- a report that misstates which command ran is
  worse than no report;
* every statement about the automatic response must cite an `action` or
  `escalation` fact, so the section cannot become plausible-sounding response
  theatre;
* any alert id named in the prose must be an alert of this incident: a wrong
  identifier is one an analyst will paste into a search box;
* the first recommended step must be a verification, never an approval to
  isolate or block -- that is how a false positive becomes an outage.

With `GRAPHSENTINEL_TRIAGE_AGENT=1` the local model writes the prose through
the same bounded LangGraph loop as triage (prepare, draft, validate, repair,
at most three attempts); anything it cannot ground is rejected and the
deterministic writer produces the same report more plainly. Which engine
wrote it is returned in `X-Triage-Provider` / `X-Triage-Fallback` and shown
as a badge in the console.

| Route | Purpose |
|---|---|
| `GET /api/v1/soc/incidents` | accounts worth a report, worst first (escalated, then by risk) |
| `POST /api/v1/soc/incidents/{account}/report` | write the report; JSON plus a `markdown` field |
| `GET /api/v1/soc/incidents/{account}/report.md` | the same report as Markdown, for a ticket |

Offline, from a database a serving process is no longer holding:

```bash
graphsentinel soc-report --database artifacts/graphsentinel.db              # list candidates
graphsentinel soc-report --database artifacts/graphsentinel.db \
    --account 'C2287$@DOM1' --agent --out incident.md                       # write one
```

## Console

**Automatic Response** workspace: mode banner with audited controls; the SOC
incident report panel (an account list, the written report with its citations,
and a copy-as-Markdown button); dispatched
/ planned-or-executed / awaiting-approval / failed tiles; pending approvals
with the command that will run and an approve button; the dispatch audit with
every record, outcome and command. The alert drawer shows the plan and the
records for that alert, with inline approval. A labelled attacker the model
missed renders as `GT · MISSED`, never as a detection (Finding 17).

## API

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/soc/incidents` | accounts worth a handover report, worst first |
| `POST /api/v1/soc/incidents/{account}/report` | write that report (LLM or template; provenance in the headers) |
| `GET /api/v1/soc/incidents/{account}/report.md` | the report as Markdown |
| `GET /api/v1/response/status` | mode, backend, can-arm, counts, the unattended ceiling, the budget, the loop's state |
| `GET /api/v1/response/incidents` | accounts under observation, active escalations with their evidence and auto-revert times (reading it performs due reverts) |
| `POST /api/v1/response/incidents/keep` `{account, actor}` | keep an automatic lock: no auto-revert |
| `POST /api/v1/response/incidents/revert` `{account, actor}` | lift an automatic lock now |
| `GET /api/v1/response/executions?limit=&alert_id=` | every dispatch, newest first, with commands |
| `GET /api/v1/response/pending` | actions waiting for a person |
| `POST /api/v1/response/approve` `{alert_id, action, approver, note}` | release one reserved action (dispatches immediately in the current mode) |
| `POST /api/v1/response/mode` `{mode, actor}` | switch off / dry_run / armed |
| `GET /api/v1/alerts/{id}/response` | the plan for one alert with its records and pending actions |

All mutations are protected by `GRAPHSENTINEL_API_KEY` when one is configured.

## Restart safety

Records are durable (SQLite, WAL) when a database is configured. On start the
coordinator replays the store and re-registers every settled dispatch, so a
restart cannot re-fire an action that already ran, and a pending approval
survives to be approved later. A replayed batch is refused upstream by the
detection service (409) before the coordinator is ever asked.

The loop's own state is replayed too. Every `lock_account` the system applied
and has not lifted is re-adopted with the revert time the original escalation
chose, so a restart inside the window lifts the lock when it was always going
to be lifted; the console labels such a lock as re-adopted rather than
pretending it was decided live. An analyst's **keep** is written to the store
as a `kept` record for the same reason: a decision held only in memory would
be undone by the next restart, re-enabling an account a person chose to hold.
Without this, doubling the window to two hours would have doubled the time in
which a restart could strand a disabled account with nothing left to lift it.

## Validation status

The connectors' command plans are correct by specification and have not been
run against a live directory: this environment has no lab domain. That is
precisely why `dry_run` is the default and the executing backend is opt-in.
Closing that gap needs a lab Active Directory, which is open item 8.
