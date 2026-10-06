# The analyst-facing agent: what a language model is allowed to do here

A detector that acts on its own has to be able to explain itself, and prose is
what an analyst reads at three in the morning. That is the whole job a
language model has in this product: **phrase an explanation over facts the
detector already produced.** It scores nothing, decides nothing, and dispatches
nothing.

It is opt-in (`GRAPHSENTINEL_TRIAGE_AGENT=1`), local (Ollama on the same
machine — no telemetry leaves the estate), and every output it produces is
checked against the bundle it was given before anyone sees it.

## Two documents

| | unit | route | module |
|---|---|---|---|
| **Triage report** | one alert | `POST /api/v1/alerts/{id}/triage` | `explain/agent.py` |
| **SOC incident report** | one account: every alert, every action, the escalation | `POST /api/v1/soc/incidents/{account}/report` | `explain/soc_report.py` |

Triage answers "why is this event in my queue". The SOC report is the
handover: by the time the prevention loop has contained an account, escalated
and scheduled a revert, the analyst picking it up has a dozen alerts and twice
as many dispatch records to reconstruct, and the question is "what happened to
this account, what did the system already do, and what is left for me".

## The contract

Both documents are written over a **bundle** — evidence items (`E-nnn`) for an
alert, facts (`F-nnn`) for an incident — and both are validated before they
are returned:

1. **Citations must exist.** Every statement carries ids; an id that is not in
   this bundle is a rejection, not a warning.
2. **Detector conclusions are copied, never authored.** The ATT&CK mapping on
   a triage report, and the severity, window, host list and action records on
   a SOC report, are taken from the detector and the store. A report that
   misstates which command ran is worse than no report.
3. **Response claims must cite an action.** Every sentence in "what the system
   did" must cite an `action` or `escalation` fact, so the section cannot
   become plausible-sounding response theatre.
4. **Identifiers must be real.** An alert id named in the prose must belong to
   this incident: a wrong one is an identifier an analyst will paste into a
   search box.
5. **Verification before disruption.** The first recommended step on a SOC
   report is a verification, never an approval to isolate or block. That is
   how a false positive becomes an outage.
6. **No speculation.** The prompt forbids attacker intent, malware and data
   theft that the evidence does not establish, and the model is told it has no
   other knowledge of the network.

## The loop, and why it is a graph

`prepare → draft → validate → repair`, compiled with LangGraph, at most three
attempts. The control flow is declared up front, so the sequence is
inspectable and bounded, and the validator is a conditional edge inside the
graph rather than a hopeful post-check. A rejection names the exact contract
breach in the repair prompt, so the retry is targeted rather than a vague plea
for better output.

If the model cannot ground its output within the attempt budget — or is
unreachable, or returns something that is not JSON — the **deterministic
writer** produces the same document from the same bundle, more plainly.
Enabling the agent can change how the prose reads; it cannot change whether a
report exists or whether it is true.

## Provenance is never hidden

Every response carries `X-Triage-Provider`, `X-Triage-Fallback` and
`X-Triage-Trace` (`prepare|draft#1|validate:accepted`), the console shows a
badge, and the server logs the same. An analyst acting on a report needs to
know whether they are reading a template or model prose that fell back, and an
audit of a security decision needs it more.

## Running it

```bash
ollama serve                      # local model host
ollama pull qwen3.5:4b            # the default; any Ollama model works

GRAPHSENTINEL_TRIAGE_AGENT=1 \
GRAPHSENTINEL_OLLAMA_MODEL=qwen3.5:4b \
GRAPHSENTINEL_OLLAMA_HOST=http://127.0.0.1:11434 \
python -m graphsentinel.api.run
```

Measured on this project's own bundles with `qwen3.5:4b` on a laptop CPU/GPU:
a triage report takes ~8 s, a SOC report over a five-alert incident ~30 s, both
accepted on the first attempt. `qwen3.5:4b` was chosen over `llama3.2:3b`
because it grounds more statements across more evidence ids and produces
specific recommendations; it needs `think=False` (set in `ollama_generate`) or
its reasoning trace consumes the whole token budget and the report comes back
empty.

Offline, without a server, from a durable database:

```bash
graphsentinel soc-report --database artifacts/graphsentinel.db                      # candidates
graphsentinel soc-report --database artifacts/graphsentinel.db \
    --account 'C2287$@DOM1' --agent --out incident.md
```

## What is tested

`tests/test_triage_agent.py` and `tests/test_soc_report.py` inject a fake
generator: the guarantees must hold whatever model is behind them, and CI
cannot depend on a local model host being up. Between them they cover a
grounded response being accepted without fallback, fabricated citations never
reaching output, a response claim that cites no action being rejected, an
invented alert id being rejected, the model being unable to rewrite the
detector's actions or raise its own severity, an unreachable model still
producing a report, and the retry budget being bounded with the repair prompt
naming the actual violation.
