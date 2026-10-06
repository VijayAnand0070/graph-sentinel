from rc_api import BUL, CH, EQ, FIG, P, SEC, SUB, TAB

CH(4, "PROJECT DESCRIPTION")
SEC("4.1", "METHODOLOGIES")
P("The project follows the eight-stage methodology shown in {fig:method}. Each stage produces an artifact that "
  "the next stage consumes and that records its own provenance, so every number reported in Chapter 5 can be "
  "regenerated from the raw data.")
FIG("method", "r_methodology.png", 5.75, "Methodology")
P("**Stage 1: data acquisition.** The LANL authentication file (1,051,430,459 events, 7.6 GB compressed) and "
  "the red-team file (749 events) were downloaded, registered with their checksums and verified row by row: "
  "timestamps run from 1 to 5,011,199 seconds and no row is malformed. For external validation, 29 lateral-"
  "movement recordings of Windows Security telemetry were obtained from the OTRF Security Datasets project.")
P("**Stage 2: pre-processing.** Local logons, in which the source and destination computer are the same, make "
  "up 53.8% of the raw stream and never represent movement between hosts; none of them is labelled as an "
  "attack, so the ingestion now drops them. The corpus behind the shipped model was built before this "
  "correction and still contains them, which is why a second, corrected corpus was built for comparison. "
  "Because the full stream is far too large to train on with a laptop GPU, every event matching a red-team "
  "record is kept and benign events are stride-sampled (one in 512 for the corpus behind the shipped model, "
  "one in 448 for the corrected corpus). Account and host names are mapped to "
  "integer identifiers by the entity dictionary. The data are split chronologically into training, "
  "validation and test partitions, so that the model is always tested on a period later than the one it was "
  "trained on and each partition holds complete campaigns.")
P("**Stage 3: causal feature engineering.** For every event, 27 features are computed from the events that "
  "precede it (Section 4.2.2). **Stage 4: TGN training.** The temporal graph network is trained on the "
  "training partition with a class-weighted loss, selecting the epoch with the best validation PR-AUC "
  "(Section 4.2.3). **Stage 5: fusion and rule calibration.** The reliabilities of the noisy-OR gate are "
  "fitted on validation data, and the chain rule is priced on an unsampled day of LANL traffic, because "
  "sampled data hide most benign multi-hop patterns (Section 4.2.4). **Stage 6: threshold derivation.** The "
  "alert threshold is chosen on validation data at a budget of 25 false positives per 10,000 benign events, "
  "and the execution gate from a Wilson lower bound on precision (Section 4.2.5).")
P("**Stage 7: evaluation.** The frozen system is compared with baseline detectors on the sealed test "
  "partition with bootstrap confidence intervals, re-evaluated with the dominant attacker held out, ablated to "
  "see what the memory contributes, replayed against 100 simulated campaigns to measure prevention, and run "
  "without retraining on the external OTRF data (Section 4.2.9 and Chapter 5). **Stage 8: deployment.** The "
  "model, dictionary, thresholds and warm state are served by the FastAPI service together with the response "
  "loop, the report agent and the analyst console.")

SEC("4.2", "MODULE DESCRIPTION")
P("GraphSentinel is organised into nine modules. Each is described below with its inputs, processing and "
  "outputs, and with the equations it implements.")

SUB("4.2.1", "Log Ingestion and Format Detection Module")
P("This module turns heterogeneous log records into one ordered stream of canonical events. Each supported "
  "format has an adapter ({tab:sources}). The Windows adapter reads the five authentication events that matter "
  "for lateral movement: 4624 (successful logon), 4625 (failed logon), 4768 (Kerberos ticket-granting ticket "
  "request), 4769 (Kerberos service ticket request) and 4776 (NTLM credential validation). It discards "
  "high-volume system identities such as SYSTEM, LOCAL SERVICE, NETWORK SERVICE and ANONYMOUS LOGON, which "
  "carry no signal about movement between machines, and it canonicalises host names so that different "
  "spellings of the same machine, including IPv4-mapped IPv6 addresses and loopback addresses, resolve to one "
  "node.")
TAB("sources", "Supported Log Sources", [1900, 2600, 3806],
    [["Source", "Adapter input", "Mapping to the canonical event"],
     ["LANL", "auth.txt.gz (CSV)", "time, source and destination user and computer, authentication type, logon "
      "type, orientation, success or failure"],
     ["Windows Security", "JSON from Winlogbeat, Splunk, Elastic or OTRF exports", "events 4624, 4625, 4768, "
      "4769 and 4776; account, workstation or IP address, target host, logon type, outcome"],
     ["Linux SSH", "sshd lines from auth.log or secure", "Accepted and Failed lines; account, client address, the "
      "host that wrote the line"],
     ["Zeek", "kerberos.log and ntlm.log (JSON or TSV)", "Kerberos service-ticket requests and NTLM "
      "authentications observed on the network"],
     ["Microsoft Entra ID", "Graph sign-in logs (JSON)", "user principal name; device name or IP address as "
      "source; resource or application as destination; error code as outcome"],
     ["Okta", "System Log (JSON)", "session starts and application sign-ons"],
     ["Generic", "CSV or JSON lines with a column map", "operator names the columns for time, user, source, "
      "destination and success"]],
    aligns=["left", "left", "left"], size=10.5)
P("When the operator does not name the format, the detector reads a sample of the input and scores every "
  "adapter on how well the column names and values match what it expects. It selects the best adapter, "
  "reports its choice, and warns about fields it could not map. On the 29 OTRF recordings it recognised every "
  "file as Windows Security JSON without configuration.")

SUB("4.2.2", "Causal Feature Engineering Module")
P("Each canonical event is represented as in {eq:event}, where *u*_{*k*} is the account, *s*_{*k*} and "
  "*d*_{*k*} are the source and destination hosts, *t*_{*k*} is the time, *o*_{*k*} is the outcome and "
  "**x**_{*k*} is a 27-dimensional feature vector. The feature map Φ is computed from the history ℋ of events "
  "strictly before *t*_{*k*}; no feature can therefore encode the future or the label.")
EQ("event")
P("The features fall into five groups ({tab:features}). The engine maintains rolling windows of 5 minutes, 15 "
  "minutes, 1 hour and 24 hours, first-seen sets for accounts, account-destination pairs and hosts, and "
  "degree counters. Twelve of the features are cumulative, so the engine saves its state to disk and restores "
  "it on restart; a service that restarted cold would otherwise treat every familiar pair as new. Before they "
  "enter the model, the features are standardised with a per-feature centre and scale stored in the "
  "checkpoint.")
TAB("features", "Groups of the 27 Causal Features", [1900, 800, 5606],
    [["Group", "Count", "Features"],
     ["Event attributes", "6", "success, authentication type, logon type, orientation, hour of day (sine and "
      "cosine)"],
     ["Recency", "2", "logarithm of the time since the account's previous event and since the pair's previous "
      "event"],
     ["Novelty and rarity", "6", "account seen before, pair seen before, new pair, pair rarity, destination "
      "novelty, rare-logon score"],
     ["Windowed behaviour", "8", "pair frequency in 1 h; distinct destinations of the account in 5 min, 1 h and "
      "24 h; authentication rate in 5 min; failure rate and failures before success in 15 min; share of new "
      "destinations in 1 h"],
     ["Graph structure", "5", "distinct destinations of the source host in 1 h, distinct inbound users of the "
      "destination in 1 h, historical degrees of the account, the source host and the destination"]],
    aligns=["left", "center", "left"], size=10.5)

SUB("4.2.3", "Temporal Graph Network Detection Module")
P("Accounts and hosts are the nodes of a temporal graph, and each logon is a timestamped edge from an account "
  "and its source host to a destination host. Every node *i* has a memory vector **m**_{*i*} ∈ ℝ^{64} that "
  "summarises its past. {fig:tgn} shows how the model processes one event.")
FIG("tgn", "fig2_tgn.png", 4.6, "Temporal Graph Network Scorer")
P("**Time encoding.** The time Δ*t* since a node was last updated is encoded with a learnable harmonic "
  "function {eq:time}, in which **ω** and **φ** are learned 16-dimensional frequencies and phases. The "
  "logarithm compresses gaps that range from seconds to weeks, so that three seconds and three days are "
  "genuinely different inputs.")
EQ("time")
P("**Scoring.** For event *e*_{*k*}, the scorer concatenates the memories of the account and of both hosts, "
  "the standardised features and the two time encodings {eq:concat}, and maps the result to a probability "
  "through a two-layer network *g* with LayerNorm, GELU activation and dropout, plus a linear residual "
  "projection **P** that keeps gradient paths short {eq:score}. Here σ is the logistic function.")
EQ("concat")
EQ("score")
P("**Memory update.** Only after an event has been scored does it change the memories. A message function *h* "
  "forms one message for each endpoint from its own memory, the memory of the other endpoint, the features and "
  "the time encodings {eq:message}. When several messages reach node *i* within the same batch, they are "
  "weighted by attention {eq:attn}, and their normalised weighted sum updates the memory through a gated "
  "recurrent unit {eq:gru}.")
EQ("message")
EQ("attn")
EQ("gru")
P("Scoring before updating guarantees that each event is judged by the state that existed before it; the "
  "implementation enforces this order and a regression test asserts it. For speed, events are processed in "
  "60-second buckets, which made training 20.7 times and inference 16.9 times faster; within a bucket memory "
  "is still read before any write.")
P("**Training.** The model is trained with the class-weighted binary cross-entropy {eq:loss}, where *y*_{*k*} "
  "is 1 for a red-team event and *β* is the ratio of benign to attack events in the training partition, capped "
  "at 120 because attacks are about one event in a thousand. {tab:hyper} lists the configuration of the "
  "shipped model.")
EQ("loss")
TAB("hyper", "Configuration of the Temporal Graph Network", [3500, 4806],
    [["Parameter", "Value"],
     ["Memory dimension / time-encoding dimension / hidden units", "64 / 16 / 96"],
     ["Input features per event", "27"],
     ["Entity slots", "63,397 (33,650 accounts, 29,747 hosts)"],
     ["Out-of-vocabulary buckets", "4,096 accounts, 16,384 hosts"],
     ["Trainable parameters", "107,585"],
     ["Optimiser", "AdamW, learning rate 0.001, weight decay 0.01"],
     ["Loss", "Weighted binary cross-entropy, positive weight capped at 120"],
     ["Dropout", "0.15"],
     ["Epochs / early-stopping patience", "16 / 5"],
     ["Truncated back-propagation", "every 2,048 events"],
     ["Batching", "60-second time buckets, score before update"],
     ["Random seed", "1729"]],
    aligns=["left", "left"], size=10.5)

SUB("4.2.4", "Evidence Fusion and Chain Rule Module")
P("The learned probability is combined with four explicit evidence channels: novelty (a new relationship), "
  "burst (a sudden increase in the account's activity), pivot (the account continuing from a host it just "
  "reached) and corroboration (confirmation from another log source). The original design used a weighted "
  "average whose weights summed to one. That operator gives the learned score a veto: with 0.55 on the model, "
  "the other channels could reach at most 0.45, which was below the alert threshold then in use, so no amount "
  "of explicit evidence could raise an alert by itself. GraphSentinel therefore uses a noisy-OR gate "
  "[@pearl] {eq:noisyor}, in which each channel *c* with signal *s*_{*k*,*c*} ∈ [0, 1] has an independent "
  "reliability *r*_{*c*}. The reliabilities, fitted on validation data by coordinate ascent on PR-AUC, are "
  "0.95 for the model, 0.35 for corroboration, 0.30 for burst and 0.05 for novelty and pivot. Any single "
  "strong channel can carry an alert, weak channels compound, and adding evidence never lowers the risk.")
EQ("noisyor")
P("The **chain rule** turns the path intuition of Hopper [@hopper] into a streaming test. Let ℛ_{*u*} be the "
  "set of hosts that account *u* has successfully reached before *t*_{*k*}, and let *n*_{*u*} be the number of "
  "novel hops that *u* has made within the previous 1,800 seconds. An event is a chain hop {eq:chain} when it "
  "succeeds, starts from a host that the account has reached, lands on a host that the account has never "
  "reached, and follows at least three such novel hops. Novelty is judged only from successful logons: if "
  "failed attempts counted as sightings, an attacker who guessed a password once before each hop would make "
  "every hop look familiar. When the rule fires, the fused risk is raised to a floor {eq:floor}; in the "
  "autonomous policy the floor equals the execution gate *τ*_{*x*}, so a confirmed chain can trigger "
  "containment.")
EQ("chain")
EQ("floor")

SUB("4.2.5", "Execution Gate Module")
P("Two thresholds are applied to the fused risk *ρ*_{*k*}. The alert threshold *τ*_{*a*} = 0.329 admits events "
  "to the analyst queue and was chosen on validation data at 25 false positives per 10,000 benign events. The "
  "execution gate *τ*_{*x*} decides when the system may act without a person, so it is derived from a "
  "statistical guarantee rather than a guess. For a candidate threshold, let *n* be the number of validation "
  "alerts above it and *p̂* their precision. The Wilson score interval [@wilson] gives the lower bound "
  "{eq:wilson} with *z* = 1.96 for 95% confidence. The gate is the lowest threshold for which every candidate "
  "at or above it keeps this lower bound at 0.75 or more {eq:gate}, considering only candidates with at least "
  "20 alerts.")
EQ("wilson")
EQ("gate")
P("On the corpus behind the shipped model this gives *τ*_{*x*} = 0.846, which admits 251 validation alerts at "
  "80.5% precision with a lower bound of 75.1%. The same constant is stored together with its realised test "
  "precision (Chapter 5), because a threshold that means 75% at derivation time can mean less on a later "
  "period.")

SUB("4.2.6", "Bounded Automatic Response Module")
P("This module turns decisions into actions. The catalogue in {tab:actions} lists every action the system "
  "can request, how disruptive it is on a scale from 0 to 5, whether it can be undone, and when it may run "
  "without a person. The rule is simple: nothing irreversible and nothing highly disruptive ever runs "
  "automatically.")
TAB("actions", "Response Action Catalogue", [2250, 1250, 1250, 3556],
    [["Action", "Disruption", "Reversible", "Runs automatically"],
     ["increase_monitoring", "0", "Yes", "Always (invisible to the user)"],
     ["notify_soc", "0", "Yes", "Always (routes the alert with its evidence)"],
     ["force_reauth", "1", "Yes", "When *ρ* ≥ *τ*_{*x*} and the budget allows"],
     ["lock_account", "3", "Yes", "Only as escalation after a failed containment; otherwise needs approval"],
     ["block_network_path", "3", "Yes", "Never; needs approval"],
     ["disable_service_account", "4", "Yes", "Never; needs approval"],
     ["reset_credentials", "4", "No", "Never; needs approval"],
     ["isolate_host", "5", "Yes", "Never; needs approval"]],
    aligns=["left", "center", "center", "left"], size=10.5)
P("{fig:loop} shows the prevention loop, which automates the containment outcome of the NIST incident-response "
  "guidance [@nist61] for credential-based movement. **Contain:** when *ρ*_{*k*} ≥ *τ*_{*x*} and the budget "
  "{eq:budget} allows it, the coordinator forces re-authentication: the account is logged off its source host "
  "and its cloud refresh tokens are revoked. In {eq:budget}, 𝒟(*t* − 3600, *t*] is the set of automatic actions "
  "in the preceding hour and *t*^{last}_{*u*} is the time of the last automatic action on account *u*. "
  "**Verify:** a session reset can fail, for example because Kerberos tickets that were already issued stay "
  "valid, so the coordinator watches the account on the attacker's clock. **Escalate:** if the account "
  "qualifies for an automatic action again within 1,800 seconds of its containment at *t*^{*c*}_{*u*} "
  "{eq:escalate}, the containment did not hold and the loop locks the account; the escalation is exempt from "
  "the per-account condition but still counts against the hourly cap. **Revert:** the lock lifts automatically "
  "after two hours unless an analyst keeps it, which leaves time for a decision without letting a false "
  "positive keep a user locked out for a working day.")
EQ("budget")
EQ("escalate")
FIG("loop", "fig3_loop.png", 4.8, "Bounded Contain-Verify-Escalate-Revert Loop")
P("The executor turns each planned action into a concrete command for a connector and records the command, "
  "its undo and the outcome. For force_reauth on Windows the command logs the account off the source host "
  "through PowerShell remoting and revokes its sign-in sessions through Microsoft Graph; lock_account runs "
  "Disable-ADAccount, and its undo runs Enable-ADAccount. The response mode can be off, dry-run or armed. In "
  "dry-run mode, the default, every step is planned and recorded but nothing is executed, which lets an "
  "organisation observe the system's behaviour on its own traffic before arming it. Active locks are stored "
  "durably and adopted again after a restart, so a restart can never leave an account locked with nothing "
  "left to lift it.")

SUB("4.2.7", "Grounded Report Agent Module")
P("Analysts need readable summaries, but a language model must not be allowed to invent evidence. The report "
  "agent is a LangGraph workflow ({fig:agent}) over a locally hosted model, qwen3.5:4b served by Ollama, so no "
  "log data leave the host. **Prepare** assembles an evidence bundle in which every fact has an identifier "
  "(E-nnn for the evidence of one alert, F-nnn for the facts of an incident). **Draft** asks the model for a "
  "structured report in JSON. **Validate** rejects the draft if any statement cites an identifier that does "
  "not exist, names an alert that is not part of the incident, describes an automatic action without citing "
  "an action record, or changes the severity, alerts, hosts or actions recorded by the detector. **Repair** "
  "sends the draft back with the exact violation named, and the loop runs at most three attempts. If the "
  "model still fails, or cannot be reached, a deterministic writer produces the report from the same facts.")
FIG("agent", "r_agent.png", 5.75, "Workflow of the Grounded Report Agent")
P("Every response states which path produced it, through a badge in the console and through response headers "
  "(provider, fallback flag and trace), so an analyst always knows whether they are reading model prose or the "
  "template. The prompt also requires the first step recommended to the analyst to be a verification, such as "
  "confirming the activity with the account owner, rather than an approval to isolate or block. On the "
  "project's incidents a triage note took about 8 seconds and a five-alert SOC report about 30 seconds on the "
  "laptop. The same grounding contract is used to explain suspicious paths: an explanation is rejected if it "
  "names any host or account outside the path.")

SUB("4.2.8", "Analyst Console, API and Case Management Module")
P("The FastAPI service exposes 69 routes. The most important are POST /api/v1/live/events for scoring event "
  "batches; GET /api/v1/alerts and GET /api/v1/paths for alerts and ranked paths; the /api/v1/response routes "
  "for approving actions, keeping or reverting locks and changing the response mode; the /api/v1/soc routes "
  "for incident reports; a SIEM export route; Prometheus metrics; and the WebSocket /ws/events that pushes every "
  "scored event to the console.")
P("The console is a single-page application with eleven panes: Overview and Live Graph, Live Stream Demo, "
  "Attack Chains, Alert Queue, Suspicious Paths, Incidents, Automatic Response, TGN Model Lab, Detection "
  "Engineering, Research Evidence and Pipeline Telemetry. The **path ranker** searches recently scored edges "
  "for time-respecting paths of up to five hops in which each newly reached host later authenticates onward "
  "within 1,800 seconds, without repeating a host and with every edge above a risk of 0.5, and ranks them with "
  "the score {eq:pathscore}, where r̄ is the mean edge risk, *ν* the share of new relationships, *π* the pivot "
  "density and *ε* the evidence support. The console also groups persisted alerts into incidents with a "
  "Louvain modularity pass over a graph of shared entities and temporal proximity, and analysts can open "
  "investigation cases, add notes and export alerts as CSV or JSON.")
EQ("pathscore")

SUB("4.2.9", "Evaluation and Prevention Instrument Module")
P("The evaluation module scores every detector on identical partitions. Precision and recall are defined in "
  "{eq:prec} from true positives (TP), false positives (FP) and false negatives (FN). Because attacks are "
  "rare, the primary metric is the area under the precision-recall curve (PR-AUC) [@saito], computed as the "
  "average precision {eq:ap} over events ranked by score, where *P*_{*n*} and *R*_{*n*} are the precision and "
  "recall at the *n*-th threshold. The cost of false alarms is reported as false positives per 10,000 benign "
  "events {eq:fp}, where *N*_{*b*} is the number of benign events. Confidence intervals come from 2,000 "
  "stratified bootstrap resamples [@efron], and detectors are compared on identical resamples.")
EQ("prec")
EQ("ap")
EQ("fp")
P("A recorded dataset cannot show what an automatic response prevents, because nothing in it is "
  "counterfactual: the red team's fifth hop happened whether or not the fourth was detected. The prevention "
  "instrument therefore replays campaigns of known length through the production decision logic (features, "
  "TGN with restored memory, channels, chain rule, fusion, thresholds and response planner). Benign traffic is "
  "resampled from each user's own history, and the attacker operates from an ordinary busy workstation that "
  "also carries benign activity, so the attacker's identity alone cannot give it away. Two campaign families "
  "are generated: a chain, in which one credential is carried from host to host, and a fan-out, in which one "
  "host uses several harvested credentials. The prevented fraction {eq:prevent} counts the hops that follow the "
  "first automatic action, where 𝒜 is the set of campaigns that received one, *N* is the number of campaigns, "
  "*L* = 8 is the campaign length and *a*_{*c*} is the index of the hop that triggered the action.")
EQ("prevent")
