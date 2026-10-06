from rc_api import CH, FIG, P, SEC, SUB, TAB

CH(3, "SYSTEM DESIGN")
SEC("3.1", "INTRODUCTION")
P("System design translates the objectives of Chapter 1 into components, interfaces and data flows that can "
  "be implemented, tested and deployed. The design of GraphSentinel is governed by three principles that "
  "follow from the literature survey. The first is **causality**: nothing that the model uses to judge an "
  "event may depend on that event or on anything after it, so every component processes one ordered stream "
  "of events and reads state only as it existed before the event. The second is **bounded autonomy**: the "
  "system may act without a person only through reversible actions, only above a threshold with a known "
  "lower bound on precision, and only within hourly and per-account budgets; every other action waits for an "
  "analyst. The third is **traceability**: every score, alert, action, approval and generated sentence can be "
  "traced back to the recorded evidence that produced it.")
P("The design is modular. Ingestion, feature computation, model scoring, fusion, response and reporting are "
  "separate modules with narrow interfaces, so that each can be tested on its own and replaced without "
  "changing the others. For example, the temporal graph network is injected into the response planner as a "
  "scorer, which allowed the prevention instrument described in Chapter 4 to evaluate the production decision "
  "logic unchanged. The whole system runs as a single Python process that exposes a FastAPI service, serves a "
  "browser console and persists its state in a local SQLite store, which makes it easy to deploy on one "
  "server or a laptop.")

SEC("3.2", "SYSTEM ARCHITECTURE")
P("{fig:arch} shows the layered architecture of GraphSentinel. Authentication logs enter at the top and flow "
  "through four layers. Analyst services at the bottom make the results usable by people.")
FIG("arch", "r_architecture.png", 5.75, "System Architecture Diagram")
P("The **ingestion layer** accepts records from the supported log sources. When the format is not declared, "
  "the format detector samples the input, scores each candidate adapter by how well the columns and values "
  "match what the adapter expects, and reports the chosen adapter together with warnings about ambiguous "
  "fields. Each adapter emits canonical events. The entity dictionary assigns every account and host a "
  "stable integer identifier; it is frozen together with the model checkpoint so that identifiers mean the "
  "same thing at training and serving time, and names never seen before are hashed into 4,096 account and "
  "16,384 host out-of-vocabulary buckets.")
P("The **model layer** holds the causal feature engine and the temporal graph network. The feature engine "
  "keeps rolling counters and first-seen sets for accounts, hosts and account-host pairs and computes 27 "
  "features per event. The temporal graph network keeps a 64-dimensional memory for each of 63,397 entity "
  "slots, scores each event from the memories as they were before the event, and then updates them. The warm "
  "state store saves feature counters and node memories to disk so that a restart resumes with the history "
  "intact instead of starting cold.")
P("The **decision layer** combines the model's probability with explicit evidence channels through a "
  "noisy-OR gate, applies the chain rule, and compares the resulting risk with the alert threshold "
  "(0.329) and the execution gate (0.846). The **response layer** contains the response coordinator, which "
  "enforces budgets and runs the contain-verify-escalate-revert loop, and the executor, which turns each "
  "planned action into a concrete command for a connector (directory service, endpoint agent or host "
  "firewall), records the command and its undo, and executes it only when the operator has armed the "
  "connector. The **analyst services** include the path ranker, which assembles time-respecting multi-hop "
  "paths from recently scored edges, the grounded report agent, the case and incident store, the audit log, "
  "the REST and WebSocket API, and the browser console.")

SEC("3.3", "SYSTEM REQUIREMENTS")
P("This section lists the software, functional, non-functional and hardware requirements of the system. The "
  "software and hardware listed are those on which the project was developed, trained and evaluated.")
SUB("3.3.1", "Software Requirements")
TAB("software", "Software Tools", [1900, 2550, 3856],
    [["Component", "Technology", "Role"],
     ["Programming language", "Python 3.13", "Implementation of ingestion, features, model, decision and response logic"],
     ["Deep learning", "PyTorch 2.11 with CUDA 12.8 [@pytorch]", "Temporal graph network training and inference on the GPU"],
     ["Classical ML", "scikit-learn 1.7", "Logistic regression and isolation-forest baselines"],
     ["Data handling", "Polars, PyArrow, NumPy", "Reading billions of log rows, Parquet storage, numerical work"],
     ["Web service", "FastAPI 0.115, Uvicorn", "REST API (69 routes) and WebSocket live feed"],
     ["Storage", "SQLite", "Alerts, cases, incidents, response records and audit log"],
     ["Report agent", "LangGraph 1.2, Ollama, qwen3.5:4b", "Local, grounded generation of triage notes and SOC reports"],
     ["Frontend", "HTML, CSS, JavaScript", "Single-page analyst console with live graph and panels"],
     ["Response connectors", "PowerShell AD cmdlets, Microsoft Graph", "Session logoff, token revocation, account lock and unlock"],
     ["Visualisation", "Matplotlib", "Evaluation charts and research figures"],
     ["Quality", "pytest, Ruff, mypy", "755 automated tests, linting and static type checking"],
     ["Operating system", "Windows 11 (Linux supported)", "Development, training and deployment environment"]],
    aligns=["left", "left", "left"], size=10.5)

SUB("3.3.2", "Functional Requirements")
TAB("functional", "Functional Requirements", [700, 2300, 5306],
    [["S. No", "Functional Requirement", "Description"],
     ["1", "Log ingestion", "Read authentication logs from LANL, Windows Security, SSH, Zeek, Entra ID, Okta and "
      "CSV/JSON sources and detect the format automatically when it is not declared."],
     ["2", "Live event scoring", "Accept batches of events through the API, reject out-of-order timestamps, and "
      "return a risk score for every event."],
     ["3", "Causal features", "Compute 27 features per event using only information from earlier events."],
     ["4", "TGN detection", "Score each event with the temporal graph network before updating node memory."],
     ["5", "Evidence fusion", "Fuse the model probability with novelty, burst, pivot and corroboration evidence "
      "and apply the novel-hop chain rule."],
     ["6", "Alerting", "Raise an alert when the fused risk crosses the alert threshold and attach its evidence "
      "and MITRE ATT&CK technique."],
     ["7", "Autonomous containment", "Force re-authentication when the risk crosses the execution gate and the "
      "hourly and per-account budgets allow it."],
     ["8", "Verification and escalation", "Escalate to a reversible account lock if the contained account "
      "qualifies again within 30 minutes; lift the lock after two hours unless kept."],
     ["9", "Analyst approval", "Let an analyst approve pending actions, keep or lift a lock, and switch the "
      "response mode between off, dry-run and armed."],
     ["10", "Path and incident analysis", "Rank suspicious multi-hop paths and group related alerts into "
      "incidents and investigation cases."],
     ["11", "Grounded reporting", "Generate triage notes and SOC incident reports whose statements cite "
      "recorded evidence; fall back to a deterministic writer."],
     ["12", "Audit and export", "Record every action with its command and undo, and export alerts in SIEM "
      "formats."]],
    aligns=["center", "left", "left"], size=10.5)

SUB("3.3.3", "Non-Functional Requirements")
TAB("nonfunctional", "Non-Functional Requirements", [2100, 6206],
    [["Requirement", "Description"],
     ["Causality", "No feature or score may use the event being judged or any later event; enforced in code "
      "and asserted by regression tests."],
     ["Safety", "Only reversible actions may run without approval; automatic actions are capped at 20 per hour "
      "and one per account per hour; connectors start in dry-run mode."],
     ["Reproducibility", "Every model artifact records the SHA-256 of its dataset, features and entity "
      "dictionary; evaluations use fixed seeds and report bootstrap intervals."],
     ["Performance", "The live service must keep pace with streaming input; it scored 315 events per second "
      "on the development laptop and reproduced offline PR-AUC to five decimal places."],
     ["Resilience", "Feature counters, node memories and active locks survive a restart; a failed connector "
      "must not lose the record of an action."],
     ["Privacy", "The language model runs locally; no log data leave the host."],
     ["Explainability", "Every alert carries its evidence; every generated statement cites a recorded fact."],
     ["Maintainability", "Modular packages, strict type checking and 755 automated tests."]],
    aligns=["left", "left"], size=10.5)

SUB("3.3.4", "Hardware Requirements")
TAB("hardware", "Hardware Requirements", [1700, 2550, 4056],
    [["Component", "Specification Used", "Justification"],
     ["Processor", "AMD Ryzen 7 7840HS (8 cores)", "Parsing large log files, feature computation and the API service"],
     ["Memory (RAM)", "16 GB", "Holding feature state, node memories and evaluation data in memory"],
     ["GPU", "NVIDIA GeForce RTX 3050 Laptop, 6 GB", "Training and batch inference of the temporal graph network; "
      "local language model"],
     ["Storage", "SSD with at least 20 GB free", "The compressed LANL authentication file alone is 7.6 GB, plus intermediate Parquet files"],
     ["Display", "1080p monitor", "Analyst console with live graph and dashboards"],
     ["Network", "Local network access to log sources", "Receiving events; internet is not required at run time"]],
    aligns=["left", "left", "left"], size=10.5)

SEC("3.4", "DATA FLOW DIAGRAM / USE CASE DIAGRAM")
SUB("3.4.1", "Data Flow Diagram (DFD)")
P("{fig:dfd} shows the level-1 data flow diagram. Rectangles are external entities, rounded boxes are "
  "processes and open boxes are data stores. Raw authentication records from the log sources enter process "
  "1.0, which normalises them into canonical events using the entity dictionary (D1). Process 2.0 computes "
  "the causal features, reading and updating the feature counters in D2, and process 3.0 scores the event "
  "with the temporal graph network, reading the node memories in D2 before updating them. Process 4.0 fuses "
  "the probability with the explicit evidence and applies the chain rule, and process 5.0 decides whether the "
  "fused risk raises an alert, clears the execution gate and fits within the budget. Alerts are stored in D3. "
  "Action plans flow to process 6.0, which contains, verifies, escalates and reverts, sends commands and their "
  "undo to the directory, endpoint and firewall systems, and writes action records to the audit trail in D3. "
  "Process 7.0 reads the facts of an incident from D3 and produces grounded reports for the SOC analyst, whose "
  "approve, keep and lift decisions flow back into process 6.0.")
FIG("dfd", "r_dfd.png", 5.75, "Data Flow Diagram")
SUB("3.4.2", "Use Case Diagram")
P("{fig:usecase} shows the actors of the system and the use cases they participate in. The **SOC analyst** "
  "monitors the live dashboard, investigates alerts and their evidence, explores suspicious paths and attack "
  "chains, generates triage notes and incident reports, and approves, keeps or lifts response actions. The "
  "**security administrator** onboards new log sources, configures the response mode (off, dry-run or armed) "
  "and trains and evaluates models. Three system actors complete the picture: the **log source** (a domain "
  "controller or SIEM forwarder) streams events for scoring, the **local language model** served by Ollama "
  "drafts reports, and the **directory or EDR connector** executes containment, both automatically for "
  "reversible actions and after approval for the others.")
FIG("usecase", "r_usecase.png", 5.4, "Use Case Diagram")
SUB("3.4.3", "Sequence Diagram")
P("{fig:sequence} traces a single batch of events through the system. The log source posts the batch to the "
  "API gateway, which rejects a batch that does not begin after the last event already processed, because an "
  "out-of-order event would let the model see the future; events that share a timestamp must arrive in the "
  "same batch, and a batch that fails part-way is rolled back. For each event the feature engine computes the feature vector from earlier "
  "events only, and the TGN scorer produces a probability from the memories as they were before the event and "
  "only then updates them. The fusion step computes the fused risk and applies the chain-rule floor. An alert "
  "is stored when the risk crosses the alert threshold; when it also crosses the execution gate, the response "
  "coordinator checks the budget and the 30-minute verification window, and the executor runs force_reauth or, "
  "on escalation, lock_account through a dry-run or armed connector. The command, its undo and the outcome are "
  "recorded, the revert timer starts, and the API returns the risks and alert identifiers while the console "
  "receives the update over a WebSocket.")
FIG("sequence", "r_sequence.png", 5.75, "Sequence Diagram for Scoring a Batch of Events")
