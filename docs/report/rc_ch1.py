from rc_api import BUL, CH, EQ, NUM, P, SEC, TAB

CH(1, "INTRODUCTION")
SEC("1.1", "MOTIVATION")
P("Most serious intrusions into an organisation do not end on the first computer the attacker controls. A "
  "phishing mail, an exposed remote-access service or a vulnerable web application gives the intruder a "
  "foothold on one workstation, but the valuable assets usually live elsewhere: the domain controller that "
  "holds every account, the file servers, the backup systems and the databases. To reach them, the attacker "
  "collects passwords, hashes and Kerberos tickets from the compromised machine and uses them to log in to "
  "the next machine, and then the next. MITRE ATT&CK names this stage of an attack lateral movement (tactic "
  "TA0008) [@mitre], and it is a common step in ransomware operations and in long-running targeted attacks.")
P("Lateral movement is hard to see for a simple reason: every hop is performed with a genuine credential. "
  "When the attacker signs in to a server with a stolen but valid account, the operating system records an "
  "ordinary, successful logon. Signature-based tools find nothing wrong, and threshold rules in a security "
  "information and event management (SIEM) system either miss the logon or fire on thousands of harmless "
  "administrative logons as well. What does stand out is the pattern across events: an account that suddenly "
  "authenticates to hosts it has never used before, often starting from a host that it reached only a few "
  "minutes earlier. This pattern is written in the authentication logs that almost every organisation "
  "already collects, such as Windows logon events on domain controllers, SSH logs and cloud sign-in records.")
P("Graph-based machine learning is a natural fit for this problem. Accounts and computers form a network, "
  "and each logon adds a timestamped edge between them. Temporal graph neural networks keep a small memory "
  "for every account and host and update it as new edges arrive, so the model can judge each new logon in "
  "the light of everything the entities have done before [@tgn]. Research systems built on this idea report "
  "very high detection scores on public data [@euler,jbeil].")
P("Two practical problems motivated this project. First, a detector that only raises an alert is often too "
  "slow. Scripted lateral movement can complete several hops within minutes, long before an analyst in a "
  "security operations centre (SOC) opens the first alert, and every extra hop increases the attacker's reach "
  "and the eventual damage. The time an attacker stays undetected, the dwell time, therefore depends on how "
  "quickly a detection becomes containment. Second, automation is only acceptable if it can be trusted. An "
  "automatic response that locks out a legitimate user during business hours causes an outage of its own, "
  "and a report written by a language model that invents evidence misleads the analyst who acts on it. "
  "Recent studies also show that the benchmark scores reported for lateral-movement detectors depend heavily "
  "on how the data were prepared, so a high number on a public dataset does not guarantee good behaviour in "
  "a real network [@larroche,arp].")
P("This project, GraphSentinel, was built to address both problems together. It detects lateral movement "
  "directly from authentication logs with a temporal graph neural network, allows itself to act only where "
  "a statistical bound on precision says it may, keeps every automatic action bounded, reversible and "
  "recorded, explains its decisions through reports that may cite only recorded evidence, and reports its "
  "own evaluation honestly, including the cases in which the learned model does not help.")

SEC("1.2", "EXISTING SYSTEM")
P("Organisations currently defend against lateral movement with a combination of tools, each of which "
  "covers part of the problem.")
P("**Rule-based SIEM correlation.** A SIEM collects logs centrally and raises alerts when a fixed rule "
  "matches, for example several failed logons followed by a success, or a logon from a host outside an "
  "allowed list. Rules are transparent and cheap, but their thresholds are static. An attacker who already "
  "holds a valid password produces no failures, and rules loose enough to catch careful attackers also match "
  "a large amount of normal administrative activity, which floods the analysts with false alarms.")
P("**Endpoint detection and response (EDR).** EDR agents watch processes, files and network connections on "
  "each host. They are powerful on a single machine, but a hop made with a valid credential through a normal "
  "remote-administration protocol can look legitimate from inside either endpoint, and correlating many "
  "hosts is left to the analyst. EDR also needs an agent on every machine, which is rarely true for servers, "
  "network devices and cloud services.")
P("**User and entity behaviour analytics (UEBA).** UEBA products build a statistical baseline for each user "
  "and flag deviations such as unusual login times or unusual destinations. They typically judge single "
  "events against a per-user profile and do not reason about the path an account is walking through the "
  "network, which is where lateral movement becomes visible.")
P("**Research detectors.** Academic systems mine login patterns [@siadati], reconstruct login paths "
  "[@hopper], learn graph embeddings [@log2vec,bowman] or apply temporal graph neural networks [@euler,jbeil]. "
  "These systems advance detection quality, but they stop at a ranked list of alerts, are usually evaluated "
  "offline on a single public dataset, and rarely say how an alert should become an action.")
P("**Security orchestration, automation and response (SOAR).** SOAR platforms execute response playbooks, "
  "such as disabling an account or isolating a host, when a rule triggers. The playbooks are static, the "
  "trigger is usually a rule rather than a calibrated risk, and automatic disruptive actions without bounds "
  "or verification can harm legitimate users as easily as attackers [@irs].")
P("Across these systems, three gaps remain: learned detection and automatic response are not connected with "
  "explicit safety bounds; explanations are either missing or generated without checks; and the evidence for "
  "detection quality is often weaker than the headline numbers suggest. {tab:existing} compares the existing "
  "approaches with the proposed system.")
TAB("existing", "Existing Vs Proposed System", [1700, 3303, 3303],
    [["Parameter", "Existing System", "Proposed System (GraphSentinel)"],
     ["Data source", "Separate tools per source; manual correlation across logs",
      "One canonical stream from LANL, Windows Security, SSH, Zeek, Entra ID, Okta and CSV/JSON logs, with "
      "automatic format detection"],
     ["Detection approach", "Static rules and per-user statistical baselines",
      "Temporal graph neural network over accounts and hosts, fused with explicit evidence and a novel-hop "
      "chain rule"],
     ["Context used", "Mostly the single event against a threshold or profile",
      "The full history of each entity through node memory and 27 past-only features"],
     ["Decision threshold", "Chosen by hand", "Alert threshold from a false-positive budget; action gate from "
      "a Wilson lower bound on precision"],
     ["Response", "Alert only, or static playbooks without limits",
      "Contain, verify, escalate and revert automatically, within hourly and per-account budgets"],
     ["Safety of automation", "Disruptive actions may run on any rule match",
      "Only reversible actions run alone; the lock lifts after two hours unless kept; dry-run by default"],
     ["Explanation", "Raw scores or unchecked text",
      "Local language model reports in which every claim must cite recorded evidence; deterministic fallback"],
     ["Evaluation", "Headline accuracy on one dataset",
      "Bootstrap intervals, baselines, entity hold-out, ablation, prevention replay and an external dataset"]],
    aligns=["left", "left", "left"], size=10.5)

SEC("1.3", "PROBLEM STATEMENT")
P("Enterprises record every authentication in their networks, yet attackers who move with stolen credentials "
  "still go unnoticed long enough to reach critical systems. Existing detectors either judge single events "
  "against static rules, which misses careful attackers and overwhelms analysts with false alarms, or rank "
  "suspicious logons offline without any means of stopping the attacker in time. Where automatic response "
  "exists, it is triggered by rules rather than calibrated risk and is not bounded, verified or reversible, "
  "so a false positive can lock legitimate users out of their work. Language models are increasingly used "
  "to summarise alerts, but unchecked output can state facts that are not in the evidence.")
P("The problem addressed in this project is therefore to design and build a system that, given a continuous "
  "stream of authentication events from heterogeneous sources, (i) scores every logon for lateral-movement "
  "risk using only information available at that moment, (ii) acts automatically to contain a moving "
  "attacker when, and only when, the risk clears a threshold with a guaranteed lower bound on precision, "
  "(iii) keeps every automatic action within explicit budgets, reversible and auditable, (iv) explains each "
  "incident with reports that cannot cite evidence the system does not hold, and (v) measures detection, "
  "prevention and false-action cost honestly, including on data the model has never seen.")

P("**Threat model.** The adversary already controls one workstation, the foothold *h*_{0}, and has obtained "
  "credentials on it, for example through operating-system credential dumping (MITRE technique T1003). From "
  "there it moves with valid accounts over remote services (T1021, T1078) or with stolen hashes and Kerberos "
  "tickets (T1550) [@mitre_t1021,mitre_t1550]. It may rotate between harvested accounts, slow down to blend into "
  "normal traffic and guess passwords before a hop succeeds, but every hop produces at least one authentication "
  "event that reaches the defender. An adversary who can tamper with the log pipeline or the detection host, "
  "movement that never authenticates and poisoning of the training data are outside the scope of this project.")
P("**Formal statement.** Authentication events arrive as a stream *e*_{1}, *e*_{2}, … over a temporal multigraph "
  "whose nodes are accounts and hosts. A lateral-movement campaign of length *L* is a sequence of successful "
  "events with sources *σ*_{*i*} and destinations *δ*_{*i*} in which every hop starts from the foothold or from a "
  "host reached earlier in the campaign {eq:campaign}. For every event, and using only information available at "
  "its time, the system outputs a risk *ρ*_{*k*} ∈ [0, 1] and an action from none, alert, contain and lock. The "
  "goal is a policy *π* that prevents as many campaign hops as possible while keeping automatic actions on "
  "benign logons below a budget *β* per 10,000 {eq:objective}, where *η* is the prevented fraction defined in "
  "Chapter 4, FA(*π*) counts automatic actions on benign events and *N*_{*b*} is the number of benign events.")
EQ("campaign")
EQ("objective")

SEC("1.4", "OBJECTIVES OF THE PROJECT")
BUL([
    "To ingest authentication logs from heterogeneous sources, namely the LANL research corpus, Windows "
    "Security events, SSH logs, Zeek records, Microsoft Entra ID and Okta sign-ins, and generic CSV or JSON "
    "files, into one canonical event stream, detecting the format automatically when it is not declared.",
    "To compute, for every logon, 27 causal features that describe recency, novelty, windowed behaviour and "
    "graph structure using only events that happened before it, so that the model can never learn from the "
    "future.",
    "To score every logon with a temporal graph neural network (TGN) that keeps a memory for each account and "
    "host, and to guarantee that each event is scored before it updates that memory.",
    "To fuse the learned probability with explicit evidence in an auditable way through a noisy-OR gate and a "
    "same-account chain rule, and to derive the threshold for autonomous action from a Wilson lower bound on "
    "precision rather than from a hand-picked value.",
    "To contain lateral movement automatically through a bounded loop that forces re-authentication, verifies "
    "whether the account keeps moving, escalates to a reversible two-hour account lock and reverts, under "
    "hourly and per-account budgets, with every action recorded for audit.",
    "To generate triage notes and SOC incident reports with a locally hosted language model whose every "
    "statement is checked against the evidence, falling back to a deterministic writer when the check fails.",
    "To provide an analyst console and an application programming interface (API) for live monitoring, "
    "investigation, approvals and reporting.",
    "To evaluate the system rigorously: against baselines with bootstrap confidence intervals, with the "
    "dominant attacker held out, through a prevention replay of simulated campaigns, at full data rate, and on "
    "an external dataset.",
])

SEC("1.5", "PROPOSED SYSTEM")
P("The proposed system, GraphSentinel, is a trustworthy temporal graph neural network model for autonomous "
  "detection and prevention of lateral movement. It works as a single service over one ordered stream of "
  "authentication events and is organised in four layers.")
P("The **ingestion layer** reads logs of several formats. Source adapters for LANL, Windows Security, SSH, "
  "Zeek, Entra ID, Okta and tabular files convert every record into a canonical event made of the time, the "
  "account, the source host, the destination host, the authentication attributes and the outcome. When the "
  "operator does not declare the format, a detector scores candidate columns by their content and selects "
  "the adapter automatically. An entity dictionary, frozen together with the model, maps account and host "
  "names to integer identifiers and hashes unseen names into a fixed number of out-of-vocabulary buckets.")
P("The **model layer** turns each event into a 27-dimensional feature vector computed only from earlier events "
  "and scores it with a temporal graph network. Every account and host carries a 64-dimensional memory. The "
  "network reads the memories of the account and both hosts, the features and the time since each entity was "
  "last seen, produces a probability of malicious activity, and only then updates the memories with a gated "
  "recurrent unit.")
P("The **decision layer** combines the learned probability with explicit evidence channels (novelty, burst, "
  "pivot and cross-source corroboration) through a noisy-OR gate, and applies a chain rule that recognises an "
  "account making its fourth successful hop into a never-reached host within 30 minutes. The resulting risk "
  "is compared with two thresholds: an alert threshold that feeds the analyst queue and a stricter execution "
  "gate that permits unattended action. The gate is derived so that the lower confidence bound on the "
  "precision of the actions it admits is at least 75% on validation data.")
P("The **response layer** executes a bounded prevention loop. When the gate and the budgets allow it, the "
  "account is contained by forcing re-authentication. If the account keeps moving within 30 minutes, the "
  "loop escalates to an account lock, which lifts automatically after two hours unless an analyst decides to "
  "keep it. Every command, approval and reversal is recorded with its undo. A locally hosted language model "
  "writes triage notes and incident reports that may cite only recorded facts, and an analyst console shows "
  "live detections, suspicious paths, attack chains, incidents, the prevention loop and the evaluation "
  "evidence.")

SEC("1.6", "BENEFITS OF THE PROJECT")
BUL([
    "**Earlier detection from existing data.** The system works on authentication logs that organisations "
    "already collect, so no new sensors or endpoint agents are required to begin.",
    "**Automatic containment that limits the attacker's reach.** In a replay of 100 simulated campaigns the "
    "system acted on its own in 38 campaigns and prevented 14.6% of all attacker hops, and 27.8% of the hops of "
    "attackers carrying one credential from host to host.",
    "**Safe automation.** Only reversible actions run without approval; the number of automatic actions per "
    "hour and per account is capped; connectors start in dry-run mode; and an escalated lock lifts after two "
    "hours unless a person keeps it. On benign traffic the cost was 5.5 automatic session resets per 10,000 "
    "logons.",
    "**Less work for analysts.** Suspicious multi-hop paths are ranked, related alerts are grouped into "
    "incidents, and grounded reports summarise what happened and what the system did, with every statement "
    "linked to its evidence.",
    "**Privacy and low cost.** The model trains on a laptop GPU, and the language model runs locally, so no log "
    "data has to leave the organisation.",
    "**Trust through honest evaluation.** Results are reported with confidence intervals and with their "
    "limits, which tells an organisation what to expect before it arms the automatic response.",
    "**Contribution to the Sustainable Development Goals (SDGs)** [@un_sdg]. The project supports SDG 8 "
    "(Decent Work and Economic Growth) by reducing business disruption and financial loss from intrusions, "
    "SDG 9 (Industry, Innovation and Infrastructure) by protecting digital infrastructure with an innovative AI "
    "model, and SDG 16 (Peace, Justice and Strong Institutions) by helping institutions resist cybercrime "
    "through accountable, auditable automation.",
])
