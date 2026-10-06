from rc_api import BUL, CH, P, SEC, SUB, TAB

CH(2, "LITERATURE SURVEY")
SEC("2.1", "INTRODUCTION")
P("The literature relevant to this project comes from four areas: detection of lateral movement in enterprise "
  "logs, learning on graphs that change over time, the methodology used to evaluate machine-learning "
  "detectors in security, and automated incident response. A fifth, more recent area concerns the use of "
  "large language models to explain security events. This chapter reviews representative work in each area, "
  "states what each work contributes and where it stops, and draws the inferences that shaped the design of "
  "GraphSentinel.")
P("Two observations run through the survey. The first is that the evidence for lateral movement lies in "
  "sequences of logons rather than in any single logon, which is why the field moved from single-event "
  "anomaly detection to path reconstruction and then to graph learning. The second is that almost every "
  "system stops at producing alerts, while the practical value of detection depends on what happens after "
  "the alert, and on whether the reported accuracy survives outside the dataset on which it was measured.")

SEC("2.2", "RELATED WORK")
SUB("2.2.1", "Login Pattern Mining and Path-Based Detection")
P("Siadati and Memon [@siadati] observed that logins inside an enterprise follow a structure, for example "
  "that users of a certain group log in to a certain class of servers from a certain class of workstations. "
  "They extracted this network login structure with a variant of market-basket pattern mining and flagged "
  "logins inconsistent with it. On five months of login data from a global financial company the approach "
  "detected 82% of malicious logins at a false-positive rate of 0.3%. The method judges each login "
  "separately against the mined patterns and does not follow the attacker from one hop to the next.")
P("Hopper by Ho et al. [@hopper] made the path the unit of analysis. It builds a graph of logins between "
  "internal machines, infers the causal chain of logins that led to each new login, and raises an alert "
  "when a chain switches credentials unusually or reaches an unusual destination. On fifteen months of "
  "enterprise logs Hopper detected 94.5% of more than 300 realistic attack scenarios while producing fewer "
  "than nine alerts per day. Hopper established that path context is what separates attacker movement from "
  "administration, an insight that GraphSentinel's chain rule applies in streaming form.")

SUB("2.2.2", "Graph Embedding Approaches")
P("Log2vec by Liu et al. [@log2vec] converts audit records into a heterogeneous graph whose edges encode "
  "rule-defined relations between log entries, learns node embeddings with random walks, and separates "
  "malicious from benign activity by clustering the embeddings. Bowman et al. [@bowman] learned unsupervised "
  "embeddings of authenticating entities and scored each authentication with a link predictor, reporting a "
  "true-positive rate of 85% at a false-positive rate of 0.9%, against 72% and 4.4% for traditional "
  "heuristics. Both approaches capture relationships between entities, but their embeddings are learned from "
  "a static snapshot and must be recomputed to reflect new behaviour, and both stop at an alert.")

SUB("2.2.3", "Temporal Graph Neural Networks")
P("Continuous-time dynamic graph models learn from streams of timestamped interactions. JODIE by Kumar et al. "
  "[@jodie] learns an embedding trajectory for each user and item and updates it with recurrent networks at "
  "every interaction. TGAT by Xu et al. [@tgat] aggregates the temporal neighbourhood of a node with "
  "self-attention and introduces a functional time encoding based on harmonic analysis. The Temporal Graph "
  "Network (TGN) framework of Rossi et al. [@tgn] combines a memory module that stores a state per node, "
  "message functions that summarise each interaction, and graph-based embedding operators; memories are "
  "updated with gated recurrent units (GRU) [@gru]. The TGN framework is general and efficient, and its "
  "memory is well suited to authentication streams in which accounts and hosts appear repeatedly over weeks. "
  "GraphSentinel uses a TGN-style model with attention-weighted message aggregation and a GRU memory updater.")

SUB("2.2.4", "Temporal Graph Learning for Lateral Movement")
P("Euler by King and Huang [@euler] stacks a graph neural network on a recurrent sequence encoder over "
  "discrete snapshots of the authentication graph and treats lateral movement as anomalous link prediction; "
  "its design distributes the graph convolutions across machines for scale. Jbeil by Khoury et al. [@jbeil] "
  "applies inductive temporal-graph learning to authentication events from the Los Alamos National "
  "Laboratory (LANL) network and reports an AUC above 0.99, even when part of the graph is withheld during "
  "training. These works show that temporal graph models can rank malicious logons highly on public data. "
  "They are, however, evaluated offline, report aggregate scores on a single corpus, and do not connect the "
  "detector to any response.")

SUB("2.2.5", "Evaluation Methodology and Its Pitfalls")
P("Sommer and Paxson [@sommer] explained why anomaly detection for intrusions is harder to evaluate than "
  "machine learning in other domains: attacks are rare, the cost of errors is high, and realistic labelled "
  "data are scarce. Arp et al. [@arp] surveyed security papers and catalogued recurring pitfalls, including "
  "sampling bias, data snooping, spurious correlations and inappropriate baselines. In dynamic-graph "
  "learning, Poursafaei et al. [@edgebank] showed that a baseline that simply memorises previously seen "
  "edges performs strongly under common evaluation protocols, and Cong et al. [@graphmixer] showed that a "
  "conceptually simple architecture built from multilayer perceptrons can match more complex temporal "
  "models. Most directly relevant, Larroche [@larroche] re-evaluated three graph-based lateral-movement "
  "detectors on the LANL and OpTC datasets under standardised preprocessing and labelling and found results "
  "well below those originally reported. For rare-event detection, Saito and Rehmsmeier [@saito] showed that "
  "the precision-recall curve is more informative than the ROC curve, which is why this project reports "
  "PR-AUC as the primary metric.")

SUB("2.2.6", "Intrusion Response and Zero Trust")
P("Inayat et al. [@irs] surveyed intrusion response systems and stressed that automatic responses must weigh "
  "the damage an attack may cause against the cost of a wrong response, which motivates cost-sensitive and "
  "reversible actions. The NIST incident-response profile for the Cybersecurity Framework 2.0 [@nist61] "
  "treats containment and eradication of incidents as outcomes of the Respond function and allows "
  "containment to be performed automatically by security technologies. The NIST zero-trust architecture "
  "[@zt] requires that every access request be evaluated rather than trusted because it originates inside "
  "the network. Classic secure-design principles of Saltzer and Schroeder [@saltzer], such as fail-safe "
  "defaults and complete mediation, remain the reference for systems that take actions on their own.")

SUB("2.2.7", "Language Models in Security Operations")
P("Large language models are increasingly used to summarise alerts and draft incident reports. The survey of "
  "Ji et al. [@halluc] documents that such models can produce fluent text that is not supported by their "
  "input, a behaviour known as hallucination. In a security operations centre, a report that names the wrong "
  "host or claims an action that never happened can lead an analyst to a harmful decision. This motivates "
  "constraining the model to cite supplied evidence and validating every citation before a report is shown.")

SUB("2.2.8", "Datasets and Threat Frameworks")
P("The LANL comprehensive cyber-security events dataset [@lanl,kent2016] is the most widely used public corpus "
  "for lateral-movement research. It covers 58 consecutive days of de-identified activity on the LANL "
  "corporate network and includes more than one billion authentication events together with a list of "
  "red-team compromise events. The OTRF Security Datasets project [@otrf] publishes recordings of real "
  "Windows telemetry captured while known attack tools are executed in a small lab, which makes it useful as "
  "an independent external test. MITRE ATT&CK describes the adversary behaviours involved: remote services "
  "(T1021) [@mitre_t1021], valid accounts (T1078) and the use of alternate authentication material such as "
  "pass-the-hash and pass-the-ticket (T1550) [@mitre_t1550]. {tab:related} summarises the reviewed detectors.")
TAB("related", "Comparative Analysis of Related Work",
    [1560, 1850, 1330, 1850, 1716],
    [["Author & Year", "Method", "Data", "Contribution", "Limitation"],
     ["Siadati & Memon (2017) [@siadati]", "Market-basket mining of login patterns", "Enterprise logins, 5 months",
      "82% of malicious logins at 0.3% false positives", "Single-login view; alerts only"],
     ["Liu et al. (2019) [@log2vec]", "Heterogeneous graph embedding and clustering", "CERT, LANL",
      "Rule-defined relations between log entries", "Offline batch; hand-built relations"],
     ["Bowman et al. (2020) [@bowman]", "Unsupervised graph embedding with link prediction", "Simulated network, LANL",
      "85% TPR at 0.9% FPR, better than heuristics", "Static embeddings; alerts only"],
     ["Ho et al. (2021) [@hopper]", "Login-path inference and credential switching", "Enterprise logs, 15 months",
      "94.5% detection, fewer than 9 alerts/day", "Depends on path inference; alerts only"],
     ["King & Huang (2022) [@euler]", "GNN with recurrent encoder over snapshots", "LANL",
      "Scalable temporal link prediction", "Discrete snapshots; alerts only"],
     ["Khoury et al. (2024) [@jbeil]", "Inductive temporal graph learning", "LANL",
      "AUC above 0.99 with unseen nodes", "Offline evaluation; alerts only"],
     ["Larroche (2026) [@larroche]", "Standardised re-evaluation protocol", "LANL, OpTC",
      "Shows preprocessing changes reported results", "Evaluation study, no detector"],
     ["Proposed system", "TGN, noisy-OR fusion, chain rule, precision-gated autonomous response, grounded reports",
      "LANL, OTRF", "Measures prevention and false-action cost end to end",
      "Prevention measured on simulated campaigns"]],
    aligns=["left", "left", "left", "left", "left"], size=10)

SEC("2.3", "INFERENCE FROM RELATED WORK")
P("The survey leads to the following inferences, each of which is reflected in a design decision of "
  "GraphSentinel.")
BUL([
    "**Path context carries the signal.** Single-login detectors miss careful attackers, while path-based and "
    "graph-based methods capture how an account moves [@hopper,siadati]. GraphSentinel therefore combines a "
    "temporal graph model with an explicit same-account chain rule.",
    "**Temporal memory suits authentication streams.** Continuous-time models such as TGN keep a state per "
    "entity and update it with every event [@tgn,jodie,tgat], which lets the model judge a logon against the "
    "full history of the account and hosts involved without recomputing embeddings.",
    "**Leakage must be prevented by construction.** A model that sees the event it is predicting, or features "
    "computed with future information, produces inflated scores. GraphSentinel computes features only from "
    "earlier events and scores each event before it updates memory.",
    "**Baselines and data preparation decide the conclusions.** Simple baselines can match complex temporal "
    "models [@edgebank,graphmixer], and preprocessing changes reported results [@larroche]. GraphSentinel is "
    "compared with rule, rarity, isolation-forest [@iforest] and logistic-regression baselines on identical "
    "data, with bootstrap intervals [@efron] and with the dominant attacker held out.",
    "**Detection must connect to bounded response.** Research detectors stop at alerts, while response "
    "systems act on rules without calibrated risk [@irs]. GraphSentinel derives an execution gate from a lower "
    "confidence bound on precision [@wilson] and wraps every automatic action in budgets, verification and "
    "reversal.",
    "**Generated explanations must be verifiable.** Because language models can hallucinate [@halluc], "
    "GraphSentinel lets the model cite only identifiers of recorded facts and rejects any report that does "
    "not pass validation.",
    "**External data are necessary.** A detector tuned on one network may not transfer. GraphSentinel is "
    "tested on the independent OTRF recordings [@otrf] without retraining.",
])
P("In summary, prior work provides strong components but not a complete, trustworthy loop from logs to "
  "action. The contribution of this project is to assemble those components into one model whose automatic "
  "behaviour is bounded and verifiable, and to measure what that loop actually prevents and what it costs.")
