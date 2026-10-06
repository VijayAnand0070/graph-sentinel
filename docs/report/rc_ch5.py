from rc_api import BUL, CH, FIG, P, SEC, SUB, TAB

CH(5, "RESULT AND DISCUSSION")
P("This chapter presents the results in three parts. Section 5.1 describes the experimental setup. Section "
  "5.2 shows the implemented system running on a demonstration stream, and Sections 5.3 to 5.9 report the "
  "measured results: model training, detection quality, the execution gate, prevention, the full-rate cost of "
  "the chain rule, the external test and the performance and testing of the live service. Section 5.10 "
  "discusses what the results do and do not show.")

SEC("5.1", "EXPERIMENTAL SETUP")
P("All experiments were run on the laptop described in Table 3.4. {tab:corpora} lists the data. Corpus C1 is "
  "the corpus behind the shipped model: every red-team event and one in 512 benign events over the first 16 "
  "days of LANL, split chronologically into training (days 1 to 10), validation (days 10 to 13) and test (days "
  "13 to 16) partitions. Corpus C2 is a corrected slice built after local logons were found to dominate the "
  "raw stream: it covers the first 900,000 seconds, removes the 95,025,843 local logons, and keeps one in 448 "
  "of the remaining events. The OTRF recordings are used only for the external test.")
TAB("corpora", "Corpora Used in the Evaluation", [1650, 1600, 1100, 3956],
    [["Corpus", "Events", "Attacks", "Partitions (events / attacks)"],
     ["LANL raw", "1,051,430,459", "749", "58 days; 4 attacker hosts (701, 26, 19 and 3 events)"],
     ["C1 (shipped)", "543,615", "649", "train 333,551 / 316; validation 94,072 / 207; test 115,992 / 126"],
     ["C2 (corrected)", "182,815", "316", "train 127,970 / 50; validation 27,422 / 165; test 27,423 / 101"],
     ["OTRF", "195 scored", "77", "21 recordings used for the external test only"]],
    aligns=["left", "right", "right", "left"], size=10.5)
P("Thresholds are chosen on validation data only, and each test partition is scored once with everything "
  "frozen. Detectors are compared with PR-AUC, ROC-AUC, recall and false positives per 10,000 benign events, "
  "with 95% confidence intervals from stratified bootstrap resampling (2,000 resamples for C1 and 1,000 for "
  "C2, seed 1729). The baselines, scored on identical partitions, are a hand-written rule, a rarity score, an "
  "isolation forest [@iforest] and a class-weighted logistic regression over the same 27 features.")

SEC("5.2", "IMPLEMENTATION RESULTS")
P("The complete system was run as a service with the shipped checkpoint, the noisy-OR operating point, the "
  "response loop in dry-run mode and the local language model enabled. The console was driven with the "
  "demonstration stream, which replays LANL identities and embeds three scripted attack chains, and the "
  "figures below were captured from that session. The demonstration shows how the system works; it is not "
  "an evaluation. Its benign events are synthetic, so the alert counts in these figures are not false-positive "
  "rates, and several high-risk alerts concern events that the stream labels benign, as noted below. The "
  "measured results are reported from Section 5.3 onwards.")
FIG("sc_overview", "s_overview.jpg", 5.75, "Real-Time Threat Detection Console")
P("{fig:sc_overview} shows the main console. The counters at the top report the events scored in this session "
  "(26,201), the alerts raised (197, an alert rate of 0.8%), the highest risk seen (0.8464) and the number of "
  "active attack chains (3). Below them, the risk trend of the last 200 events, the real-time authentication "
  "graph in which alerted edges are drawn in red, and the alert queue update live through the WebSocket feed.")
FIG("sc_stream", "s_stream.jpg", 5.75, "Synthetic Event Streamer and CSV Batch Scoring")
P("{fig:sc_stream} shows the stream injection gateway used for the demonstration. It streams "
  "schema-faithful authentication events to the same API endpoint a production log forwarder would use, and "
  "the log shows each event of the attack chains with its risk and alert decision. Every identity in the "
  "stream is known to the model's dictionary (\"0 OOV entities verified\"). The lower panel accepts a CSV file "
  "of authentication events for ad-hoc batch scoring.")
FIG("sc_chains", "s_chains.jpg", 5.75, "Detected Multi-Hop Lateral Movement Chains")
P("{fig:sc_chains} reports the three scripted campaigns honestly. ATK-002, a credential pivot chain by account "
  "C1708$@DOM1, crossed the alert threshold at its fifth hop and four of its eight observed hops alerted at "
  "risk 0.8464, the value of the chain-rule floor. ATK-001, a slow and stealthy movement by U66@DOM1, alerted "
  "only once, at its sixth hop (risk 0.5714). ATK-003, a fan-out from one host, did not cross the threshold at "
  "all (peak risk 0.2686): a campaign that spreads from one source is invisible to the chain rule by "
  "construction and is rarely caught by the model, a limitation that Section 5.6 quantifies.")
FIG("sc_alerts", "s_alerts.jpg", 5.75, "Alert Investigation Queue")
P("{fig:sc_alerts} shows the alert queue. Each alert shows the account and destination, the attack chain it "
  "belongs to when known, the fused risk and a bar for each evidence channel, so that an analyst can see at a "
  "glance why the alert scored high. Alerts can be searched on the server, filtered by status and severity and "
  "exported as CSV or JSON.")
FIG("sc_drawer", "s_alert_drawer.jpg", 5.75, "Alert Investigation Drawer with Evidence and AI Triage Report")
P("Opening an alert shows the investigation drawer in {fig:sc_drawer}. The left part shows the alert, its "
  "entities, the fused risk (0.9515) and the MITRE ATT&CK mapping (T1021, remote services). The right part "
  "shows the evidence-grounded investigation context, in which each technique is marked as evidence-backed or "
  "as a telemetry gap (T1550 cannot be confirmed because no hashes, tickets or endpoint process data are "
  "ingested), questions an analyst should answer and recommended hunts, followed by the AI triage report. The "
  "badge states that the report was generated by the local model and that every claim was citation-checked; "
  "each statement carries the identifier of the evidence it relies on (E-001 to E-005). This particular event "
  "is labelled benign in the demonstration stream. Its source, C17693, is the host from which 94% of the LANL "
  "red-team events originated, and the high score reflects what the model learned from that campaign, the "
  "dependence measured in Section 5.4. It also shows why the drawer and the report recommend verifying the "
  "activity with the account owner before any disruptive action.")
FIG("sc_paths", "s_paths.jpg", 5.75, "Time-Respecting Suspicious Paths with Grounded Explanation")
P("{fig:sc_paths} shows the suspicious-path view. The top path follows account C1708$@DOM1 from C1015 through "
  "C2327, C585 and C743 to C229, one hop every 30 seconds, and is scored 0.778 from a mean edge risk of 0.846, "
  "a new-relationship ratio of 1.0, a pivot density of 0.75 and no cross-source evidence. The grounded "
  "explanation written by the local model restates exactly these facts and names no host or account outside "
  "the path; an explanation that did would be rejected.")
FIG("sc_incidents", "s_incidents.jpg", 5.75, "Auto-Correlated Incidents and Investigation Cases")
P("{fig:sc_incidents} shows how related alerts are grouped. In this session the 197 alerts were grouped into "
  "43 incidents within a 15-minute window. Incident 1 joins alerts of account C1708$@DOM1, the scripted "
  "ATK-002 chain, on hosts C585 and C743. Incident 2 joins two high-risk alerts of U1653@DOM1 from host "
  "C17693; these events are labelled benign in the demonstration stream, and their scores again reflect the "
  "model's knowledge of C17693. Analysts can open an incident as a durable investigation case with notes.")
FIG("sc_response", "s_response.jpg", 5.75, "Automatic Response: Dry-Run Dispatch and Prevention Loop")
P("{fig:sc_response} shows the automatic response in dry-run mode. Of 432 actions considered, 401 were planned "
  "and recorded but performed by nothing, as dry-run requires, 30 wait for a person and none failed. The "
  "prevention loop panel shows the escalation for C1708$@DOM1: force_reauth was applied at event time 2,650,360, "
  "the account qualified for an automatic action again 30 seconds later, so the containment had not held and "
  "the system escalated to lock_account on its own authority. The lock will be lifted automatically in 1 hour "
  "59 minutes unless the analyst presses \"Keep locked\"; \"Lift now\" releases it immediately. The SOC "
  "Incident Reports list below it shows the accounts with alerts, ordered by risk.")
FIG("sc_soc", "s_soc_report.jpg", 5.0, "SOC Incident Report Written by the Local Language Model")
P("{fig:sc_soc} shows an incident report written by the local model for account U1653@DOM1, which "
  "authenticated from C17693 to three other hosts in six alerts with fused risks between 0.945 and 0.955. The "
  "report passed validation: every statement cites a fact identifier (F-001 to F-009), "
  "the timeline reproduces the recorded alerts, the only automatic actions mentioned are the non-disruptive "
  "ones that were recorded, and the first recommendation is to verify the activity with the account owner. "
  "As with the alert above, these events are labelled benign in the demonstration stream; the report is shown "
  "to illustrate grounding, and its advice to verify before acting is the right response to such an alert. "
  "When the same was requested for account C1708$@DOM1, the model's draft failed validation, and the console "
  "showed the deterministic report with the badge \"Model failed grounding: template used\". The fallback "
  "worked as designed: the analyst still received a complete and correct report, and was told which writer "
  "produced it.")
FIG("sc_detection", "s_detection.jpg", 5.75, "MITRE ATT&CK Coverage and Hunt Playbooks")
P("{fig:sc_detection} shows the detection-engineering view. For each MITRE ATT&CK technique it states "
  "whether the system has evidence (T1021 remote services, 197 alerts), a behavioural signal (T1078 valid "
  "accounts, T1110 brute force) or a telemetry gap (T1550, T1210, T1563), and it lists hunt playbooks and the "
  "telemetry sources that are available or missing. Stating gaps explicitly prevents an analyst from reading "
  "coverage the system does not have.")
FIG("sc_model", "s_model_prov.jpg", 5.4, "TGN Checkpoint Provenance")
P("{fig:sc_model} shows the provenance of the served model: the architecture, the model and feature "
  "versions, the capacity of the entity dictionary (29,554 known accounts plus 4,096 out-of-vocabulary "
  "buckets, and 13,363 known hosts plus 16,384 buckets) and the SHA-256 digests of the checkpoint, the feature "
  "contract and the training dataset. The decision threshold shown (0.4543) is the checkpoint's own threshold "
  "for its raw probability under the earlier linear fusion; the product compares the fused noisy-OR risk "
  "against the alert threshold of 0.329 and the execution gate of 0.846.")
FIG("sc_research", "s_research.jpg", 5.75, "Research Evidence Dashboard")
P("{fig:sc_research} shows the research-evidence view, which puts the measurements behind the numbers in "
  "front of the analyst, starting with a warning that the headline test score depends on one attacker host. "
  "The same measurements are reported in detail in the following sections.")

SEC("5.3", "MODEL TRAINING")
P("The temporal graph network was trained for 16 epochs on the C1 training partition with the NVIDIA RTX 3050 "
  "GPU. {fig:training} shows the progress. The weighted training loss fell from 0.148 to about 0.014, and the "
  "validation PR-AUC rose from 0.675 to 0.913, with small dips at epochs 4, 7 and 9. The best validation score "
  "came at the last epoch, so early stopping with a patience of five epochs never triggered and the model had "
  "not fully plateaued when the epoch budget ended. Processing events in 60-second buckets made training 20.7 "
  "times faster than processing one timestamp at a time.")
FIG("training", "r_training.png", 5.6, "Training Progress of the Temporal Graph Network")

SEC("5.4", "DETECTION PERFORMANCE")
P("{tab:detect} and {fig:detectors} report the test results. On C1 the TGN probability reaches a PR-AUC of "
  "0.821 [0.764, 0.878] and a ROC-AUC of 0.999. It is significantly better than the shipped noisy-OR pipeline "
  "(0.805; paired difference +0.016 [+0.006, +0.031]) and far better than the linear fusion (0.577) and the "
  "logistic regression (0.246). At its validation-derived threshold the noisy-OR pipeline recalls 90.5% of the "
  "test attacks at 34.8 false positives per 10,000 benign events. Chance level, the prevalence of attacks, is "
  "0.001.")
TAB("detect", "Test PR-AUC [95% CI] and ROC-AUC of Detectors", [2206, 1900, 900, 1900, 1400],
    [["Detector", "C1 PR-AUC", "C1 ROC", "C2 PR-AUC", "C2 ROC"],
     ["Chance (prevalence)", "0.001", "0.500", "0.004", "0.500"],
     ["Hand-written rule", "0.071", "0.876", "0.548", "0.975"],
     ["Rarity score", "0.007", "0.776", "0.288", "0.848"],
     ["Isolation forest", "0.041", "0.926", "0.244", "0.979"],
     ["Logistic regression", "0.246", "0.993", "**0.956**", "0.999"],
     ["Linear fusion (TGN + channels)", "0.577 [0.498, 0.656]", "0.969", "0.676 [0.588, 0.757]", "0.956"],
     ["Noisy-OR fusion (shipped)", "0.805 [0.741, 0.867]", "0.987", "0.604 [0.520, 0.696]", "0.985"],
     ["TGN probability", "**0.821** [0.764, 0.878]", "0.999", "0.566 [0.480, 0.660]", "0.977"],
     ["Best detector, dominant attacker host held out", "0.0019 [0.0017, 0.0037]", "-", "0.0003", "-"]],
    aligns=["left", "center", "center", "center", "center"], size=10)
FIG("detectors", "r_detectors.png", 5.75, "Test PR-AUC of Detectors on the Two LANL Corpora")
P("Two further measurements change how these numbers must be read. **Entity contamination:** 121 of the 126 "
  "test attacks in C1 come from a single source host that never appears in benign training traffic. Holding "
  "that host's attacks out and scoring the remaining five attacks against all benign events lowers the TGN's "
  "PR-AUC from 0.821 to 0.0019 [0.0017, 0.0037], so 99.8% of the headline figure rests on one campaign. "
  "**Reversal on the corrected corpus:** on C2 the logistic regression over the same 27 features reaches 0.956 "
  "(ROC-AUC 0.999), while the TGN reaches 0.566 [0.480, 0.660] and the fused variants 0.604 and 0.676, and the "
  "training pipeline's promotion gate, which requires a candidate to beat the best baseline on validation, "
  "refused to promote the TGN. Holding out the dominant attacker host of C2 lowers the best detector from 0.676 "
  "to 0.0003.")
P("The reversal is a warning rather than a contradiction. The two corpora differ in local logons, sampling "
  "stride and time span, and each test partition is dominated by one attacker, so which model wins depends on "
  "these choices, in line with the re-evaluations of Larroche [@larroche] and the benchmark critiques in "
  "[@edgebank,graphmixer]. The LANL scores are therefore comparisons under a stated protocol, not estimates of "
  "accuracy against a new attacker, and this report does not claim that the TGN is better than simpler "
  "models.")
P("To check whether the TGN learned the dominant campaign's behaviour or merely memorised its host, a "
  "score-time ablation was run on the C1 test partition ({tab:ablation}). Each condition replaces part of the "
  "scorer's input while the memory trajectory stays identical. Zeroing every memory lowers PR-AUC from 0.821 "
  "to 0.389, but mostly because benign scoring collapses (from 34.5 to 969.8 false positives per 10,000) when "
  "every ordinary event starts to look unfamiliar; the recall on the dominant host's attacks at the alert "
  "threshold falls only from 94.2% to 81.8%. Zeroing the source-host memory does not change that recall at "
  "all, because that host never appears as a destination and its memory row is never written, and "
  "neutralising the five entity-degree features still leaves 78.5%. The campaign is recognised from behaviour "
  "spread across many features rather than from an identity channel, and the memory mainly serves to "
  "recognise benign familiarity; the model has, however, seen only one campaign of this kind.")
TAB("ablation", "Score-Time Ablation on the C1 Test Partition", [3300, 1100, 1450, 1256, 1200],
    [["Condition", "PR-AUC", "Main-host recall", "Above gate", "FP / 10k"],
     ["Full model", "0.821", "94.2%", "87.6%", "34.5"],
     ["Source-host memory zeroed", "0.592", "94.2%", "87.6%", "822.8"],
     ["Account memory zeroed", "0.773", "93.4%", "85.1%", "40.0"],
     ["Destination memory zeroed", "0.469", "90.9%", "81.0%", "719.2"],
     ["All memory zeroed", "0.389", "81.8%", "67.8%", "969.8"],
     ["Source-host historical degree at median", "0.660", "95.0%", "86.8%", "55.9"],
     ["Source-host distinct destinations (1 h) at median", "0.781", "89.3%", "74.4%", "18.8"],
     ["Five entity-degree features at median", "0.671", "78.5%", "54.5%", "16.0"]],
    aligns=["left", "center", "center", "center", "center"], size=10)

SEC("5.5", "EXECUTION GATE")
P("{tab:gate} compares the execution gate on the validation partition, where it was derived, with the sealed "
  "test partition. On validation the gate of 0.846 admits 251 alerts at 80.5% precision, with a Wilson lower "
  "bound of 75.1% that meets the 75% target. On the later test period the same gate admits 201 alerts at "
  "53.2% precision [46.3%, 60.0%], and the number of benign events it would act on rises from 5.22 to 8.11 per "
  "10,000. The guarantee holds when it is derived but decays over time, because the false-positive floor "
  "depends on the day while the volume of attacks varies. Both figures are therefore stored together with the "
  "constant, and future gates are best expressed as a false-positive budget, with precision reported as an "
  "outcome.")
TAB("gate", "Execution Gate: Validation Versus Sealed Test", [3300, 2503, 2503],
    [["Quantity", "Validation (derivation)", "Test (later period)"],
     ["Gate on the fused risk", "0.846", "0.846"],
     ["Alerts at or above the gate", "251", "201"],
     ["Precision [95% CI]", "80.5% (lower bound 75.1%)", "53.2% [46.3%, 60.0%]"],
     ["Benign events above the gate per 10k", "5.22", "8.11"]],
    aligns=["left", "center", "center"], size=10.5)

SEC("5.6", "PREVENTION RESULTS")
P("The prevention instrument replayed 100 campaigns of eight hops each (two families, ten inter-hop intervals "
  "from 15 seconds to one hour, five replicates) among 102,476 benign events over three simulated days, after a "
  "warm-up that restored the model's state through the end of the validation period. {tab:prevent} summarises "
  "the outcome at the shipped operating point.")
TAB("prevent", "Prevention Instrument Results", [3700, 1500, 1500, 1606],
    [["Measure", "Chain", "Fan-out", "All"],
     ["Campaigns (8 hops each)", "50", "50", "100"],
     ["Detected (an alert raised)", "36", "9", "45"],
     ["Median first-alert hop index", "4", "5", "4"],
     ["Autonomous action taken", "36", "2", "38"],
     ["Hops prevented, campaign semantics", "27.8%", "1.5%", "14.6%"],
     ["Hops prevented, account semantics", "27.8%", "0.8%", "14.3%"],
     ["Benign alerts per 10k", "<span=3>30.8 (316 of 102,476 benign events)"],
     ["Automatic actions per 10k", "<span=3>5.5 (56 events, 56 distinct users)"]],
    aligns=["left", "center", "center", "center"], size=10.5)
P("The system alerts on 45 of the 100 campaigns with a median detection latency of four hops, the hop-count "
  "counterpart of time to detect, and acts without approval on 38 of them, preventing 14.6% of all attacker "
  "hops. The benefit lies in chains. All 36 detected chains were contained automatically, 33 at their fifth "
  "hop and three at their fourth, preventing 27.8% of chain hops, whereas only 2 of 50 fan-outs were acted on. "
  "Because the chain rule needs four novel hops of evidence, at most half of an eight-hop chain can be "
  "prevented. Under account semantics, where an action stops only the account it was taken on, the fan-out "
  "figure drops to 0.8% because a fan-out rotates several stolen accounts.")
FIG("prevention", "fig4_prevention.png", 5.0, "Prevention Instrument Results")
P("{fig:prevention}(a) shows the detection rate by the interval between hops. Every chain is detected when its "
  "hops are at most ten minutes apart, and almost none when they are fifteen minutes or more apart, because "
  "four hops then no longer fit the 1,800-second window of the chain rule. An attacker who slows down to one "
  "hop every fifteen minutes therefore evades the rule, which is the price of keeping its false-positive cost "
  "low; fan-outs are rarely detected at any speed.")
P("A session reset does not always stop an attacker, for example when previously issued Kerberos tickets "
  "remain valid. {fig:prevention}(b) and {tab:killsweep} vary the probability that a reset actually stops the "
  "campaign. Without verification and escalation, prevention falls in proportion to that probability and "
  "reaches zero when resets never work. With the loop, continued movement is noticed and the account is "
  "locked, and 9.3% of hops are still prevented even when resets never work, at the cost of escalating 36 "
  "campaigns to a lock.")
TAB("killsweep", "Prevention When Containment Fails", [2800, 1900, 1900, 1706],
    [["Probability that a reset stops the attacker", "Contain only", "Contain, verify, escalate",
      "Campaigns escalated"],
     ["1.00", "14.6%", "14.6%", "0"],
     ["0.75", "11.5%", "13.6%", "8"],
     ["0.50", "8.8%", "12.5%", "14"],
     ["0.25", "5.3%", "11.0%", "22"],
     ["0.00", "0.0%", "9.3%", "36"]],
    aligns=["center", "center", "center", "center"], size=10.5)
P("The instrument is meaningful only for a model that has never seen its generator. In a controlled "
  "experiment, 60 campaigns from the same generator were added to the training data. The retrained model then "
  "detected 94 of the 100 instrument campaigns at the attacker's first or second hop, but its PR-AUC on the "
  "real C1 test partition fell from 0.805 to 0.403 [0.318, 0.491], and its recall at the operating budget from "
  "90% to 56%. The model had learned the generator rather than lateral movement, and the instrument would have "
  "measured the training set. The shipped model therefore excludes such data.")

SEC("5.7", "COST OF THE CHAIN RULE AT FULL DATA RATE")
P("Rule costs measured on a stride-sampled corpus are misleading, because keeping one benign event in several "
  "hundred removes nearly every benign multi-hop pattern. On C1 an early four-hop, 300-second chain rule "
  "appeared to cost 4.6 false positives per 10,000 events; on an unsampled day of LANL (7,263,653 events after "
  "local logons are removed) the same rule flagged 715 to 855 benign events per 10,000. {tab:fullrate} and "
  "{fig:fullrate} compare three variants on that day, processed from a cold start.")
TAB("fullrate", "Benign Flags per 10,000 Events of Chain-Rule Variants on an Unsampled Day",
    [3900, 1100, 1100, 1100, 1106],
    [["Hop that completes the chain must be", "Whole day", "Hours 6-11", "Hours 12-17", "Hours 18-23"],
     ["Any authentication (4 hops within 1,800 s)", "114.4", "261.6", "26.2", "4.86"],
     ["A successful authentication", "113.7", "259.8", "26.2", "4.86"],
     ["A successful hop into a never-reached host (shipped)", "**4.30**", "**9.91**", "**0.95**", "**0.09**"]],
    aligns=["left", "center", "center", "center", "center"], size=10.5)
FIG("fullrate", "fig5_fullrate.png", 5.0, "Benign Cost of Chain Rules, Hour by Hour, on an Unsampled Day")
P("Requiring successful hops into never-reached hosts lowers the day's cost from 114.4 to 4.3 per 10,000, a "
  "26-fold reduction, and the cost keeps falling as each account's history accumulates, to about 0.1 per "
  "10,000 in the last six hours of the day. No chain campaign is lost by this stricter test, because a walk "
  "into new hosts satisfies both versions at the same hop.")

SEC("5.8", "EXTERNAL VALIDATION ON OTRF")
P("The frozen system, with the LANL-trained checkpoint and LANL-calibrated thresholds and without retraining, "
  "was run on the OTRF Security Datasets recordings of Windows lateral movement from a small lab domain "
  "(theshire.local, with workstations WORKSTATION5 to WORKSTATION7 and the domain controller MORDORDC). Each "
  "recording captures one technique executed with Empire, Covenant, Mimikatz or PurpleSharp, such as PsExec-"
  "style service creation over SMB, WMI, WMIC, DCOM, WinRM and the Zerologon exploit. Ground truth for each "
  "recording was taken from the attacker's console transcript published with the data. Of 29 recordings, six "
  "were excluded before scoring (two without metadata, three that name no target and one from a different "
  "lab) and two produced no authentication event, leaving 21 recordings with 77 attack and 118 benign events. "
  "Every file was read through the product's own ingestion path, and format detection recognised all of them "
  "as Windows Security JSON.")
TAB("otrf", "External Test on 21 OTRF Recordings", [4700, 3606],
    [["Measure", "Value"],
     ["Attack / benign events", "77 / 118"],
     ["Recordings detected at the alert threshold 0.329", "2 of 21"],
     ["Benign events alerted at the alert threshold", "13 of 118"],
     ["Attack ranked first in its recording (expected by chance)", "10 of 18 (6.3)"],
     ["Pooled ROC-AUC [95% CI, bootstrap over recordings]", "0.661 [0.564, 0.754]"],
     ["Mean ROC-AUC within a recording", "0.787 (18 recordings)"]],
    aligns=["left", "center"], size=10.5)
FIG("otrf", "fig6_otrf.png", 5.0, "Fused Risk of Every Event in the 21 OTRF Recordings")
P("{tab:otrf} and {fig:otrf} give the result. At the shipped threshold only 2 of the 21 attacks are detected: "
  "a PurpleSharp Active Directory playbook (risk 0.961) and an Empire WMIC backdoor (risk 0.734), which are "
  "also the two busiest recordings and the source of the 13 benign alerts. Without a threshold, the signal is "
  "real but weak: the pooled ROC-AUC is 0.661, the mean ROC-AUC within a recording is 0.787, and the attacker's "
  "event is ranked first in 10 of 18 recordings against 6.3 expected by chance.")
P("Three known effects combine here. Every OTRF identity is outside the frozen dictionary, so the model "
  "reasons from shared out-of-vocabulary memory; every recording holds a single hop, so the chain rule cannot "
  "fire by construction; and a threshold is a property of a score distribution, which moves between networks. "
  "Reading a new network's logs therefore works, but alerting correctly on them requires a warm-up on that "
  "network's own history and a threshold re-derived on its own data. The external test also exposed two "
  "identity defects that are now fixed: IPv4-mapped IPv6 addresses (for example ::ffff:172.18.39.5) and "
  "loopback addresses now resolve to a single host.")

SEC("5.9", "LIVE SERVICE PERFORMANCE AND TESTING")
P("To confirm that the deployed service behaves exactly like the offline evaluation, the test partition of C2 "
  "was streamed through the live API with the model, dictionary and warm state produced by the pipeline "
  "({tab:live}). The service scored 27,423 events in 55 requests in 87.1 seconds, about 315 events per second, "
  "and its PR-AUC on these events matched the offline evaluation to five decimal places. The novelty, burst "
  "and pivot channels agreed exactly with the offline computation, and the TGN probability and the fused risk "
  "within 3 x 10^{-7}. After a restart, the feature state was restored and 22,088 node memories were warm, "
  "and an approval replayed after the restart was refused, as it must be. In the demonstration session of "
  "Section 5.2, the service answered 234 scoring requests with a median latency of 9.6 ms and a "
  "95th-percentile latency of 43 ms.")
TAB("live", "Live Service Replay on the Corrected Corpus", [4700, 3606],
    [["Measure", "Value"],
     ["Events streamed / requests", "27,423 / 55"],
     ["Throughput", "314.9 events per second"],
     ["Alerts at the corpus threshold (0.669)", "85 (31.0 per 10k)"],
     ["Attacks caught / missed / false alerts", "55 / 46 / 30"],
     ["PR-AUC live vs offline", "0.603796 vs 0.603798"],
     ["Largest channel difference live vs offline", "2.7 x 10^{-7} (TGN), 0 (novelty, burst, pivot)"],
     ["Dry-run dispatch records", "349 (208 unattended, 141 awaiting approval)"],
     ["After restart", "features restored, 22,088 memories warm, replayed approval refused"]],
    aligns=["left", "left"], size=10.5)
P("The implementation is covered by 755 automated tests grouped in {tab:tests}. All tests pass except one, "
  "which is skipped by design: the full end-to-end pipeline test runs only when explicitly enabled because it "
  "rebuilds the corpus from the raw data. The tests cover, among other things, that events are scored before "
  "memory updates, that the gate matches its derivation, that locks are adopted after a restart, that the "
  "report agent rejects invented citations and alert identifiers, and that the console does not show claims "
  "the backend cannot support.")
TAB("tests", "Automated Test Summary", [4200, 1400, 2706],
    [["Area", "Tests", "Result"],
     ["Log ingestion, source adapters and datasets", "103", "all passed"],
     ["Causal features, temporal graph and state", "43", "all passed"],
     ["TGN model, training and serving", "50", "all passed"],
     ["Detection: fusion, chain rule, gate, tactics, paths", "178", "all passed"],
     ["Automatic response and playbooks", "109", "all passed"],
     ["Report agents and explanations", "42", "all passed"],
     ["Evaluation, calibration and simulation", "101", "all passed"],
     ["API, console, store, audit and integrations", "123", "all passed"],
     ["End-to-end pipeline", "6", "5 passed, 1 skipped (opt-in)"],
     ["**Total**", "**755**", "**754 passed, 1 skipped**"]],
    aligns=["left", "center", "left"], size=10.5)

SEC("5.10", "DISCUSSION")
P("The results support four conclusions. First, the system works end to end: logs are read in several "
  "formats, every event is scored causally, alerts carry evidence, the response loop contains, verifies, "
  "escalates and reverts within its budgets, reports are grounded, and the live service reproduces the offline "
  "evaluation. Second, bounded automation prevents a meaningful share of attacker progress against "
  "credential chains (27.8% of hops) at a low cost to legitimate users (5.5 session resets per 10,000 benign "
  "logons), and verification with escalation keeps some protection even when containment fails. Third, the "
  "strongest protection comes from combining the learned model with the explicit chain rule, not from the "
  "model alone. Fourth, measurement choices matter as much as models: the headline LANL score rests on one "
  "attacker host, a linear model wins on the corrected corpus, sampled data understate rule costs by two orders "
  "of magnitude, and a frozen model transfers its ranking but not its threshold to an unseen network.")
P("The limitations follow from the same results and are stated so that the system is not over-trusted:")
BUL([
    "The LANL labels describe one red-team exercise with four attacker hosts, one of which produced 94% of the "
    "events, so no absolute detection figure here predicts performance against a new attacker.",
    "Both LANL corpora are stride-sampled, which inflates the prevalence of attacks and shortens benign "
    "histories relative to attack histories; repeating the model comparison with features computed at full "
    "rate is the first item of future work.",
    "Prevention is measured on simulated campaigns whose generator is independent of training but is still a "
    "model of attacker behaviour; fan-out campaigns and attackers who slow down beyond the chain window are "
    "rarely stopped.",
    "The OTRF recordings are short and come from a single lab; alerting well on a new network requires "
    "warm-up and a re-derived threshold.",
])
