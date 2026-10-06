from rc_api import BUL, CH, NUM, P, SEC

CH(6, "CONCLUSION AND FUTURE WORK")
SEC("6.1", "CONCLUSION")
P("This project designed, implemented and evaluated GraphSentinel, a trustworthy temporal graph neural network "
  "model for autonomous detection and prevention of lateral movement in enterprise networks. The system reads "
  "authentication logs of several formats into one canonical stream, scores every logon with a temporal graph "
  "network from features computed only from the past, fuses the learned probability with explicit evidence "
  "through a noisy-OR gate and a novel-hop chain rule, and acts on its own only when the risk clears a gate "
  "derived from a Wilson lower bound on precision. Its response is a bounded loop that contains an account by "
  "forcing re-authentication, verifies whether the account keeps moving, escalates to a reversible two-hour "
  "lock and reverts, all within hourly and per-account budgets and with every action recorded. A locally "
  "hosted language model writes triage notes and SOC incident reports that cannot cite evidence the system "
  "does not hold, and a deterministic writer takes over when the model fails.")
P("Measured end to end, the loop prevented 14.6% of attacker hops across 100 simulated campaigns, and 27.8% of "
  "the hops of attackers who carry one credential from host to host, at a cost of 5.5 automatic session resets "
  "per 10,000 benign logons; verification and escalation preserved 9.3% prevention even when session resets "
  "never worked. The evaluation is a result in its own right: the headline LANL score depends on a single "
  "attacker host, a logistic regression outperforms the TGN on a corrected corpus, sampled corpora understate "
  "rule costs by two orders of magnitude, and a frozen model transfers its ranking but not its threshold to an "
  "unseen network. Reporting these limits alongside the system is what makes its automatic behaviour "
  "trustworthy: an organisation knows what the system prevents, what it costs and where it must be "
  "recalibrated before the response is armed.")
P("The key achievements of the project are:")
BUL([
    "**One pipeline from logs to action:** ingestion with automatic format detection, causal features, a "
    "temporal graph network, auditable fusion, a precision-gated response loop, grounded reports and an analyst "
    "console, delivered as one deployable service.",
    "**Bounded and reversible autonomy:** only reversible actions run alone, within budgets, with verification, "
    "escalation and automatic reversal, and with dry-run as the default.",
    "**Grounded explanations:** every generated statement cites a recorded fact, invented identifiers are "
    "rejected, and the provenance of each report is always shown.",
    "**Measured prevention:** a replay instrument that measures the hops a response prevents and the benign "
    "users it disturbs, instead of detection scores alone.",
    "**Honest evaluation:** confidence intervals, baselines, entity hold-out, ablation, full-rate costing and "
    "an external dataset, with 755 automated tests guarding the behaviour.",
])
SEC("6.2", "FUTURE WORK")
NUM([
    "**Full-rate features:** recompute the 27 features on unsampled data and repeat the comparison of the TGN, "
    "logistic regression and gradient-boosted trees with several random seeds, so that the model choice rests "
    "on data free of the sampling artefact.",
    "**More labelled attackers:** evaluate on further labelled corpora and hold out attacker hosts, so that "
    "detection is measured against attackers the model has never seen.",
    "**Per-network calibration:** derive the alert threshold and the execution gate automatically from a short "
    "warm-up period on each new network, expressed as a false-positive budget.",
    "**Fan-out detection:** add a rule and features for one host using several stolen accounts, the campaign "
    "type the current system rarely stops.",
    "**Richer telemetry:** ingest endpoint process, network flow and ticket data so that techniques currently "
    "marked as telemetry gaps, such as pass-the-hash and pass-the-ticket (T1550), can be confirmed.",
    "**Analyst study:** measure the accuracy and usefulness of the generated reports with practising SOC "
    "analysts, and support regional languages in the report agent.",
])
