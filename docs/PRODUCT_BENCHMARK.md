# Product benchmark and development direction

Status date: 2026-08-12 — GraphSentinel `0.9.0`

This benchmark compares product capabilities, not vendor market position. GraphSentinel is a
specialized, single-node lateral-movement detection product; the compared products are broad,
commercial security platforms with larger connector, content, operations, and response ecosystems.

| Capability | GraphSentinel 0.9 | Microsoft Sentinel | Splunk Enterprise Security | CrowdStrike Falcon | Cortex XSIAM |
|---|---|---|---|---|---|
| Primary strength | Causal temporal authentication graph, transparent model training, evidence-bounded triage | Unified incidents, entity investigation graph, UEBA, hunting | Risk-based alert aggregation, search, detection engineering, MITRE coverage, SOAR | Unified endpoint and identity visibility, identity attack paths, real-time policy | Unified security data, broad analytics, cases, evidence, automation, exposure management |
| Entity behavior | User/host history, novelty, fan-out, failure context, pivot paths | Entity baselines plus peer- and organization-level behavior | UEBA and normalized entity risk | Identity and endpoint behavioral analytics | Cross-domain analytics over unified telemetry |
| Investigation | Temporal graph, ranked paths, related-alert timeline, evidence IDs | Incident timeline, entities, similar incidents, graph expansion queries | Risk notable timeline, investigation and response plans | Identity/endpoint attack-path investigation | Prioritized cases, root-cause story, causal evidence |
| ATT&CK handling | T1021 evidence; T1078/T1110 hypotheses; explicit gaps for T1550/T1210/T1563 | Broad analytics and hunting mappings | Coverage visualization and detection lifecycle | Adversary and identity attack context | Broad incident tactic and technique context |
| Response | Advisory only; no autonomous containment | Playbooks and automation with configured permissions | SOAR and adaptive response | Risk-based access and identity/endpoint response | Integrated automation and guided actions |
| Current limitation | Authentication-only telemetry, no peer groups/asset privilege, single ordered worker | Platform onboarding, data engineering, and cloud operating model | Platform cost/engineering and content tuning | Commercial sensor/platform dependency | Commercial platform and unified data dependency |

## Evidence from current official product material

- Microsoft documents entity investigation graphs, incident timelines, related entities, and
  exploration queries, while its UEBA builds entity profiles using own-history, peer-group, and
  organization-level baselines: [incident investigation](https://learn.microsoft.com/en-us/azure/sentinel/investigate-cases),
  [UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics).
- Splunk documents risk-based alerting, normalized entity risk, ATT&CK-aligned coverage, threat
  hunting, and an integrated TDIR workflow: [RBA documentation](https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.2/introduction/about-risk-based-alerting-in-splunk-enterprise-security),
  [Enterprise Security capabilities](https://www.splunk.com/en_us/products/enterprise-security.html).
- CrowdStrike describes unified identity/endpoint ITDR and graph-based predictive attack-path
  analysis: [Identity Protection](https://www.crowdstrike.com/en-us/platform/next-gen-identity-security/itdr/),
  [Attack Path Analysis](https://www.crowdstrike.com/en-us/platform/exposure-management/attack-path-analysis/).
- Cortex XSIAM describes prioritized cases, root-cause attack stories, unified evidence, hunting,
  automation, and attack-surface findings: [XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam),
  [case evidence](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Evidence).
- MITRE defines lateral movement as access and control of remote systems, including Remote
  Services, alternate authentication material, exploitation, and session hijacking. Its current
  detection strategies reinforce the need for authentication plus process, session, network, and
  identity context: [Lateral Movement](https://attack.mitre.org/tactics/TA0008/),
  [Remote Services](https://attack.mitre.org/techniques/T1021/),
  [Valid Accounts](https://attack.mitre.org/techniques/T1078/),
  [Brute Force](https://attack.mitre.org/techniques/T1110/).

## Changes adopted through 0.9

- ATT&CK coverage is a ledger, not a marketing percentage. It separates evidence-backed
  techniques, behavioral hypotheses, and techniques blocked by missing telemetry.
- Guided hunts are executable scopes over current alerts: first-seen relationships, failures
  before remote activity, rapid fan-out, time-respecting pivots, and multi-signal consensus.
- Alert investigation now adds related-entity timelines, technique assessments, analyst validation
  questions, and direct identity/source/destination pivots.
- The UI labels the local insecure configuration as development instead of claiming production.
- Response remains human-controlled because authentication-only evidence is insufficient for safe
  automatic containment.
- Real-data activation is now one audited lifecycle: full raw verification, reusable normalization
  and causal features, four declared baselines, fused-objective TGN training, validation-only
  thresholding, sealed holdout evaluation, and rollback-safe promotion.
- The model lab reports PR-AUC, Recall@K, Precision@K, false positives per 10k, Brier score,
  threshold, split prevalence, leakage checks, release gates, and checkpoint lineage without
  inventing results when the licensed dataset is absent.
- Model jobs now use an atomic restart journal, a cross-process execution lease, run-scoped
  candidates, dataset-bound checkpoint metadata, and fail-closed raw-hash re-verification.

## Highest-value remaining development

1. Add identity privilege, peer group, MFA, service-account, device, and geographic context.
2. Add process, network flow, DNS, session lifecycle, Kerberos, asset, vulnerability, and criticality
   schemas with source-specific evidence provenance.
3. Add durable incidents/cases, ownership, comments, audit history, suppression, and risk decay.
4. Move ordered stream state and retry receipts to a partitioned durable processor; add PostgreSQL,
   tenant isolation, RBAC/OIDC, secret rotation, and horizontal query services.
5. Add a detection lifecycle with backtesting, versioned content, shadow mode, drift, false-positive
   feedback, calibration monitoring, and controlled rollback.
6. Integrate response only through approved, least-privilege playbooks with analyst confirmation,
   reversible actions, and complete audit records.
