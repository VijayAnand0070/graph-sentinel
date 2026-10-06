"""Build the GraphSentinel IEEE conference paper (.docx), then export PDF with Word."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from ooxml import (
    Media, Para, Raw, Refs, floating_box, mfrac, md, mfunc, mnary, mr, mrad, msub, msubsup, msup, macc,
    picture, ppr, rich, run, sect_pr, table, write_docx,
)

HERE = Path(__file__).resolve().parent
FIGS = HERE / "figs"
OUT_DOCX = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "GraphSentinel_Conference_Paper.docx"

COL = 4909            # column width, twips
FULL = 10106          # text width, twips
ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X"]

# ----------------------------------------------------------------- references
REFERENCES = {
    "mitre": 'MITRE ATT&CK, "Remote Services, Technique T1021 – Enterprise," The MITRE Corporation. '
             "[Online]. Available: https://attack.mitre.org/techniques/T1021/ (accessed Sep. 2026).",
    "siadati": 'H. Siadati and N. Memon, "Detecting structurally anomalous logins within enterprise networks," '
               "in *Proc. ACM SIGSAC Conf. Computer and Communications Security (CCS)*, Dallas, TX, USA, 2017, "
               "pp. 1273–1284.",
    "hopper": 'G. Ho, M. Dhiman, D. Akhawe, V. Paxson, S. Savage, G. M. Voelker, and D. Wagner, "Hopper: Modeling '
              'and detecting lateral movement," in *Proc. 30th USENIX Security Symp.*, 2021, pp. 3093–3110.',
    "log2vec": 'F. Liu, Y. Wen, D. Zhang, X. Jiang, X. Xing, and D. Meng, "Log2vec: A heterogeneous graph embedding '
               'based approach for detecting cyber threats within enterprise," in *Proc. ACM SIGSAC Conf. Computer '
               "and Communications Security (CCS)*, London, U.K., 2019, pp. 1777–1794.",
    "bowman": 'B. Bowman, C. Laprade, Y. Ji, and H. H. Huang, "Detecting lateral movement in enterprise computer '
              'networks with unsupervised graph AI," in *Proc. 23rd Int. Symp. Research in Attacks, Intrusions and '
              "Defenses (RAID)*, 2020, pp. 257–268.",
    "euler": 'I. J. King and H. H. Huang, "Euler: Detecting network lateral movement via scalable temporal link '
             'prediction," in *Proc. Network and Distributed System Security Symp. (NDSS)*, San Diego, CA, USA, 2022.',
    "jbeil": "J. Khoury, Đ. Klisura, H. Zanddizari, G. De La Torre Parra, P. Najafirad, and E. Bou-Harb, "
             '"Jbeil: Temporal graph-based inductive learning to infer lateral movement in evolving enterprise '
             'networks," in *Proc. IEEE Symp. Security and Privacy (SP)*, San Francisco, CA, USA, 2024, '
             "pp. 3644–3660.",
    "lanl": 'A. D. Kent, "Comprehensive, multi-source cyber-security events," Los Alamos National Laboratory, 2015, '
            "doi: 10.17021/1179829.",
    "larroche": 'C. Larroche, "On fair and realistic performance evaluations for graph-based lateral movement '
                'detectors," arXiv:2607.29390, Jul. 2026.',
    "sommer": 'R. Sommer and V. Paxson, "Outside the closed world: On using machine learning for network intrusion '
              'detection," in *Proc. IEEE Symp. Security and Privacy*, Oakland, CA, USA, 2010, pp. 305–316.',
    "arp": "D. Arp, E. Quiring, F. Pendlebury, A. Warnecke, F. Pierazzi, C. Wressnegger, L. Cavallaro, and K. Rieck, "
           '"Dos and don’ts of machine learning in computer security," in *Proc. 31st USENIX Security Symp.*, '
           "Boston, MA, USA, 2022, pp. 3971–3988.",
    "tgn": 'E. Rossi, B. Chamberlain, F. Frasca, D. Eynard, F. Monti, and M. Bronstein, "Temporal graph networks for '
           'deep learning on dynamic graphs," arXiv:2006.10637, 2020.',
    "jodie": 'S. Kumar, X. Zhang, and J. Leskovec, "Predicting dynamic embedding trajectory in temporal interaction '
             'networks," in *Proc. 25th ACM SIGKDD Int. Conf. Knowledge Discovery & Data Mining*, Anchorage, AK, '
             "USA, 2019, pp. 1269–1278.",
    "tgat": 'D. Xu, C. Ruan, E. Korpeoglu, S. Kumar, and K. Achan, "Inductive representation learning on temporal '
            'graphs," in *Proc. Int. Conf. Learning Representations (ICLR)*, 2020.',
    "gru": "K. Cho, B. van Merriënboer, C. Gulcehre, D. Bahdanau, F. Bougares, H. Schwenk, and Y. Bengio, "
           '"Learning phrase representations using RNN encoder–decoder for statistical machine translation," '
           "in *Proc. Conf. Empirical Methods in Natural Language Processing (EMNLP)*, Doha, Qatar, 2014, "
           "pp. 1724–1734.",
    "edgebank": 'F. Poursafaei, S. Huang, K. Pelrine, and R. Rabbany, "Towards better evaluation for dynamic link '
                'prediction," in *Advances in Neural Information Processing Systems (NeurIPS)*, vol. 35, Datasets '
                "and Benchmarks Track, 2022.",
    "graphmixer": "W. Cong, S. Zhang, J. Kang, B. Yuan, H. Wu, X. Zhou, H. Tong, and M. Mahdavi, "
                  '"Do we really need complicated model architectures for temporal networks?" in *Proc. Int. Conf. '
                  "Learning Representations (ICLR)*, Kigali, Rwanda, 2023.",
    "irs": 'Z. Inayat, A. Gani, N. B. Anuar, M. K. Khan, and S. Anwar, "Intrusion response systems: Foundations, '
           'design, and challenges," *J. Network and Computer Applications*, vol. 62, pp. 53–74, 2016.',
    "halluc": "Z. Ji, N. Lee, R. Frieske, T. Yu, D. Su, Y. Xu, E. Ishii, Y. J. Bang, A. Madotto, and P. Fung, "
              '"Survey of hallucination in natural language generation," *ACM Computing Surveys*, vol. 55, no. 12, '
              "art. 248, 2023.",
    "otrf": 'R. Rodriguez and J. L. Rodriguez, "Security Datasets," Open Threat Research Forge (OTRF). [Online]. '
            "Available: https://github.com/OTRF/Security-Datasets (accessed Sep. 2026).",
    "pearl": "J. Pearl, *Probabilistic Reasoning in Intelligent Systems: Networks of Plausible Inference*. "
             "San Mateo, CA, USA: Morgan Kaufmann, 1988.",
    "wilson": 'E. B. Wilson, "Probable inference, the law of succession, and statistical inference," *J. American '
              'Statistical Association*, vol. 22, no. 158, pp. 209–212, 1927.',
    "saito": 'T. Saito and M. Rehmsmeier, "The precision-recall plot is more informative than the ROC plot when '
             'evaluating binary classifiers on imbalanced datasets," *PLoS ONE*, vol. 10, no. 3, e0118432, 2015.',
    "efron": "B. Efron and R. J. Tibshirani, *An Introduction to the Bootstrap*. New York, NY, USA: "
             "Chapman & Hall, 1993.",
    "iforest": 'F. T. Liu, K. M. Ting, and Z.-H. Zhou, "Isolation forest," in *Proc. 8th IEEE Int. Conf. Data '
               'Mining (ICDM)*, Pisa, Italy, 2008, pp. 413–422.',
}

# ------------------------------------------------------------------ equations
def v(s):          # bold vector
    return mr(s, "b")


def it(s):         # italic variable
    return mr(s)


def up(s):         # upright text
    return mr(s, "p")


def sub(b, s):
    return msub(b, s)


EQUATIONS = {
    "event": sub(it("e"), it("k")) + up("=") + md(
        sub(it("u"), it("k")) + up(",") + sub(it("s"), it("k")) + up(",") + sub(it("d"), it("k")) + up(",")
        + sub(it("t"), it("k")) + up(",") + sub(v("x"), it("k")))
        + up(",  ") + sub(v("x"), it("k")) + up("=") + it("Φ")
        + md(sub(it("e"), it("k")) + up(" | ") + sub(it("ℋ"), up("<") + sub(it("t"), it("k")))),
    "time": it("ψ") + md(up("Δ") + it("t")) + up("=") + mfunc("cos", md(
        v("ω") + up("⊙") + mfunc("log", md(up("1+Δ") + it("t"))) + up("+") + v("φ"))),
    "concat": sub(v("z"), it("k")) + up("=") + md(
        sub(v("m"), it("u")) + up("‖") + sub(v("m"), it("s")) + up("‖") + sub(v("m"), it("d")) + up("‖")
        + sub(macc(v("x"), "̂"), it("k")) + up("‖") + it("ψ") + md(up("Δ") + sub(it("t"), it("u")))
        + up("‖") + it("ψ") + md(up("Δ") + sub(it("t"), it("d"))), "[", "]"),
    "score": sub(it("p"), it("k")) + up("=") + it("σ") + md(
        msup(v("w"), up("⊤")) + md(it("g") + md(sub(v("z"), it("k"))) + up("+") + v("P") + sub(v("z"), it("k")))
        + up("+") + it("b")),
    "attn": sub(it("α"), it("j")) + up("=") + msub(up("softmax"), it("j")) + md(
        msup(v("a"), up("⊤")) + md(sub(v("μ"), it("j")) + up("‖") + sub(v("m"), it("i")), "[", "]")),
    "gru": sub(v("m"), it("i")) + up("←") + up("GRU") + md(
        up("LN") + md(mnary("∑", it("j"), sub(it("α"), it("j")) + sub(v("μ"), it("j"))))
        + up(",") + sub(v("m"), it("i"))),
    "loss": it("ℒ") + up("=−") + mfrac(up("1"), it("N")) + mnary("∑", it("k"), md(
        it("β") + sub(it("y"), it("k")) + mfunc("log", sub(it("p"), it("k"))) + up("+")
        + md(up("1−") + sub(it("y"), it("k"))) + mfunc("log", md(up("1−") + sub(it("p"), it("k")))), "[", "]")),
    "noisyor": sub(it("R"), it("k")) + up("=1−") + md(up("1−") + sub(it("r"), up("0")) + sub(it("p"), it("k")))
        + mnary("∏", it("c") + up("∈") + it("𝒞"), md(up("1−") + sub(it("r"), it("c")) + sub(it("s"), it("k") + up(",") + it("c")))),
    "floor": sub(it("ρ"), it("k")) + up("=") + up("max") + md(
        sub(it("R"), it("k")) + up(", ") + sub(it("τ"), it("x")) + up("·") + up("𝟙")
        + md(sub(up("chain"), it("k")), "[", "]")),
    "wilson": up("LB") + up("=") + mfrac(
        macc(it("p"), "̂") + up("+") + mfrac(msup(it("z"), up("2")), up("2") + it("n")) + up("−") + it("z")
        + mrad(mfrac(macc(it("p"), "̂") + md(up("1−") + macc(it("p"), "̂")), it("n")) + up("+")
               + mfrac(msup(it("z"), up("2")), up("4") + msup(it("n"), up("2")))),
        up("1+") + mfrac(msup(it("z"), up("2")), it("n"))),
    "prevent": it("η") + up("=") + mfrac(up("1"), it("N") + it("L")) + mnary(
        "∑", it("c") + up("∈") + it("𝒜"), md(it("L") + up("−") + sub(it("a"), it("c")) + up("−1"))),
}

# --------------------------------------------------------------------- content
# Figures, tables and equations are numbered in the order they appear below.
C = []


def P(text):
    C.append(("p", text))


def H1(text):
    C.append(("h1", text))


def H2(text):
    C.append(("h2", text))


def EQ(label):
    C.append(("eq", label))


def FIG(label, file, width, caption, full=False):
    C.append(("fig", label, file, width, caption, full))


def TAB(label, caption, widths, rows, full=False, aligns=None):
    C.append(("tab", label, caption, widths, rows, full, aligns))


TITLE = ("GraphSentinel: Detecting and Containing Lateral Movement in Authentication Logs "
         "with Temporal Graph Networks and a Bounded Response Loop")

AUTHORS = [
    ["[Author Name 1]", "[Designation]", "[Department]", "[Institution]", "[City, Country]", "[e-mail address]"],
    ["[Author Name 2]", "[Designation]", "[Department]", "[Institution]", "[City, Country]", "[e-mail address]"],
    ["[Author Name 3]", "[Designation]", "[Department]", "[Institution]", "[City, Country]", "[e-mail address]"],
    ["[Author Name 4]", "[Designation]", "[Department]", "[Institution]", "[City, Country]", "[e-mail address]"],
    ["[Author Name 5]", "[Designation]", "[Department]", "[Institution]", "[City, Country]", "[e-mail address]"],
]

ABSTRACT = (
    "Lateral movement, in which an intruder reuses valid credentials to hop from host to host, is recorded in "
    "enterprise authentication logs, yet learned detectors for it are usually evaluated offline and stop at an "
    "alert. This paper presents GraphSentinel, a system that ingests authentication logs of several formats, "
    "scores every logon with a temporal graph network (TGN) over users and hosts using 27 causal features, fuses "
    "that score with explicit evidence through a noisy-OR gate and a same-account chain rule, and closes the loop "
    "with a bounded response: an unattended session reset once a precision-derived gate is crossed, a check on "
    "whether the account keeps moving, escalation to a two-hour account lock, and automatic reversal. A locally "
    "hosted language-model agent drafts triage and incident reports in which every statement must cite supplied "
    "evidence, with a deterministic fallback. On the Los Alamos authentication corpus the TGN reaches a test "
    "PR-AUC of 0.821, but holding out the single dominant attacker host lowers it to 0.002, and on a corrected "
    "slice without local logons a logistic regression over the same features scores 0.956, above every "
    "TGN-based detector (at most 0.676). Replaying 100 simulated campaigns, the loop acts on 38 and prevents "
    "14.6% of attack hops (27.8% for single-credential chains) at 5.5 unattended actions per 10,000 benign "
    "logons, and escalation retains 9.3% prevention even when session resets never work. On 21 public Windows "
    "lateral-movement recordings the frozen model ranks attacks above chance (ROC-AUC 0.66) but alerts on only "
    "two. We report these limits alongside the system as guidance for deploying learned detectors with "
    "automatic response."
)

KEYWORDS = ("lateral movement, authentication logs, temporal graph networks, intrusion detection, automated "
            "incident response, security operations, large language models")

# I. INTRODUCTION ------------------------------------------------------------
H1("INTRODUCTION")
P("After an initial compromise, an intruder rarely stops at the first host. The usual next step is to log in to "
  "other machines through remote services with credentials that are valid but stolen, the behaviour catalogued "
  "as technique T1021 in MITRE ATT&CK [@mitre]. Every hop leaves an authentication record on the destination "
  "host or on a domain controller. Taken one at a time these records look legitimate, because the credentials "
  "are genuine; the anomaly lies in the sequence, when an account begins to reach hosts it has never used, "
  "often from a host it reached only minutes before.")
P("Research on this problem has moved from mining login patterns [@siadati] and reconstructing login paths "
  "[@hopper] to graph embeddings [@log2vec,bowman] and temporal link prediction with graph neural networks "
  "[@euler,jbeil]. Much of this work is evaluated on the Los Alamos National Laboratory (LANL) authentication "
  "corpus [@lanl], on which several detectors report very high scores. Two gaps nevertheless separate these "
  "results from an operational defence. First, almost every system ends at a ranked list of alerts, whereas "
  "scripted lateral movement can complete several hops before an analyst opens the first one. Second, recent "
  "re-examinations show that reported LANL results depend strongly on preprocessing and labelling choices "
  "[@larroche], echoing long-standing warnings about how machine learning is evaluated in security "
  "[@sommer,arp].")
P("This paper describes GraphSentinel, a detection-and-response system designed around both gaps, and measures "
  "what it does and does not achieve. The objectives of the work are as follows:")
C.append(("list", [
    "To ingest authentication logs from different sources (LANL records, Windows Security events, SSH and cloud "
    "sign-in exports, generic CSV or JSON files) into one canonical event stream with automatic format detection.",
    "To score every logon with a temporal graph network (TGN) [@tgn] whose node memories summarise the history "
    "of each account and host, using 27 features computed strictly from past events.",
    "To combine the learned probability with explicit evidence in an auditable way, and to derive the threshold "
    "for unattended action from a statistical lower bound on precision rather than a hand-picked value.",
    "To respond automatically within explicit bounds (contain, verify, escalate and revert) under hourly and "
    "per-account budgets, recording every action for audit.",
    "To produce triage and incident reports with a locally hosted language model whose statements are checked "
    "against the evidence before they reach an analyst.",
    "To quantify prevention, false-action cost and generalisation, including the cases in which the learned "
    "model does not help.",
]))
P("Beyond the system, the evaluation yields three findings that we regard as equally important: the headline "
  "LANL score is dominated by one attacking host; once local logons are removed, a linear model over the same "
  "features outperforms the TGN; and a model that ranks attacks sensibly on an unseen network can still miss "
  "nearly all of them at a threshold calibrated elsewhere. Section II reviews related work, Section III "
  "presents the datasets and the architecture, Section IV details the model and decision layers, Section V "
  "reports the results, and Section VI concludes.")

# II. RELATED WORK -------------------------------------------------------------
H1("RELATED WORK")
P("Siadati and Memon [@siadati] describe the normal login structure of an enterprise with market-basket pattern "
  "mining and flag logins that do not fit it, detecting 82% of malicious logins at a 0.3% false-positive rate "
  "over five months of data from a financial company. Hopper [@hopper] builds a graph of logins between "
  "internal machines, infers the causal paths that connect them, and alerts on paths that switch credentials "
  "or reach unusual destinations; over fifteen months of enterprise logs it detects 94.5% of more than 300 "
  "realistic attack scenarios with fewer than nine alerts per day. Both works establish that the path, rather "
  "than the individual login, carries the signal, an idea that GraphSentinel's chain rule applies in streaming "
  "form.")
P("Log2vec [@log2vec] converts audit records into a heterogeneous graph with rule-defined relations, learns "
  "random-walk embeddings and separates malicious activity by clustering. Bowman et al. [@bowman] learn "
  "unsupervised embeddings of authenticating entities and score each authentication with a link predictor, "
  "improving on heuristic baselines in a simulated and a real environment. Euler [@euler] stacks a graph "
  "neural network on a recurrent encoder over discrete graph snapshots and distributes the computation across "
  "machines, and Jbeil [@jbeil] applies inductive temporal-graph learning to LANL authentications, reporting an "
  "AUC above 0.99 even when part of the graph is withheld during training. These detectors build on "
  "continuous-time graph models such as JODIE [@jodie], TGAT [@tgat] and TGN [@tgn], which keep a state per "
  "node that is updated as timestamped interactions arrive; GraphSentinel uses a TGN-style memory updated by a "
  "gated recurrent unit (GRU) [@gru].")
P("Benchmarks for dynamic graphs can reward memorisation: a baseline that merely remembers past edges performs "
  "strongly under common protocols [@edgebank], and a simple MLP-based architecture matches more elaborate "
  "temporal models [@graphmixer]. In security, Sommer and Paxson [@sommer] explain why anomaly detection is "
  "harder to evaluate than in other domains, Arp et al. [@arp] catalogue pitfalls such as sampling bias, "
  "spurious correlations and inappropriate baselines, and Larroche [@larroche] "
  "re-evaluates three graph-based lateral-movement detectors on LANL and OpTC under standardised preprocessing "
  "and labelling, obtaining results well below those originally reported. The entity-contamination and "
  "sampling effects reported in Section V are instances of these pitfalls, measured on our own system.")
P("Automated intrusion response is a field of its own, and surveys stress that the cost of a wrong automatic "
  "response must be weighed against the damage it prevents [@irs]; learned lateral-movement detectors, in contrast, rarely "
  "specify how an alert becomes an action. Language models are increasingly used to summarise alerts, but their "
  "tendency to produce unsupported statements [@halluc] makes unchecked output unsuitable for security "
  "decisions. GraphSentinel therefore bounds automated response with budgets and reversal, and restricts the "
  "language model to claims that cite supplied evidence. {tab:related} compares representative work.")

TAB("related", "Comparative Analysis of Related Work on Lateral-Movement Detection",
    [1650, 2230, 1400, 2500, 2326],
    [["Author & Year", "Method", "Data", "Contribution", "Limitation"],
     ["Siadati & Memon (2017) [@siadati]", "Market-basket mining of login patterns", "Enterprise logins, 5 months",
      "82% of malicious logins at 0.3% false positives", "Single-login view; alerts only"],
     ["Liu et al. (2019) [@log2vec]", "Heterogeneous graph embedding and clustering", "CERT, LANL",
      "Rule-defined relations between log entries", "Offline batch; hand-built relations"],
     ["Bowman et al. (2020) [@bowman]", "Unsupervised graph embedding, link prediction", "Simulated network, LANL",
      "Outperforms heuristic baselines", "Static embeddings; alerts only"],
     ["Ho et al. (2021) [@hopper]", "Login-path inference, credential switching", "Enterprise logs, 15 months",
      "94.5% detection, < 9 alerts per day", "Depends on path inference; alerts only"],
     ["King & Huang (2022) [@euler]", "GNN with recurrent encoder over snapshots", "LANL",
      "Scalable temporal link prediction", "Discrete snapshots; alerts only"],
     ["Khoury et al. (2024) [@jbeil]", "Inductive temporal graph learning", "LANL",
      "AUC > 0.99 with unseen nodes", "Offline evaluation; alerts only"],
     ["Larroche (2026) [@larroche]", "Standardised re-evaluation protocol", "LANL, OpTC",
      "Shows preprocessing changes reported results", "Evaluation study, no detector"],
     ["This work", "TGN, noisy-OR fusion, chain rule, bounded response, grounded LLM reports", "LANL, OTRF",
      "Measures prevention and false-action cost end to end", "Prevention measured on simulated campaigns"]],
    full=True)

# III. SYSTEM ARCHITECTURE ------------------------------------------------------
H1("SYSTEM ARCHITECTURE")
H2("Datasets")
P("The primary corpus is the LANL comprehensive cyber-security events dataset [@lanl], which covers 58 "
  "consecutive days of de-identified activity by 12,425 users on 17,684 computers. Its authentication file "
  "holds 1,051,430,459 events, each giving the time, the source and destination user and computer, the "
  "authentication and logon type, the orientation and the outcome. A separate file lists 749 red-team "
  "compromise events involving 104 accounts and 301 destination hosts. These labels are highly concentrated: "
  "701 of the 749 events originate from one source computer and the other 48 from three more (26, 19 and 3 "
  "events), which shapes every evaluation on this corpus.")
P("Two processed corpora are used ({tab:corpora}). The corpus behind the shipped model (C1) keeps every event "
  "that matches a red-team record and one in 512 of the others over the first 16 days, split chronologically "
  "so that each partition holds complete campaigns. A corrected slice (C2) covers the first 900,000 s, removes "
  "the 95,025,843 local logons (source equal to destination; none is labelled as an attack), which make up "
  "53.8% of the raw stream, and keeps one in 448 of the remaining events. Stride sampling makes training "
  "feasible on a laptop GPU (NVIDIA RTX 3050, 6 GB), but it inflates the prevalence of attacks and truncates "
  "benign histories; Section V-D quantifies the consequence for rules.")
TAB("corpora", "Corpora Used in the Evaluation", [1200, 1170, 690, 1849],
    [["Corpus", "Events", "Attacks", "Train / val. / test attacks"],
     ["LANL raw", "1,051,430,459", "749", "58 days; 4 attacker hosts"],
     ["C1 (shipped)", "543,615", "649", "316 / 207 / 126"],
     ["C2 (corrected)", "182,815", "316", "50 / 165 / 101"],
     ["OTRF", "195", "77", "external test, 21 recordings"]],
    aligns=["left", "right", "right", "center"])
P("The external test set comes from the OTRF Security Datasets project [@otrf]: 29 public recordings of "
  "Windows Security telemetry from a small lab domain, each capturing one lateral-movement technique executed "
  "with Empire, Covenant, Mimikatz or PurpleSharp. Ground truth was assigned per recording from the attacker "
  "console transcripts published with the data. Six recordings were excluded before scoring because their "
  "metadata name no target or describe a different lab, and two produced no authentication edge, leaving 21 "
  "recordings with 77 attack and 118 benign events.")
H2("Architecture")
P("{fig:arch} shows the architecture, which runs as a single process over one ordered event stream. Source "
  "adapters for LANL, Windows Security, SSH, Zeek, Entra ID, Okta and tabular files convert records into a "
  "canonical event (time, account, source host, destination host, authentication attributes and outcome); "
  "when the format is not declared, a detector scores candidate columns by their content and names the adapter "
  "it selected, warning about ambiguous fields. An entity dictionary, frozen together with the model "
  "checkpoint, maps names to integer identifiers, and unseen names are hashed into 4,096 user and 16,384 host "
  "out-of-vocabulary buckets. The causal feature engine computes 27 features per event, the TGN produces a "
  "probability, explicit channels and a chain rule add rule-based evidence, and the fusion layer produces one "
  "risk value per event. That value is compared with two thresholds: an alert threshold that feeds the analyst "
  "queue and a stricter execution gate that permits unattended action.")
P("Actions pass through a single response coordinator, which enforces budgets and runs the prevention loop, and "
  "an executor that records the exact command and its undo for every connector (directory service, endpoint "
  "agent, host firewall). Connectors stay in dry-run mode until an operator arms them. Feature state and TGN "
  "memories are persisted, so a restart resumes with warm state; on C2 the deployed service reproduced the "
  "offline PR-AUC to five decimal places (0.603796 against 0.603798) while processing 315 events/s. A path "
  "ranker assembles suspicious multi-hop paths, and a report agent turns alerts and incidents into documents "
  "for analysts. The system is implemented in Python with PyTorch, a FastAPI service and a browser console; "
  "its 754 automated tests pass.")
FIG("arch", "fig1_architecture.png", 7.0,
    "Architecture of GraphSentinel. Logs of any supported format become one canonical event stream; each event "
    "is scored from past-only features and node memory, fused with explicit evidence, and compared with an alert "
    "threshold and a stricter execution gate that drives a bounded response loop.", full=True)

# IV. MODEL BUILDING -----------------------------------------------------------
H1("MODEL BUILDING")
H2("Canonical Events and Causal Features")
P("Each authentication becomes an event (1), where *u*_{*k*} is the account, *s*_{*k*} and *d*_{*k*} are the "
  "source and destination hosts, *t*_{*k*} is the time and **x**_{*k*} ∈ ℝ^{27} is a feature vector computed "
  "by a function Φ of the history ℋ strictly before *t*_{*k*}, so that no feature can encode the future or the "
  "label.")
EQ("event")
P("The features describe the event itself (outcome, authentication and logon type, orientation, hour of day as "
  "sine and cosine), recency (logarithmic time since the account's and the pair's previous events), novelty "
  "(whether the account and the account–destination pair were seen before, pair rarity, destination "
  "novelty), windowed behaviour (distinct destinations per account over 5 min, 1 h and 24 h, authentication "
  "rate, failure rate and failures before success within 15 min, share of new destinations) and structure "
  "(fan-out of the source host, distinct inbound users of the destination, historical degrees of the account "
  "and both hosts).")
H2("Temporal Graph Network")
P("Accounts and hosts are nodes with a 64-dimensional memory **m**. The time since a node was last updated "
  "enters through a learnable harmonic encoding (2), in which **ω** and **φ** are learned 16-dimensional "
  "frequencies and phases and the logarithm compresses gaps from seconds to weeks. For event *e*_{*k*}, the "
  "scorer concatenates the memories of the account and of both hosts, the standardised features and the time "
  "encodings (3), and maps the result to a probability through a two-layer network *g* with LayerNorm, GELU "
  "and dropout plus a linear residual projection **P** (4).")
EQ("time")
EQ("concat")
EQ("score")
P("Only after scoring does the event update memory ({fig:tgn}). A message function *h* forms one message per "
  "endpoint from its own memory, the other endpoint's memory, the features and the time encodings; messages "
  "that reach node *i* within a batch are weighted by attention (5), and their normalised sum updates the "
  "memory through a GRU cell (6). Scoring before updating guarantees that an event is judged by the state that "
  "existed before it; the implementation enforces this order and a regression test asserts it. Events are "
  "processed in 60-s buckets, a 20.7-fold training speed-up, and within a bucket memory is still read before "
  "any write.")
EQ("attn")
EQ("gru")
FIG("tgn", "fig2_tgn.png", 3.35,
    "TGN scorer. An event is scored from the memories that existed before it (step 1); only then are messages "
    "formed and aggregated (step 2) and memories written (step 3).")
P("The model has 107,585 parameters. It is trained with the class-weighted binary cross-entropy (7), where "
  "*β* is the ratio of negative to positive training events capped at 120, using AdamW (learning rate "
  "10^{−3}, weight decay 0.01), truncated back-propagation every 2,048 events and 16 epochs on C1; validation "
  "PR-AUC improved in every epoch, so early stopping (patience 5) never triggered.")
EQ("loss")
H2("Evidence Fusion and Chain Rule")
P("A weighted average of detection channels lets the learned score veto every rule: with weights summing to "
  "one and 0.55 on the model, the remaining channels could reach at most 0.45, below the 0.454 alert threshold "
  "then in use. GraphSentinel instead fuses channels with a noisy-OR gate [@pearl] (8), in which each channel "
  "*c* with signal *s*_{*k*,*c*} ∈ [0, 1] has an independent reliability *r*_{*c*}. The reliabilities, fitted "
  "on validation data by coordinate ascent on PR-AUC, are 0.95 for the TGN, 0.35 for cross-source "
  "corroboration, 0.30 for burst and 0.05 for novelty and pivot. Any single strong channel can carry an alert, "
  "weak channels compound, and adding evidence never lowers the risk.")
EQ("noisyor")
P("The chain rule turns the path intuition of [@hopper] into a streaming test. An event is a chain hop if it is "
  "a successful authentication by account *u* from a host that *u* has already reached, to a host that *u* "
  "has never successfully reached, and *u* has made at least three such novel hops within the previous "
  "1,800 s. Novelty is judged from the rule's own record of successful logons, because counting failed "
  "attempts as sightings would let an attacker who guesses a password before each hop make every hop look "
  "familiar. When the rule fires, the fused risk is raised to a floor (9), which in the unattended policy "
  "equals the execution gate.")
EQ("floor")
H2("Execution Gate")
P("Two thresholds are applied to *ρ*_{*k*}. The alert threshold *τ*_{*a*} = 0.329 was set on validation data "
  "at a budget of 25 false positives per 10,000 benign events (FP/10k). The execution gate *τ*_{*x*} is derived "
  "by scanning candidate thresholds downward from the highest validation score and keeping the last one at "
  "which the Wilson lower bound [@wilson] (10) on precision is still at least 0.75 over at least 20 alerts, "
  "where *p̂* is the precision of the *n* alerts above the candidate and *z* = 1.96.")
EQ("wilson")
P("On C1 this yields *τ*_{*x*} = 0.846, admitting 251 validation alerts at 80.5% precision (lower bound "
  "75.1%). On the later test period the same gate yields 201 alerts at 53.2% precision [46.3%, 60.0%] and "
  "8.1 benign actions per 10,000 events: the meaning of a fixed gate decays with time, so both figures are "
  "stored with the constant and neither is quoted alone.")
H2("Bounded Response Loop")
P("{fig:loop} shows the loop. When *ρ*_{*k*} ≥ *τ*_{*x*} and budget remains (at most 20 unattended actions per "
  "hour and one per account per hour), the coordinator contains the account by forcing re-authentication: the "
  "account is logged off the source host and its cloud refresh tokens are revoked. Below the gate or over "
  "budget, the plan waits for an analyst. Containment is then verified in event time: if the same account "
  "authenticates onward within 30 min, the reset has failed, and the loop escalates to an account lock. The "
  "lock is reversible and lifts automatically after two hours unless an analyst keeps it, which leaves time for "
  "a decision without letting a false positive lock a user out for a working day. Other disruptive actions "
  "(credential reset, host isolation, network block) always wait for approval, and every action, approval and "
  "reversal is written to an audit store that also restores active locks after a restart.")
FIG("loop", "fig3_loop.png", 3.35,
    "Bounded response loop. Unattended containment requires the execution gate and free budget; continued "
    "movement within 30 min escalates to a reversible two-hour account lock.")
H2("Grounded Report Agent")
P("Triage notes and incident reports are generated by a LangGraph workflow over a locally hosted model "
  "(qwen3.5:4b served by Ollama), so no log data leaves the host. The workflow has four steps: prepare "
  "assembles an evidence bundle with identifiers (E-nnn for alert evidence, F-nnn for incident facts); draft "
  "asks the model for a structured report; validate rejects any statement that cites a missing identifier, "
  "names an alert outside the incident, claims an action the system did not take or raises the severity; and "
  "repair returns the specific violation to the model. After three failed attempts, or if the model is "
  "unavailable, a deterministic writer produces the report from the same bundle, and every response carries "
  "headers that state which path produced it. The model can change how a report reads but not what it "
  "records: severity, alerts, hosts and actions are checked against the records, and the prompt requires the "
  "first step recommended to the analyst to be a verification rather than an approval to isolate or block. "
  "On the project's own incidents a "
  "triage note took about 8 s and a five-alert incident report about 30 s on the laptop, both accepted at the "
  "first attempt; this is an observation, not a benchmark. {fig:report} reproduces part of one generated "
  "report.")
C.append(("box", "report", [
    "**Critical account C2287$@DOM1 authenticated across 4 hosts with high fused risk**",
    "Incident INC-C2287$@DOM1-2932909 · severity CRITICAL · window 93 s · 5 alerts · hosts "
    "C5554, C1137, C988, C4483",
    "**Summary.** Account C2287$@DOM1 authenticated from four distinct hosts within a 93-second window, "
    "reaching the highest fused risk of 0.8464. [F-001, F-006, F-007]",
    "**What the system did automatically.** The system ran force_reauth on C2287$@DOM1 with outcome dry_run "
    "and authority plan, followed by lock_account with outcome dry_run and authority escalation. "
    "[F-008, F-009] […]",
    "**Uncertainty.** The account qualified for an unattended action again 24s after the first force_reauth "
    "attempt, requiring escalation to lock_account. [F-019]",
], "Verbatim excerpt ([…] marks omissions) of a report drafted by the local model on the demonstration "
   "stream (synthetic events over LANL identities). Cited identifiers must exist in the evidence bundle."))

# V. RESULTS AND DISCUSSION -----------------------------------------------------
H1("RESULTS AND DISCUSSION")
H2("Experimental Setup")
P("Thresholds are chosen on validation data only and each test partition is scored once. PR-AUC is the primary "
  "metric because attacks are rare [@saito]; ROC-AUC and FP/10k are reported alongside it. Intervals are 95% "
  "stratified bootstrap intervals [@efron] with 2,000 (C1) or 1,000 (C2) resamples, and detectors are compared "
  "on identical resamples. The baselines, scored on the same partitions, are a hand-written rule, a rarity "
  "score, an isolation forest [@iforest] and a class-weighted logistic regression over the 27 features.")
H2("Detection on LANL")
P("{tab:detect} reports test PR-AUC. On C1 the TGN reaches 0.821 [0.764, 0.878] with ROC-AUC 0.999, "
  "significantly above the shipped noisy-OR pipeline (0.805; paired difference +0.016 [+0.006, +0.031]) and "
  "far above the logistic baseline (0.246). At its validation-derived threshold the noisy-OR pipeline "
  "recalls 90.5% of test attacks at 34.8 FP/10k.")
TAB("detect", "Test PR-AUC on the Two LANL Corpora", [1829, 1540, 1540],
    [["Detector", "C1 (126 attacks)", "C2 (101 attacks)"],
     ["Chance (prevalence)", "0.001", "0.004"],
     ["Hand-written rule", "0.071", "0.548"],
     ["Rarity score", "0.007", "0.288"],
     ["Isolation forest", "0.041", "0.244"],
     ["Logistic regression", "0.246", "**0.956**"],
     ["Linear fusion (TGN + channels)", "0.577 [0.498, 0.656]", "0.676 [0.588, 0.757]"],
     ["Noisy-OR fusion (shipped)", "0.805 [0.741, 0.867]", "0.604 [0.520, 0.696]"],
     ["TGN probability", "**0.821** [0.764, 0.878]", "0.566 [0.480, 0.660]"],
     ["Best detector, dominant attacker host held out", "0.0019", "0.0003"]],
    aligns=["left", "center", "center"])
P("Two checks change how these numbers should be read. First, 121 of the 126 test attacks come from one host "
  "that never appears in benign training traffic. Holding its attacks out and scoring the remaining five "
  "against all benign events lowers the TGN from 0.821 to 0.0019 [0.0017, 0.0037], so 99.8% of the headline "
  "figure rests on one campaign. Second, on C2 the ordering reverses: the logistic regression reaches 0.956 (ROC-AUC "
  "0.999), whereas the TGN reaches 0.566 [0.480, 0.660] and its fused variants 0.604 and 0.676, and the "
  "pipeline's promotion gate, which requires a candidate to beat the best baseline on validation, rejected "
  "the TGN. Holding out the dominant host on C2 lowers the best fused detector from 0.676 to 0.0003. Even on "
  "C1, the training pipeline found the TGN and the logistic model indistinguishable on validation (PR-AUC "
  "0.913 against 0.916), although on test the TGN is far ahead.")
P("The reversal is a warning rather than a contradiction. The corpora differ in local logons, sampling stride "
  "and time span, and each test partition is dominated by one attacker; which model wins depends on these "
  "choices, consistent with the re-evaluations in [@larroche] and the benchmark critiques in "
  "[@edgebank,graphmixer]. We therefore read the LANL scores as comparisons under a stated protocol, not as "
  "field accuracy, and we do not claim that the TGN is better than simpler models.")
P("Whether the TGN learned the dominant campaign's behaviour or merely its host was tested with a score-time "
  "ablation on the C1 test partition ({tab:ablation}): each condition replaces part of the scorer's input while "
  "the memory trajectory stays identical. Zeroing every memory lowers PR-AUC from 0.821 to 0.389, mostly because "
  "benign scoring collapses (34.5 to 969.8 FP/10k) as every ordinary event starts to look unfamiliar; recall on "
  "the dominant host's attacks at the alert threshold falls only from 94.2% to 81.8%, and neutralising the five "
  "entity-degree features still leaves 78.5%. The campaign is thus recognised from behaviour spread across "
  "features rather than from an identity channel, and the memory mainly serves to recognise benign "
  "familiarity; the model has, however, seen only one campaign of this kind.")
TAB("ablation", "Score-Time Ablation on the C1 Test Partition", [1989, 760, 1260, 900],
    [["Condition", "PR-AUC", "Main-host recall", "FP/10k"],
     ["Full model", "0.821", "94.2%", "34.5"],
     ["Destination memory zeroed", "0.469", "90.9%", "719.2"],
     ["All memory zeroed", "0.389", "81.8%", "969.8"],
     ["Source-host degree at median", "0.660", "95.0%", "55.9"],
     ["Five degree features at median", "0.671", "78.5%", "16.0"]],
    aligns=["left", "center", "center", "center"])
H2("Prevention")
P("A recorded corpus cannot measure prevention, because nothing in it is counterfactual: the red team's fifth "
  "hop happened whether or not the fourth was detected. We therefore replay campaigns of known length through "
  "the production composition of the stack (features, TGN with restored memory, channels, chain rule, fusion, "
  "thresholds and response planner). Benign traffic is resampled from each user's own history, and the attacker "
  "operates from an ordinary busy workstation that also carries benign activity, so host identity cannot "
  "separate the classes. The grid has two families, a chain that carries one credential from host to host and "
  "a fan-out that rotates harvested credentials from one host, at ten inter-hop intervals from 15 s to 1 h, "
  "with five replicates of eight hops: 100 campaigns and 800 attack events among 102,476 benign events over "
  "three simulated days, after a warm-up that restores state through the validation boundary. The prevented "
  "fraction *η* counts the hops that follow the first unattended action (11), where 𝒜 is the set of the *N* = "
  "100 campaigns that received one, *a*_{*c*} is the index of the triggering hop and *L* = 8.")
EQ("prevent")
TAB("prevent", "Prevention Instrument Results", [2229, 860, 920, 900],
    [["Measure", "Chain", "Fan-out", "All"],
     ["Campaigns (8 hops each)", "50", "50", "100"],
     ["Detected (alert raised)", "36", "9", "45"],
     ["Median first-alert hop index", "4", "5", "4"],
     ["Unattended action taken", "36", "2", "38"],
     ["Attack hops prevented", "27.8%", "1.5%", "14.6%"],
     ["Benign alerts per 10k", "<span=3>30.8 (316 of 102,476 events)"],
     ["Unattended actions per 10k", "<span=3>5.5 (56 events, 56 users)"]],
    aligns=["left", "center", "center", "center"])
P("{tab:prevent} summarises the outcome. The stack alerts on 45 of the 100 campaigns, with a median of four "
  "hops, and acts without approval on 38, preventing 14.6% of all attack hops. The benefit lies in chains: all "
  "36 detected chains are acted on, 33 at the fifth hop and three at the fourth, preventing 27.8% of chain "
  "hops, whereas only 2 of 50 fan-outs are acted on (1.5%). Because the rule needs four novel hops of "
  "evidence, at most half of an eight-hop chain can be prevented. {fig:prev}(a) shows the boundary an "
  "attacker must cross to evade: every chain is caught when its hops are at most 10 min apart and almost none "
  "when they are 15 min or more apart, because four hops then no longer fit the 1,800-s window. The price is "
  "30.8 benign alerts and 5.5 unattended actions per 10,000 benign events, each action a session reset that "
  "the user resolves by signing in again.")
FIG("prev", "fig4_prevention.png", 3.35,
    "Prevention instrument (100 campaigns). (a) Detection rate by the interval between hops; (b) share of attack "
    "hops prevented when a session reset stops the attacker only with the given probability.")
P("Session resets do not always stop an attacker, for instance when a stolen password stays valid. "
  "{fig:prev}(b) varies the probability that a reset stops the campaign. Without verification and "
  "escalation, prevention falls linearly to zero; with them, the loop notices continued movement within "
  "30 min and locks the account, retaining 9.3% prevention when resets never work (36 campaigns escalated). "
  "The instrument is only meaningful for a model that has not seen its generator: when 60 campaigns from the "
  "same generator were added to training, the retrained model detected 94 of the 100 instrument campaigns at "
  "the first or second hop, but its PR-AUC on the real C1 test partition fell from 0.805 to 0.403 "
  "[0.318, 0.491]. The instrument would then measure the training set, so the shipped model excludes such "
  "data.")
FIG("full", "fig5_fullrate.png", 3.35,
    "Benign cost of two chain rules, hour by hour, on an unsampled LANL day processed from a cold start. "
    "Open triangles mark hours without a single flag.")
H2("Cost of the Chain Rule at Full Rate")
P("Rule costs measured on a stride-sampled corpus are misleading, because keeping one benign event in several "
  "hundred removes nearly every benign multi-hop pattern. On C1 a four-hop, 300-s chain rule appeared to cost "
  "4.6 FP/10k; on an unsampled day of LANL (7,263,653 events after local logons are removed) the same rule "
  "flagged 715 to 855 benign events per 10,000. {fig:full} compares, hour by hour on that day and from a cold "
  "start, a rule that flags any four-hop chain within 1,800 s with the shipped rule. Requiring successful hops "
  "into never-reached hosts lowers the day's cost from 114.4 to 4.3 per 10,000, a 26-fold reduction, and the "
  "cost keeps falling as history accumulates, to about 0.1 per 10,000 in the last six hours. No chain "
  "campaign is lost, since a walk into new hosts satisfies both tests at the same hop.")
H2("External Test on OTRF")
P("The frozen product (LANL-trained checkpoint, LANL-calibrated thresholds, no retraining) was run on the 21 "
  "OTRF recordings through its own ingestion path: format detection recognised every recording as Windows "
  "Security JSON, and each event was scored by a served instance started from the shipped warm state. "
  "{tab:otrf} and {fig:otrf} give the result. At the shipped threshold only 2 of 21 attacks are detected, a "
  "PurpleSharp playbook (risk 0.961) and an Empire WMIC backdoor (0.734), which are also the busiest "
  "recordings and the source of the 13 benign alerts. Without a threshold the signal is real but weak: the "
  "pooled ROC-AUC is 0.661 [0.564, 0.754] under a bootstrap over recordings, the mean within-recording ROC-AUC "
  "is 0.787, and the attacker's event is ranked first in 10 of 18 recordings against 6.3 expected by chance.")
TAB("otrf", "External Test on 21 OTRF Recordings", [2909, 2000],
    [["Measure", "Value"],
     ["Attack / benign events", "77 / 118"],
     ["Recordings detected at *τ*_{*a*} = 0.329", "2 of 21"],
     ["Benign events alerted at *τ*_{*a*}", "13 of 118"],
     ["Attack ranked first (expected by chance)", "10 of 18 (6.3)"],
     ["Pooled ROC-AUC [95% CI]", "0.661 [0.564, 0.754]"],
     ["Mean within-recording ROC-AUC", "0.787 (18 recordings)"]],
    aligns=["left", "center"])
FIG("otrf", "fig6_otrf.png", 3.35,
    "Fused risk of every event in the 21 OTRF recordings, scored by the frozen LANL model. Only two attacks "
    "exceed the alert threshold, although attacks usually outrank the benign events of their own recording.")
P("Three known effects combine here. Every OTRF identity is outside the frozen dictionary, so the model reasons "
  "from shared out-of-vocabulary memory; every recording holds a single hop, so the chain rule cannot fire by "
  "construction; and a threshold is a property of a score distribution, which moves between networks. Reading "
  "a new estate's logs therefore works, but alerting correctly on them requires warm-up on that estate's own "
  "history and a re-derived gate, which the deployment guidance now states. The test also exposed two identity "
  "defects, now fixed: IPv4-mapped IPv6 addresses and loopback spellings now resolve to one host.")
H2("Threats to Validity")
P("The LANL labels describe one red-team exercise with four attacker hosts, one of which produced 94% of the "
  "events, so no absolute detection figure here should be read as performance against a new attacker. Both "
  "LANL corpora are stride-sampled, which inflates prevalence and, because features are computed on the "
  "sampled stream, shortens benign histories relative to attack histories; Section V-D shows how large such "
  "effects are for rules, and repeating the model comparison with full-rate features is our first item of "
  "future work. Prevention is measured on simulated campaigns whose generator is independent of training but "
  "is still a model of attacker behaviour, and the OTRF recordings are short and come from one lab. All "
  "measurements come from one implementation; offline evaluation and the live service share code paths and "
  "agree to five decimal places, but independent replication would strengthen every claim.")

# VI. CONCLUSION ------------------------------------------------------------
H1("CONCLUSION AND FUTURE WORK")
P("GraphSentinel shows that a learned lateral-movement detector can be embedded in a complete and bounded "
  "response system. Logs of several formats are read into one stream, every logon is scored by a temporal "
  "graph network from past-only features, evidence is fused auditably through a noisy-OR gate and a novel-hop "
  "chain rule, unattended action is gated by a lower bound on precision, and a contain–verify–"
  "escalate–revert loop with budgets and a reversible two-hour lock acts on what is detected, while a "
  "grounded language-model agent writes reports that cannot cite evidence it was not given. Measured end to "
  "end, the loop prevents 14.6% of attack hops in simulated campaigns (27.8% for credential chains) at 5.5 "
  "unattended actions per 10,000 benign logons, and escalation preserves prevention when containment fails.")
P("The evaluation is a result in its own right: the headline LANL score depends on one attacker host, a "
  "logistic regression outperforms the TGN on a corrected corpus, sampled corpora misstate rule costs by two "
  "orders of magnitude, and a frozen model transfers its ranking but not its threshold to an unseen network. "
  "Future work will (i) recompute features at full rate and repeat the model comparison with gradient-boosted "
  "trees and several seeds, (ii) evaluate on further labelled corpora with held-out attacker hosts, (iii) adapt "
  "thresholds to each estate from a short warm-up period, and (iv) measure the accuracy of the report agent "
  "with practising analysts.")

ACK = ""


# ------------------------------------------------------------------ renderer
def build(out: Path) -> dict:
    refs = Refs()
    media = Media()
    # number figures, tables, equations in order of appearance
    nfig = ntab = neq = 0
    for item in C:
        if item[0] in ("fig", "box", "float"):
            nfig += 1
            refs.labels[f"fig:{item[1]}"] = f"Fig. {nfig}"
        elif item[0] == "tab":
            ntab += 1
            refs.labels[f"tab:{item[1]}"] = f"Table {ROMAN[ntab - 1]}"
        elif item[0] == "eq":
            neq += 1
            refs.labels[f"eq:{item[1]}"] = f"({neq})"

    blocks: list = []

    def para(pp, body):
        blocks.append(Para(pp, body))
        return blocks[-1]

    def close_section(cols, continuous):
        """Attach a section break to the last paragraph (adding a hairline one after a table)."""
        if not blocks or not isinstance(blocks[-1], Para) or blocks[-1].sect:
            para(ppr(jc="left", line=20), run(" ", sz=1))
        blocks[-1].sect = sect_pr(cols=cols, continuous=continuous)

    # title and authors (one column)
    para(ppr(jc="center", after=200, line=None), run(TITLE, sz=24))
    rows = [AUTHORS[:3], AUTHORS[3:]]
    if len(rows[1]) == 1:
        rows[1] = [[], rows[1][0], []]  # a single author on the second row sits in the middle
    rows = [row for row in rows if any(row)]
    tbl = ['<w:tbl><w:tblPr><w:tblW w:w="10106" w:type="dxa"/><w:jc w:val="center"/><w:tblLayout w:type="fixed"/>'
           '<w:tblCellMar><w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tblCellMar>'
           '<w:tblLook w:val="0000"/></w:tblPr><w:tblGrid>'
           + '<w:gridCol w:w="3369"/><w:gridCol w:w="3368"/><w:gridCol w:w="3369"/></w:tblGrid>']
    for r, row in enumerate(rows):
        tbl.append("<w:tr>")
        for c in range(3):
            w = 3369 if c != 1 else 3368
            lines = row[c] if c < len(row) else []
            ps = []
            for n, line in enumerate(lines):
                italic = n in (2, 3, 4)
                before = 160 if (r == 1 and n == 0) else 0
                ps.append(f"<w:p><w:pPr>{ppr(jc='center', before=before)}</w:pPr>{run(line, sz=10, i=italic)}</w:p>")
            if not ps:
                ps.append(f"<w:p><w:pPr>{ppr(jc='center')}</w:pPr></w:p>")
            tbl.append(f'<w:tc><w:tcPr><w:tcW w:w="{w}" w:type="dxa"/></w:tcPr>{"".join(ps)}</w:tc>')
        tbl.append("</w:tr>")
    tbl.append("</w:tbl>")
    blocks.append(Raw("".join(tbl)))
    para(ppr(jc="left", line=240, after=0), run(" ", sz=6))
    close_section(1, False)

    # abstract and keywords (two columns from here)
    para(ppr(first=202, after=0),
         run("Abstract", b=True, i=True, sz=9) + run("—" + ABSTRACT, b=True, sz=9))
    para(ppr(first=202, before=100, after=60),
         run("Keywords", b=True, i=True, sz=9) + run("—" + KEYWORDS, b=True, i=True, sz=9))

    h1n = 0
    h2n = 0
    pending: list[str] = []
    for item in C:
        kind = item[0]
        if kind == "h1":
            h1n += 1
            h2n = 0
            para(ppr(jc="center", before=180, after=90, keep_next=True),
                 run(f"{ROMAN[h1n - 1]}. {item[1]}", sz=10, smallcaps=True))
        elif kind == "h2":
            h2n += 1
            para(ppr(jc="left", before=90, after=50, keep_next=True),
                 run(f"{chr(64 + h2n)}. {item[1]}", i=True, sz=10))
        elif kind == "p":
            para(ppr(first=288), pending.pop() + rich(item[1], refs) if pending else rich(item[1], refs))
        elif kind == "float":
            _, label, file, width, caption = item
            from PIL import Image as _Image
            with _Image.open(FIGS / file) as _im:
                aspect = _im.height / _im.width
            pic_id = len(media.items) + 1
            inner = (f"<w:p><w:pPr>{ppr(jc='center', after=40)}</w:pPr>{picture(FIGS / file, width, media, pic_id)}</w:p>"
                     f"<w:p><w:pPr>{ppr(jc='center')}</w:pPr>"
                     + run(refs.labels[f"fig:{label}"] + ". ", sz=8) + rich(caption, refs, sz=8) + "</w:p>")
            pending.append(floating_box(inner, 7.0, width * aspect + 0.34, 900 + pic_id))
        elif kind == "list":
            for n, text in enumerate(item[1], 1):
                para(ppr(left=504, hanging=288, tabs=[("left", 504)]), run(f"{n})\t") + rich(text, refs))
        elif kind == "eq":
            label = item[1]
            omml = EQUATIONS[label]
            number = refs.labels[f"eq:{label}"].strip("()")
            # Word's own numbered display equation: "equation#(n)" inside an equation array
            body = ('<m:oMathPara><m:oMath><m:eqArr><m:eqArrPr><m:maxDist m:val="1"/></m:eqArrPr><m:e>'
                    + omml + mr("#", "p") + md(mr(number, "p")) + "</m:e></m:eqArr></m:oMath></m:oMathPara>")
            para(ppr(jc="center", before=40, after=40), body)
        elif kind == "fig":
            _, label, file, width, caption, full = item
            if full:
                close_section(2, True)
            pic_id = len(media.items) + 1
            para(ppr(jc="center", before=120, after=40, keep_next=True),
                 picture(FIGS / file, width, media, pic_id))
            para(ppr(jc="both" if not full else "center", after=120, keep_lines=True),
                 run(refs.labels[f"fig:{label}"] + ". ", sz=8) + rich(caption, refs, sz=8))
            if full:
                close_section(1, True)
        elif kind == "box":
            _, label, lines, caption = item
            border = "".join(f'<w:{side} w:val="single" w:sz="4" w:space="0" w:color="000000"/>'
                             for side in ("top", "left", "bottom", "right"))
            cell = "".join(
                f"<w:p><w:pPr>{ppr(jc='left' if n < 2 else 'both', after=30, keep_next=True)}</w:pPr>"
                f"{rich(line, refs, sz=7.5)}</w:p>" for n, line in enumerate(lines))
            blocks.append(Para(ppr(jc="left", before=60, line=120, keep_next=True), run(" ", sz=4)))
            blocks.append(Raw(
                f'<w:tbl><w:tblPr><w:tblW w:w="{COL - 40}" w:type="dxa"/><w:jc w:val="center"/>'
                f"<w:tblBorders>{border}</w:tblBorders><w:tblLayout w:type=\"fixed\"/>"
                '<w:tblCellMar><w:top w:w="50" w:type="dxa"/><w:left w:w="90" w:type="dxa"/>'
                '<w:bottom w:w="30" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar>'
                f'<w:tblLook w:val="0000"/></w:tblPr><w:tblGrid><w:gridCol w:w="{COL - 40}"/></w:tblGrid>'
                f'<w:tr><w:trPr><w:cantSplit/></w:trPr><w:tc><w:tcPr><w:tcW w:w="{COL - 40}" w:type="dxa"/>'
                f'<w:shd w:val="clear" w:color="auto" w:fill="F7F7F7"/></w:tcPr>{cell}</w:tc></w:tr></w:tbl>'))
            para(ppr(jc="both", before=60, after=120, keep_lines=True),
                 run(refs.labels[f"fig:{label}"] + ". ", sz=8) + rich(caption, refs, sz=8))
        elif kind == "tab":
            _, label, caption, widths, rows_, full, aligns = item
            if full:
                close_section(2, True)
            num = refs.labels[f"tab:{label}"].split()[1]
            para(ppr(jc="center", before=120, after=60, keep_next=True),
                 run(f"TABLE {num}. ", sz=8) + run(caption, sz=8, smallcaps=True))
            blocks.append(Raw(table(widths, rows_, refs, aligns=aligns, sz=8)))
            para(ppr(jc="left", line=120), run(" ", sz=4))
            if full:
                close_section(1, True)

    # acknowledgment and references
    if ACK:
        para(ppr(jc="center", before=180, after=90, keep_next=True), run("ACKNOWLEDGMENT", sz=10, smallcaps=True))
        para(ppr(first=288), rich(ACK, refs))
    para(ppr(jc="center", before=180, after=90, keep_next=True), run("REFERENCES", sz=10, smallcaps=True))
    missing = [k for k in REFERENCES if k not in refs.order]
    if missing:
        raise SystemExit(f"references never cited: {missing}")
    for n, key in enumerate(refs.order, 1):
        # let long URLs break after a slash instead of stretching the justified line
        text = re.sub(r"https?://\S+", lambda m: m.group(0).replace("/", "/​"), REFERENCES[key])
        para(ppr(left=360, hanging=360, tabs=[("left", 360)], after=0),
             run(f"[{n}]\t", sz=8) + rich(text, refs, sz=8))
    # a continuous break after the last reference balances the columns of the final page
    close_section(2, True)
    # the final (one-column) section holds only a 1-pt paragraph, so it never spills onto a new page
    para(ppr(jc="left", line=20, extra='<w:rPr><w:sz w:val="2"/><w:szCs w:val="2"/></w:rPr>'), "")
    body = "".join(b.xml() for b in blocks) + sect_pr(cols=1, continuous=True)
    write_docx(out, body, media, title=TITLE, subject="IEEE conference paper")
    return {"figures": nfig, "tables": ntab, "equations": neq, "references": len(refs.order)}


if __name__ == "__main__":
    info = build(OUT_DOCX)
    print(OUT_DOCX, info)
