"""Front matter and appendix content. Text in {{...}} is highlighted in yellow: confirm or fill it in.

Department pages follow the official R2023 curriculum of the Department of Artificial Intelligence and
Machine Learning, Rajalakshmi Engineering College (pages.rajalakshmi.org, R2023-AIML-Curriculum_and_Syllabus.pdf).
"""

TITLE = ("GRAPHSENTINEL: A TRUSTWORTHY TEMPORAL GRAPH NEURAL NETWORK MODEL FOR AUTONOMOUS LATERAL MOVEMENT "
         "DETECTION AND PREVENTION")
TITLE_SENTENCE = ("GraphSentinel: A Trustworthy Temporal Graph Neural Network Model for Autonomous Lateral Movement "
                  "Detection and Prevention")

# Course: R2023 AIML curriculum -> AI23721 Project Phase-I (semester VII), AI23821 Project Phase-II (semester VIII).
COURSE_LINE = "{{AI23721 PROJECT PHASE-I}} REPORT"
COURSE_HEADER = "{{AI23721 – Project Phase I}}"
COURSE_SUBJECT = "AI23721 Project Phase-I Report"

DEGREE = "ARTIFICIAL INTELLIGENCE AND MACHINE LEARNING"
DEPARTMENT = "DEPARTMENT OF ARTIFICIAL INTELLIGENCE AND MACHINE LEARNING"
DEPT = "Department of Artificial Intelligence and Machine Learning"

STUDENTS = ["THILLAI NATHAN B ({{2116231501173}})", "VIJAY ANAND J ({{2116231501181}})",
            "NITHISH BALAJI ({{2116231501115}})"]
STUDENT_SIGN = ["Thillai Nathan B", "Vijay Anand J", "Nithish Balaji"]
BATCH = "231501173 - Thillai Nathan B, 231501181 - Vijay Anand J, 231501115 - Nithish Balaji"
MONTH_YEAR = "{{[MONTH YEAR]}}"

HOD = ["Dr. M. AYYADURAI, M.E., Ph.D.,", "Associate Professor and Head", DEPT, "Rajalakshmi Engineering College",
       "Chennai- 602 105"]
SUPERVISOR = ["ANITHA R, {{[Qualification]}},", "Supervisor and Professor", DEPT, "Rajalakshmi Engineering College",
              "Chennai- 602 105"]
SUPERVISOR_LINE = "Anitha R, Professor"

BONAFIDE = ("Certified that this project report titled “" + TITLE_SENTENCE + "” is the bonafide work of "
            + STUDENTS[0] + ", " + STUDENTS[1] + " and " + STUDENTS[2] + " who carried out the work under my "
            "supervision. Certified further that to the best of my knowledge the work reported herein does not form "
            "part of any other thesis or dissertation on the basis of which a degree or award was conferred on an "
            "earlier occasion on this or any other candidate.")

ACK = [
    "First, we thank the Almighty for the successful completion of this project. We express our sincere thanks to "
    "our Chairman **Mr. S. Meganathan, B.E., F.I.E.,** for the sincere endeavour in educating us in this premier "
    "institution. We express our deep gratitude to our beloved Chairperson **Dr. (Mrs.) Thangam Meganathan, M.A., "
    "M.Phil., Ph.D.,** for the enthusiastic motivation that inspired us throughout this project, and to our "
    "Vice-Chairman **Mr. Abhay Shankar Meganathan, B.E., M.S.,** for providing us with the requisite "
    "infrastructure.",
    "We also express our sincere gratitude to our Principal **Dr. S. N. Murugesan, M.E., Ph.D.,** for the kind "
    "support and the facilities provided to complete our work on time. We extend our heartfelt gratitude to **Dr. M. "
    "Ayyadurai, M.E., Ph.D.,** Associate Professor and Head of the Department of Artificial Intelligence and Machine "
    "Learning, for the guidance and encouragement throughout the work, and to our project coordinator **Sekar K, "
    "{{[Qualification]}},** Assistant Professor, Department of Artificial Intelligence and Machine Learning, for the "
    "constant support and timely reviews.",
    "We convey our deepest gratitude to our supervisor **Anitha R, {{[Qualification]}},** Professor, Department of "
    "Artificial Intelligence and Machine Learning, for the valuable guidance, critical feedback and patience that "
    "shaped this work. We also thank our parents, our friends, and all the faculty and supporting staff of the "
    "department for their direct and indirect support throughout the project.",
]

ABSTRACT = [
    "Attackers who steal valid credentials can move from one computer to the next through ordinary remote "
    "logons, a stage of an intrusion known as lateral movement. Because every hop uses a genuine credential, "
    "signature-based tools rarely notice it, and existing detectors either judge single events against static "
    "rules or rank suspicious logons offline without stopping the attacker. This project presents GraphSentinel, "
    "a trustworthy temporal graph neural network model that detects and prevents lateral movement directly from "
    "authentication logs. Logs from LANL, Windows Security, SSH, Zeek, Entra ID, Okta and generic CSV or JSON "
    "sources are read into one stream with automatic format detection. A temporal graph network keeps a memory "
    "for every account and host and scores each logon from 27 strictly causal features before updating that "
    "memory. The score is fused with explicit evidence through a noisy-OR gate and a same-account chain rule, "
    "and the system may act on its own only above an execution gate derived from a Wilson lower bound on "
    "precision. Its response is a bounded loop that forces re-authentication, verifies whether the account keeps "
    "moving, escalates to a reversible two-hour account lock and reverts, within hourly and per-account budgets. "
    "A locally hosted language model writes triage and incident reports in which every statement must cite "
    "recorded evidence. On the LANL corpus the model reaches a test PR-AUC of 0.821, but this figure rests on "
    "one attacker host and falls to 0.002 without it, and on a corrected corpus a logistic regression over the "
    "same features scores 0.956, above every TGN-based detector. In a replay of 100 simulated campaigns the "
    "system acted on its own in 38 and prevented 14.6% of attacker hops (27.8% for single-credential chains) at "
    "5.5 automatic actions per 10,000 benign logons. On 21 public Windows attack recordings the frozen model "
    "ranked attacks above chance (ROC-AUC 0.66) but alerted on only two, showing that thresholds must be "
    "re-derived for each network.",
    "The project contributes to SDG 8 (Decent Work and Economic Growth), SDG 9 (Industry, Innovation and "
    "Infrastructure) and SDG 16 (Peace, Justice and Strong Institutions) by protecting digital infrastructure "
    "against cybercrime with accountable, auditable automation.",
]

ABBREVIATIONS = [
    ("AI", "Artificial Intelligence"),
    ("AP", "Average Precision"),
    ("API", "Application Programming Interface"),
    ("ATT&CK", "Adversarial Tactics, Techniques and Common Knowledge"),
    ("AUC", "Area Under the Curve"),
    ("BCE", "Binary Cross-Entropy"),
    ("CI", "Confidence Interval"),
    ("CSV", "Comma-Separated Values"),
    ("DFD", "Data Flow Diagram"),
    ("EDR", "Endpoint Detection and Response"),
    ("FN", "False Negative"),
    ("FP", "False Positive"),
    ("GNN", "Graph Neural Network"),
    ("GPU", "Graphics Processing Unit"),
    ("GRU", "Gated Recurrent Unit"),
    ("JSON", "JavaScript Object Notation"),
    ("LANL", "Los Alamos National Laboratory"),
    ("LLM", "Large Language Model"),
    ("NIST", "National Institute of Standards and Technology"),
    ("NTLM", "NT LAN Manager"),
    ("OOV", "Out of Vocabulary"),
    ("OTRF", "Open Threat Research Forge"),
    ("PR-AUC", "Area Under the Precision-Recall Curve"),
    ("REST", "Representational State Transfer"),
    ("ROC", "Receiver Operating Characteristic"),
    ("SDG", "Sustainable Development Goal"),
    ("SIEM", "Security Information and Event Management"),
    ("SOAR", "Security Orchestration, Automation and Response"),
    ("SOC", "Security Operations Centre"),
    ("SSH", "Secure Shell"),
    ("TGN", "Temporal Graph Network"),
    ("TP", "True Positive"),
    ("UEBA", "User and Entity Behaviour Analytics"),
]

# ---- department pages: official R2023 AIML curriculum text ----
VISION = ("To promote highly Ethical and Innovative Computer Professionals through excellence in teaching, training "
          "and research.")
MISSION = [
    "M1. To produce globally competent professionals, motivated to learn the emerging technologies and to be "
    "innovative in solving real world problems.",
    "M2. To promote research activities amongst the students and the members of faculty that could benefit the "
    "society.",
    "M3. To impart moral and ethical values in their profession.",
]
PEOS = [
    ("PEO 1", "To equip students with essential background in computer science with emphasis on Artificial "
              "Intelligence, Machine Learning, basic electronics and applied mathematics."),
    ("PEO 2", "To prepare students with fundamental knowledge in programming languages, and tools and enable them to "
              "develop applications using emerging technologies."),
    ("PEO 3", "To encourage research and innovative project development in the field of Artificial Intelligence, "
              "Machine Learning, Deep Learning, Networking, Security, Web development, Data Science and also "
              "emerging technologies for social benefit."),
    ("PEO 4", "To develop professionally ethical individuals enhanced with analytical skills, communication skills "
              "and organizing ability to meet industry requirements."),
]
POS = [
    ("Engineering knowledge", "Apply the knowledge of Mathematics, Science, Engineering fundamentals, and an "
     "engineering specialization to the solution of complex engineering problems."),
    ("Problem analysis", "Identify, formulate, review research literature, and analyze complex engineering problems "
     "reaching substantiated conclusions using first principles of mathematics, natural sciences, and engineering "
     "sciences."),
    ("Design/development of solutions", "Design solutions for complex engineering problems and design system "
     "components or processes that meet the specified needs with appropriate consideration for the public health "
     "and safety, and the cultural, societal, and environmental considerations."),
    ("Conduct investigations of complex problems", "Use research-based knowledge and research methods including "
     "design of experiments, analysis and interpretation of data, and synthesis of the information to provide "
     "valid conclusions."),
    ("Modern tool usage", "Create, select, and apply appropriate techniques, resources, and modern engineering and "
     "IT tools including prediction and modeling to complex engineering activities with an understanding of the "
     "limitations."),
    ("The engineer and society", "Apply reasoning informed by the contextual knowledge to assess societal, health, "
     "safety, legal and cultural issues and the consequent responsibilities relevant to the professional "
     "engineering practice."),
    ("Environment and sustainability", "Understand the impact of the professional engineering solutions in societal "
     "and environmental contexts, and demonstrate the knowledge of, and need for sustainable development."),
    ("Ethics", "Apply ethical principles and commit to professional ethics and responsibilities and norms of the "
     "engineering practice."),
    ("Individual and team work", "Function effectively as an individual, and as a member or leader in diverse "
     "teams, and in multidisciplinary settings."),
    ("Communication", "Communicate effectively on complex engineering activities with the engineering community and "
     "with society at large, such as, being able to comprehend and write effective reports and design "
     "documentation, make effective presentations, and give and receive clear instructions."),
    ("Project management and finance", "Demonstrate knowledge and understanding of the engineering and management "
     "principles and apply these to one’s own work, as a member and leader in a team, to manage projects and in "
     "multidisciplinary environments."),
    ("Life-long learning", "Recognize the need for, and have the preparation and ability to engage in independent "
     "and life-long learning in the broadest context of technological change."),
]
PSO_INTRO = "A graduate of the Artificial Intelligence and Machine Learning Program will demonstrate:"
PSOS = [
    ("Foundation Skills", "Ability to understand, analyze and develop Intelligent systems based on Algorithms, Web "
     "design, Artificial Intelligence, Machine Learning, Deep Learning, and Data Science for efficient design of "
     "computer-based systems of varying complexity; familiarity and practical competence with a broad range of "
     "programming languages, tools and open source platforms."),
    ("Problem-Solving Skills", "Ability to apply mathematical methods, model real world problem using appropriate "
     "Artificial Intelligence and Machine Learning algorithms and solve computational problems. To understand and "
     "apply standard practices and strategies in project development, using open-ended programming environments "
     "to deliver a quality product."),
    ("Successful Progression", "Ability to apply knowledge in various domains to identify gaps and to provide "
     "solutions in the form of new ideas, inculcate passion towards higher studies, creating innovative career "
     "paths to be an entrepreneur and evolve as an ethically responsible Artificial Intelligence and Machine "
     "Learning professional with committed to society."),
]
# Course objective and outcomes of the project course are not in the published curriculum: take them from the
# department's report front sheets.
COURSE_OBJECTIVE = "{{[Course objective of AI23721 Project Phase-I, as given in the department front sheets]}}"
COURSE_OUTCOMES = [f"{{{{[CO{k} of AI23721 Project Phase-I, as given in the department front sheets]}}}}"
                   for k in range(1, 6)]

# ---- appendix V: CO-PO-PSO mapping (proposed; the supervisor verifies and signs). 12 POs + 3 PSOs ----
COPO = [
    ("CO 1", ["3", "3", "2", "3", "2", "-", "-", "-", "1", "1", "1", "2", "3", "3", "2"]),
    ("CO 2", ["3", "3", "3", "3", "3", "2", "1", "1", "2", "2", "2", "2", "3", "3", "2"]),
    ("CO 3", ["2", "2", "3", "2", "2", "3", "2", "2", "1", "2", "1", "2", "2", "2", "3"]),
    ("CO 4", ["1", "1", "2", "2", "1", "3", "2", "3", "2", "2", "1", "2", "1", "2", "3"]),
    ("CO 5", ["1", "1", "2", "2", "2", "1", "1", "2", "3", "3", "3", "3", "2", "2", "3"]),
]

# ---- appendix VI: CO-SDG relevance ----
COSDG = [
    ("SDG 8 – Decent Work and Economic Growth", "CO2, CO5",
     "Reduces business disruption and financial loss from intrusions and ransomware by containing credential-based "
     "lateral movement early, and lowers analyst workload through grounded incident reports."),
    ("SDG 9 – Industry, Innovation and Infrastructure", "CO1, CO2",
     "Protects enterprise IT infrastructure with an innovative temporal graph neural network model and a bounded, "
     "reversible automatic response that runs on modest hardware."),
    ("SDG 16 – Peace, Justice and Strong Institutions", "CO3, CO4",
     "Helps institutions resist cybercrime while keeping automation accountable: every action is recorded, "
     "reversible and explained with verifiable evidence."),
]
