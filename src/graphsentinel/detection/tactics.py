"""MITRE ATT&CK tactic classification for authentication telemetry.

Why this is signature-based rather than a trained multi-class model
-------------------------------------------------------------------
The LANL corpus carries exactly one label: ``label_redteam``, a binary flag.
There is no attack-type column anywhere in it, so a supervised multi-class
classifier has nothing to learn from -- any per-class precision reported from
such a model would be fabricated. What *is* available is the shape of the
feature vector, and the tactics below are separable by which features fire.

Each signature is therefore a deterministic, auditable rule over features the
pipeline already computes, mapped to an ATT&CK technique. This has three
properties a learned classifier would not have on day one:

* it works at a new deployment immediately, before any site-specific training;
* every classification carries the evidence that produced it, so an analyst
  can disagree with a specific clause rather than with a number;
* it is falsifiable -- a wrong classification points at a named rule.

The intended trajectory is that analyst dispositions accumulate real
multi-class labels over months, at which point a learned classifier becomes
justified and can be validated against *these* rules as the baseline.

Validation status, stated honestly
----------------------------------
The 649 red-team events in LANL are lateral movement. ``T1021`` is therefore
the only signature with real ground truth. The others are validated by
synthetic injection only, and :func:`describe_validation` reports that
distinction so it cannot be quietly lost downstream.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from threading import RLock

from graphsentinel.detection.signals import ExplicitSignals
from graphsentinel.features.causal import FeatureRecord

# ---------------------------------------------------------------------------
# Category encodings. These are indices into the frozen entity dictionary, so
# they are part of the serving contract, not magic numbers -- see
# artifacts/id_maps_*/{auth_types,logon_types,orientations}.json.
# ---------------------------------------------------------------------------
AUTH_UNKNOWN = 0
AUTH_NTLM = 1
AUTH_NEGOTIATE = 2
AUTH_KERBEROS = 3

LOGON_UNKNOWN = 0
LOGON_NETWORK = 1
LOGON_SERVICE = 2
LOGON_BATCH = 3
LOGON_INTERACTIVE = 4
LOGON_NETWORK_CLEARTEXT = 5
LOGON_CACHED_INTERACTIVE = 6
LOGON_UNLOCK = 7
LOGON_NEW_CREDENTIALS = 8
LOGON_REMOTE_INTERACTIVE = 9

ORIENT_UNKNOWN = 0
ORIENT_LOGON = 1
ORIENT_TGS = 2
ORIENT_LOGOFF = 3
ORIENT_TGT = 4

#: Logon types that mean a human is sitting at a console (or driving one
#: remotely). A machine account performing one of these is anomalous by
#: construction: computers do not log in interactively.
HUMAN_LOGON_TYPES = frozenset(
    {LOGON_INTERACTIVE, LOGON_REMOTE_INTERACTIVE, LOGON_CACHED_INTERACTIVE, LOGON_UNLOCK}
)


@dataclass(frozen=True, slots=True)
class TacticSignature:
    """Static description of one ATT&CK technique this engine can recognise."""

    technique_id: str
    name: str
    tactic: str
    description: str
    ground_truth: bool = False


SIGNATURES: dict[str, TacticSignature] = {
    "T1021": TacticSignature(
        technique_id="T1021",
        name="Lateral Movement",
        tactic="Lateral Movement",
        description=(
            "A source host reaching outward to more destinations than its own "
            "history explains -- a foothold being used to spread. Scored on "
            "fan-out rather than on pivot; see _score_lateral_movement for the "
            "measurements behind that choice."
        ),
        ground_truth=True,
    ),
    "T1110": TacticSignature(
        technique_id="T1110",
        name="Brute Force / Password Spray",
        tactic="Credential Access",
        description=(
            "Repeated authentication failures, optionally spread thinly across many "
            "destinations to stay under per-account lockout thresholds."
        ),
    ),
    "T1087": TacticSignature(
        technique_id="T1087",
        name="Account / Remote System Discovery",
        tactic="Discovery",
        description=(
            "An account reaching an unusual number of previously untouched hosts in a "
            "short window -- mapping the estate rather than working in it."
        ),
    ),
    "T1078": TacticSignature(
        technique_id="T1078",
        name="Valid Account Abuse",
        tactic="Initial Access / Defense Evasion",
        description=(
            "A new user-host relationship that succeeds on the first attempt, with no "
            "preceding failures: the credential was known, not guessed."
        ),
    ),
    "T1550.003": TacticSignature(
        technique_id="T1550.003",
        name="Kerberos Ticket Abuse",
        tactic="Lateral Movement / Defense Evasion",
        description=(
            "Service tickets requested without the preceding ticket-granting ticket "
            "that should have produced them -- the shape of a forged or replayed ticket."
        ),
    ),
    "T1078.002": TacticSignature(
        technique_id="T1078.002",
        name="Machine / Service Account Misuse",
        tactic="Persistence / Privilege Escalation",
        description=(
            "A machine or service account behaving like a human operator, or reaching "
            "hosts outside its established service footprint."
        ),
    ),
    "T1550.002": TacticSignature(
        technique_id="T1550.002",
        name="NTLM Downgrade / Pass-the-Hash",
        tactic="Lateral Movement",
        description=(
            "NTLM authentication in an estate that predominantly speaks Kerberos, "
            "especially to a host this account has never reached."
        ),
    ),
}


@dataclass(frozen=True, slots=True)
class TacticScore:
    """One signature's verdict on one event, with the reasons that produced it."""

    technique_id: str
    name: str
    tactic: str
    score: float
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "score": round(self.score, 4),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class TacticClassification:
    """The full per-event verdict: the winner, the runners-up, and a confidence."""

    primary: TacticScore | None
    scores: tuple[TacticScore, ...]
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return {
            "primary": self.primary.to_dict() if self.primary else None,
            "confidence": self.confidence,
            "scores": [score.to_dict() for score in self.scores],
        }


@dataclass(frozen=True, slots=True)
class TacticContext:
    """Everything a signature may read. Assembled once per event.

    Keeping this explicit -- rather than letting signatures reach into engine
    state -- is what makes each rule independently testable.
    """

    record: FeatureRecord
    signals: ExplicitSignals
    user_name: str = ""
    #: Seconds since this user last obtained a TGT, or ``None`` if never seen.
    #: Required by the Kerberos signature and nothing else.
    seconds_since_tgt: float | None = None
    #: Share of this estate's recent authentications that used Kerberos. The
    #: NTLM signature is meaningless without it: NTLM is unremarkable in an
    #: estate that speaks NTLM.
    kerberos_share: float = 0.0
    #: Share of ticket-requesting accounts for which a TGT has actually been
    #: observed. Measures how complete the Kerberos telemetry is, which the
    #: ticket-abuse signature must know before it can treat a missing TGT as
    #: meaningful rather than as a gap in logging.
    tgt_coverage: float = 0.0
    #: Resolved category NAMES, not dictionary indices.
    #:
    #: Signatures previously compared ``record.logon_type_id`` against module
    #: constants such as ``LOGON_INTERACTIVE = 4``. Those indices belong to one
    #: entity dictionary, not to Windows: the frozen LANL dictionary puts
    #: "Interactive" at 4, while a dictionary built from a customer's own logs
    #: assigns ids in order of first appearance and lands on 2. Every
    #: category-keyed rule then silently never fires -- and every unit test
    #: written against the LANL constants still passes.
    #:
    #: Names are stable across dictionaries, so rules key on these. An empty
    #: name means "unknown", and a rule depending on it stays silent rather
    #: than guessing.
    logon_type_name: str = ""
    auth_type_name: str = ""
    orientation_name: str = ""
    #: Distinct hosts this source has originated to in the last hour, taken
    #: from the rolling feature rather than recomputed.
    source_fanout_1h: int = 0
    #: The deterministic chain rule fired on this event: the same account made
    #: the configured number of onward hops inside the window and is moving
    #: again. Set only when the chain-rule policy lets the rule assert the
    #: technique (``detection/policy.py``); the rule's evidence then outranks
    #: every fitted score, because a same-account multi-hop chain is lateral
    #: movement by definition.
    chain_detected: bool = False


def _ramp(value: float, low: float, high: float) -> float:
    """Linear 0->1 ramp between two thresholds, clamped at both ends.

    Signatures use ramps rather than hard cutoffs so a score degrades
    gracefully near a boundary instead of flipping, which keeps the ordering
    of near-miss events meaningful.
    """
    if high <= low:
        return 1.0 if value >= high else 0.0
    return max(0.0, min(1.0, (value - low) / (high - low)))


def _matches(name: str, *candidates: str) -> bool:
    """Case-insensitive category match on a resolved name.

    Returns False for an empty name, so an unresolved category can never
    satisfy a rule by accident.
    """
    if not name:
        return False
    lowered = name.strip().lower()
    return any(lowered == candidate.lower() for candidate in candidates)


#: Logon types meaning a human is at a console (or driving one remotely),
#: by NAME so the check survives any entity dictionary.
HUMAN_LOGON_NAMES = ("Interactive", "RemoteInteractive", "CachedInteractive", "Unlock")
REMOTE_LOGON_NAMES = ("Network", "RemoteInteractive")


def _is_machine_account(user_name: str) -> bool:
    """Windows machine accounts end in ``$`` (e.g. ``C1234$@DOM1``)."""
    local = user_name.split("@", 1)[0]
    return local.endswith("$")


# ---------------------------------------------------------------------------
# Signatures. Each returns (score, evidence). A score of 0 means "this
# technique is not indicated", never "unknown".
# ---------------------------------------------------------------------------


def _score_lateral_movement(ctx: TacticContext) -> tuple[float, list[str]]:
    """Lateral movement, scored on source-host fan-out rather than on pivot.

    The first version of this signature keyed on ``signals.pivot`` -- "the
    source host was itself recently reached" -- which is the textbook
    description of a pivot and turned out to be the wrong discriminator for
    this corpus. Measured over all 543,615 events and 649 labelled attacks:

        pivot (1800s window)          recall   0.0%   benign 47.05%
        src_host_unique_dst_1h >= 5   recall  76.9%   benign  2.37%   32x lift
        src_host_unique_dst_1h >= 10  recall  55.6%   benign  0.15%  367x lift

    Pivot fires on roughly half of all benign traffic and on *none* of the
    attacks. The reason is visible in the attack topology: the 649 red-team
    events originate from only 4 distinct source hosts, and 644 of them have a
    source host that was never previously a destination anywhere in the corpus
    (the remaining 5 were last reached over 115,000 seconds earlier). The
    attacker's beachhead was established outside the observable window, so
    there is no pivot to see. What is visible is fan-out: 4 sources reaching
    292 distinct destinations.

    Fan-out separates cleanly here -- benign traffic sits at a median of 1
    destination per source-hour with a 99th percentile of 6, while attacks sit
    at a median of 11 and reach 46. So fan-out carries the signature and pivot
    is demoted to a supporting signal: it remains genuinely diagnostic for
    multi-hop chains (which this corpus does not contain in its observable
    window) but it can no longer carry a classification on its own.
    """
    record, signals = ctx.record, ctx.signals
    evidence: list[str] = []

    if ctx.chain_detected:
        # Not a fitted score: the rule saw this account reach a host and move
        # on from it, repeatedly, inside the window. That is the definition.
        evidence.append(
            "same account continued a multi-hop chain through the estate "
            "(deterministic chain rule)"
        )
        if record.is_new_pair:
            evidence.append("first time this account has reached this host")
        return 1.0, evidence

    # Ramp chosen from the measured distributions: begins above the benign
    # 99th percentile (6) and saturates near the attack median (11).
    fanout = _ramp(float(record.src_host_unique_dst_1h), 4, 12)

    # Fan-out is necessary, not merely contributing. Without this gate the
    # modifiers below (new pair + rare destination = 0.35) clear
    # MINIMUM_REPORTED_SCORE on their own, and measured over the corpus that
    # labelled 26.7% of benign traffic as lateral movement on evidence that
    # contains no lateral indicator at all. A new account-host pair is
    # commonplace; it only becomes lateral movement when the source is
    # reaching outward at a rate its own history does not explain.
    if fanout <= 0.0:
        return 0.0, []

    score = 0.55 * fanout
    if fanout > 0:
        evidence.append(
            f"source host reached {record.src_host_unique_dst_1h} distinct "
            "destinations in the last hour"
        )

    if record.is_new_pair:
        score += 0.20
        evidence.append("first time this account has reached this host")

    # A rarely-contacted destination is a better lateral target than a domain
    # controller everyone touches; the latter is ordinary traffic.
    if record.dst_historical_degree <= 3:
        score += 0.15
        evidence.append(
            f"destination is rarely contacted (historical degree "
            f"{record.dst_historical_degree})"
        )

    # Supporting only. Weighted so that pivot alone cannot reach
    # MINIMUM_REPORTED_SCORE, which is what stops half the estate being
    # labelled lateral movement.
    if signals.pivot >= 1.0:
        score += 0.10
        evidence.append("source host was itself reached recently (pivot)")

    if score > 0 and _matches(ctx.logon_type_name, *REMOTE_LOGON_NAMES):
        score += 0.05
        evidence.append("remote-capable logon type")

    return min(1.0, score), evidence


def _score_brute_force(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []
    score = 0.0

    failure_rate = _ramp(record.user_failure_rate_15m, 0.2, 3.0)
    if failure_rate > 0:
        score += 0.45 * failure_rate
        evidence.append(
            f"failure rate {record.user_failure_rate_15m:.2f}/min over 15 minutes"
        )

    # The landing. A success immediately preceded by failures is the moment a
    # guessing campaign succeeded, and it is the single most actionable
    # instant in the whole technique.
    if record.failures_before_success_15m > 0:
        score += 0.40 * _ramp(float(record.failures_before_success_15m), 1, 8)
        evidence.append(
            f"{record.failures_before_success_15m} failures immediately preceded "
            "this success"
        )

    # Spray: failures spread thinly across many destinations to stay under
    # per-account lockout thresholds. Distinguished from vertical brute force
    # by breadth rather than depth.
    if record.user_failure_rate_15m > 0 and record.user_unique_dst_5m >= 3:
        score += 0.20 * _ramp(float(record.user_unique_dst_5m), 3, 15)
        evidence.append(
            f"failures spread across {record.user_unique_dst_5m} destinations "
            "in 5 minutes (spray pattern)"
        )

    if _matches(ctx.logon_type_name, "NetworkCleartext"):
        score += 0.10
        evidence.append("cleartext network logon")

    return min(1.0, score), evidence


def _score_discovery(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []
    score = 0.0

    # Absolute burst of distinct destinations in a short window.
    burst = _ramp(float(record.user_unique_dst_5m), 4, 20)
    if burst > 0:
        score += 0.40 * burst
        evidence.append(
            f"{record.user_unique_dst_5m} distinct destinations in 5 minutes"
        )

    # Burst relative to the account's own 24h baseline. An account that
    # normally touches 40 hosts reaching 8 in five minutes is working; one
    # that normally touches 2 doing the same is enumerating. Without this
    # ratio, every busy administrator is a false positive.
    baseline = max(1.0, float(record.user_unique_dst_24h))
    concentration = float(record.user_unique_dst_5m) / baseline
    if concentration > 0.3 and record.user_unique_dst_5m >= 3:
        score += 0.25 * _ramp(concentration, 0.3, 1.0)
        evidence.append(
            f"5-minute reach is {concentration:.0%} of this account's entire "
            "24-hour footprint"
        )

    if record.user_new_dst_ratio_1h > 0.5:
        score += 0.25 * _ramp(record.user_new_dst_ratio_1h, 0.5, 1.0)
        evidence.append(
            f"{record.user_new_dst_ratio_1h:.0%} of this hour's destinations were new"
        )

    # Kerberos service-ticket requests are how an attacker enumerates services
    # without touching them (and the precursor to kerberoasting).
    if _matches(ctx.orientation_name, "TGS") and record.user_unique_dst_5m >= 4:
        score += 0.15
        evidence.append("repeated service-ticket requests across many targets")

    return min(1.0, score), evidence


def _score_valid_account_abuse(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []

    # The technique is defined by the ABSENCE of guessing. A brand-new
    # relationship that works first time means the credential was already
    # known -- stolen, phished, or replayed.
    if not (record.is_new_pair and record.success):
        return 0.0, []
    if record.failures_before_success_15m > 0:
        # Failures first means this is brute force, not valid-account abuse.
        # Returning zero here keeps the two techniques mutually exclusive on
        # their defining condition rather than letting both fire at once.
        return 0.0, []

    # A first-try success on a new pair is necessary but nowhere near
    # sufficient: measured over the corpus it describes 28.6% of benign
    # traffic, because people legitimately reach machines they have not used
    # before every single day. The technique is about a credential being used
    # somewhere it does not belong, so require the access to be anomalous in
    # at least one further dimension that is a property of the DESTINATION
    # rather than of the user's routine.
    #
    # Benign firing rate for each candidate gate, within the base condition:
    #     destination_novelty > 0.7          1.88%
    #     rare destination (degree <= 3)      3.21%
    #     explicit alternate credentials      0.03%
    #     unusual logon hour/type             9.20%   <- kept as a booster only
    #
    # Hour-of-day is excluded from the gate deliberately: shift work and
    # global teams make it a property of the organisation, not of the access.
    corroborating = (
        record.destination_novelty > 0.7
        or record.dst_historical_degree <= 3
        or _matches(ctx.logon_type_name, "NewCredentials")
    )
    if not corroborating:
        return 0.0, []

    score = 0.45
    evidence.append("new account-host pair succeeded on the first attempt")

    if record.rare_logon_score > 0.5:
        score += 0.20 * _ramp(record.rare_logon_score, 0.5, 1.0)
        evidence.append("unusual logon type or hour for this estate")

    if record.destination_novelty > 0.7:
        score += 0.15 * _ramp(record.destination_novelty, 0.7, 1.0)
        evidence.append("destination is unusual for the population")

    if record.dst_historical_degree <= 3:
        score += 0.12
        evidence.append(
            f"destination is rarely contacted (historical degree "
            f"{record.dst_historical_degree})"
        )

    if record.user_seen_before and record.pair_rarity > 0.5:
        score += 0.10
        evidence.append("established account reaching an unfamiliar host")

    if _matches(ctx.logon_type_name, "NewCredentials"):
        score += 0.10
        evidence.append("explicit alternate credentials supplied")

    return min(1.0, score), evidence


def _score_kerberos_abuse(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []

    # Forged tickets (golden/silver) and replayed ones share an observable
    # shape: a service ticket appears without the ticket-granting ticket that
    # should have produced it. Legitimate Kerberos obtains a TGT first.
    if not _matches(ctx.orientation_name, "TGS"):
        return 0.0, []

    score = 0.0
    if ctx.seconds_since_tgt is None:
        # "No TGT was ever seen for this account" is only evidence of forgery
        # where TGTs are reliably logged. Measured on this corpus, 72.6% of
        # the 16,334 accounts that request service tickets have no observed
        # TGT at all -- the TGT was issued before the capture window or is not
        # recorded. Firing here without checking coverage measured a logging
        # artifact and produced 8.5% of benign traffic.
        #
        # Absence of evidence is only evidence of absence when the evidence
        # would have been visible.
        if ctx.tgt_coverage < 0.5:
            return 0.0, []
        score += 0.55
        evidence.append(
            "service ticket requested with no prior TGT for this account, in an "
            f"estate where {ctx.tgt_coverage:.0%} of ticket users have observed TGTs"
        )
    elif ctx.seconds_since_tgt > 36_000:  # beyond a normal 10h TGT lifetime
        score += 0.35
        evidence.append(
            f"service ticket {ctx.seconds_since_tgt / 3600:.1f}h after the last TGT, "
            "beyond normal ticket lifetime"
        )

    if score == 0.0:
        return 0.0, []

    if record.is_new_pair:
        score += 0.20
        evidence.append("ticket used against a host this account has never reached")

    if record.dst_historical_degree <= 3:
        score += 0.10
        evidence.append("service ticket targets a rarely-contacted host")

    return min(1.0, score), evidence


def _score_machine_account_misuse(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []

    if not _is_machine_account(ctx.user_name):
        return 0.0, []

    score = 0.0

    # A computer account cannot sit at a console. An interactive logon by one
    # means either a human is using the machine's credential or the account
    # has been repurposed.
    if _matches(ctx.logon_type_name, *HUMAN_LOGON_NAMES):
        score += 0.60
        evidence.append("machine account performing an interactive logon")

    # Service accounts have narrow, stable footprints; sudden breadth is the
    # signal, which is why this compares against the account's own baseline.
    baseline = max(1.0, float(record.user_historical_degree))
    if record.user_unique_dst_5m >= 3 and float(record.user_unique_dst_5m) / baseline > 0.4:
        score += 0.25
        evidence.append(
            f"machine account reached {record.user_unique_dst_5m} hosts in 5 minutes, "
            "well outside its established footprint"
        )

    if record.is_new_pair:
        score += 0.15
        evidence.append("machine account reaching a host it never has before")

    if score == 0.0:
        return 0.0, []
    return min(1.0, score), evidence


def _score_ntlm_downgrade(ctx: TacticContext) -> tuple[float, list[str]]:
    record = ctx.record
    evidence: list[str] = []

    if not _matches(ctx.auth_type_name, "NTLM"):
        return 0.0, []

    # NTLM is only suspicious in an estate that predominantly speaks Kerberos.
    # Scoring it without that context would flag every legacy application, so
    # the estate share gates the whole signature.
    if ctx.kerberos_share < 0.5:
        return 0.0, []

    score = 0.35 * _ramp(ctx.kerberos_share, 0.5, 0.95)
    evidence.append(
        f"NTLM used where {ctx.kerberos_share:.0%} of this estate uses Kerberos"
    )

    if record.is_new_pair:
        score += 0.30
        evidence.append("NTLM against a host this account has never reached")

    if ctx.signals.pivot >= 1.0:
        score += 0.20
        evidence.append("originating from a host that was itself recently reached")

    if record.dst_historical_degree <= 3:
        score += 0.10
        evidence.append("target is rarely contacted")

    return min(1.0, score), evidence


_SCORERS = (
    ("T1021", _score_lateral_movement),
    ("T1110", _score_brute_force),
    ("T1087", _score_discovery),
    ("T1078", _score_valid_account_abuse),
    ("T1550.003", _score_kerberos_abuse),
    ("T1078.002", _score_machine_account_misuse),
    ("T1550.002", _score_ntlm_downgrade),
)

#: Below this, a signature is treated as not indicated at all. Set deliberately
#: low: the engine's job is to rank techniques, and the caller decides what to
#: act on. Reporting a 0.05 "match" would be noise in the console.
MINIMUM_REPORTED_SCORE = 0.25

#: A primary tactic is only "high" confidence if it also clears its nearest
#: rival by this margin. Two techniques within 0.15 of each other means the
#: evidence genuinely does not separate them, and saying so is more useful
#: than picking one.
DECISIVE_MARGIN = 0.15


def classify(ctx: TacticContext) -> TacticClassification:
    """Score every signature against one event and rank them."""
    scored: list[TacticScore] = []
    for technique_id, scorer in _SCORERS:
        score, evidence = scorer(ctx)
        if score < MINIMUM_REPORTED_SCORE:
            continue
        signature = SIGNATURES[technique_id]
        scored.append(
            TacticScore(
                technique_id=technique_id,
                name=signature.name,
                tactic=signature.tactic,
                score=score,
                evidence=tuple(evidence),
            )
        )

    # Ties break on technique_id so the ordering is deterministic across runs;
    # an unstable "primary tactic" would make alerts irreproducible.
    scored.sort(key=lambda item: (-item.score, item.technique_id))

    if not scored:
        return TacticClassification(primary=None, scores=(), confidence="none")

    primary = scored[0]
    runner_up = scored[1].score if len(scored) > 1 else 0.0
    margin = primary.score - runner_up
    if ctx.chain_detected and primary.technique_id == "T1021":
        # Deterministic evidence is not subject to the margin test: another
        # signature scoring high on the same event does not make the chain
        # less of a chain.
        confidence = "high"
    elif primary.score >= 0.65 and margin >= DECISIVE_MARGIN:
        confidence = "high"
    elif primary.score >= 0.45:
        confidence = "medium"
    else:
        confidence = "low"

    return TacticClassification(primary=primary, scores=tuple(scored), confidence=confidence)


@dataclass
class TacticEngine:
    """Stateful wrapper holding the rolling context signatures need.

    Two signatures cannot be evaluated from a single event in isolation:
    Kerberos abuse needs to know when the account last obtained a TGT, and the
    NTLM signature needs to know what the estate normally speaks. Both are
    cheap rolling aggregates, kept here rather than recomputed per event.

    Mirrors the preview/commit discipline used elsewhere in the detection
    path: :meth:`classify_event` never mutates state, so a failed request
    cannot leave the engine half-updated. Call :meth:`observe` to advance.
    """

    #: Rolling window used to estimate what the estate normally speaks.
    auth_window: int = 5_000
    _tgt_by_user: dict[int, int] = field(default_factory=dict)
    _ticket_requesters: set[int] = field(default_factory=set)
    _recent_auth_types: deque[int] = field(default_factory=deque)
    _kerberos_count: int = 0
    _lock: RLock = field(default_factory=RLock)

    def tgt_coverage(self) -> float:
        """Fraction of ticket-requesting accounts with an observed TGT.

        A proxy for Kerberos telemetry completeness. Low coverage means a
        missing TGT says nothing about the ticket's legitimacy.
        """
        with self._lock:
            if not self._ticket_requesters:
                return 0.0
            observed = sum(1 for u in self._ticket_requesters if u in self._tgt_by_user)
            return observed / len(self._ticket_requesters)

    def kerberos_share(self) -> float:
        with self._lock:
            if not self._recent_auth_types:
                return 0.0
            return self._kerberos_count / len(self._recent_auth_types)

    def context(
        self,
        record: FeatureRecord,
        signals: ExplicitSignals,
        *,
        user_name: str = "",
        logon_type_name: str = "",
        auth_type_name: str = "",
        orientation_name: str = "",
        chain_detected: bool = False,
    ) -> TacticContext:
        with self._lock:
            last_tgt = self._tgt_by_user.get(record.src_user_id)
        seconds_since_tgt = None if last_tgt is None else float(record.timestamp - last_tgt)
        return TacticContext(
            record=record,
            signals=signals,
            user_name=user_name,
            seconds_since_tgt=seconds_since_tgt,
            kerberos_share=self.kerberos_share(),
            tgt_coverage=self.tgt_coverage(),
            logon_type_name=logon_type_name,
            auth_type_name=auth_type_name,
            orientation_name=orientation_name,
            source_fanout_1h=record.src_host_unique_dst_1h,
            chain_detected=chain_detected,
        )

    def classify_event(
        self,
        record: FeatureRecord,
        signals: ExplicitSignals,
        *,
        user_name: str = "",
        logon_type_name: str = "",
        auth_type_name: str = "",
        orientation_name: str = "",
        chain_detected: bool = False,
    ) -> TacticClassification:
        """Classify without advancing state."""
        return classify(
            self.context(
                record,
                signals,
                user_name=user_name,
                logon_type_name=logon_type_name,
                auth_type_name=auth_type_name,
                orientation_name=orientation_name,
                chain_detected=chain_detected,
            )
        )

    def observe(
        self,
        record: FeatureRecord,
        *,
        auth_type_name: str = "",
        orientation_name: str = "",
    ) -> None:
        """Fold one event into the rolling state. Call after classifying it."""
        with self._lock:
            # Prefer names when the caller has them. The id fallbacks only
            # ever compare ids within one stream to each other, never to a
            # cross-dictionary constant, so they stay correct either way.
            orientation = (orientation_name or "").strip().lower()
            if orientation == "tgt" or (
                not orientation and record.orientation_id == ORIENT_TGT
            ):
                self._tgt_by_user[record.src_user_id] = record.timestamp
            elif orientation == "tgs" or (
                not orientation and record.orientation_id == ORIENT_TGS
            ):
                self._ticket_requesters.add(record.src_user_id)
            self._recent_auth_types.append(record.auth_type_id)
            kerberos = (auth_type_name or "").strip().lower() == "kerberos"
            if kerberos or (
                not auth_type_name and record.auth_type_id == AUTH_KERBEROS
            ):
                self._kerberos_count += 1
            while len(self._recent_auth_types) > self.auth_window:
                evicted = self._recent_auth_types.popleft()
                if evicted == AUTH_KERBEROS:
                    self._kerberos_count -= 1

    def reset(self) -> None:
        with self._lock:
            self._tgt_by_user.clear()
            self._ticket_requesters.clear()
            self._recent_auth_types.clear()
            self._kerberos_count = 0


def describe_validation() -> dict[str, object]:
    """Report which signatures have real ground truth and which do not.

    Exposed deliberately so the distinction survives into the API and the
    console. The 649 LANL red-team events are all lateral movement, so T1021
    is the only technique that can be scored against real labels; claiming
    measured accuracy for the others would be inventing it.
    """
    return {
        "ground_truth_corpus": "LANL red-team labels (649 events, all lateral movement)",
        "validated_against_labels": [
            technique_id
            for technique_id, signature in SIGNATURES.items()
            if signature.ground_truth
        ],
        "synthetic_validation_only": [
            technique_id
            for technique_id, signature in SIGNATURES.items()
            if not signature.ground_truth
        ],
        "note": (
            "Techniques outside the ground-truth list are validated by synthetic "
            "injection only. No per-class precision or recall is claimed for them."
        ),
    }
