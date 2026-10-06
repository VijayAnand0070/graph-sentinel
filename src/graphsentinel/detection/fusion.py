"""Auditable late fusion of learned risk and explicit evidence channels.

Two operators live here, and the choice between them is the substantive
design decision in the detection path.

The weighted-average problem
----------------------------
The original operator was a weighted sum with the constraint that weights sum
to one. That constraint has a consequence which is easy to miss and fatal in
practice: with ``tgn`` weighted 0.55, the remaining channels sum to 0.45,
while the calibrated decision threshold is 0.4543. An event with *perfect*
novelty, burst, pivot and corroboration therefore scores 0.45 and does not
alert. The three behavioural channels cannot raise an alert on their own at
any evidence level. The TGN holds an absolute veto.

That is not a tuning accident, it is what a weighted average does: it
*averages*. Averaging is correct for combining estimates of the same quantity,
and wrong for combining independent evidence of different kinds. A model that
has never seen this pivot pattern and a rule that recognises it exactly should
not be averaged -- the confident one should carry the decision.

This was not hypothetical. Replaying a labelled five-hop lateral-movement
chain through the deployed linear fusion produced risks of 0.0015 to 0.1576
against a 0.4543 threshold: entirely missed, with ``pivot`` firing at 1.0 on
four of the five hops.

Noisy-OR
--------
The standard operator for combining independent evidence is the noisy-OR gate:

    P(malicious) = 1 - prod_i (1 - r_i * s_i)

where ``s_i`` is the channel signal in [0, 1] and ``r_i`` is that channel's
*reliability* -- how much a fully-fired channel moves the verdict on its own.
Reliabilities are independent probabilities, so unlike linear weights they are
deliberately NOT constrained to sum to one.

Properties this buys:

* any single strong channel can carry an alert, which is what "defence in
  depth" is supposed to mean;
* weak channels still compound, so three mediocre signals beat one;
* monotonic in every channel, so more evidence never lowers the score;
* bounded in [0, 1] without clipping;
* still fully decomposable for audit, via marginal contributions.

Both operators are kept. The linear one remains the calibrated baseline that
current thresholds were fitted against, and swapping operators changes the
score distribution, so a new threshold must be re-derived on validation at the
same false-positive budget before noisy-OR is made the default.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass

CHANNELS = ("tgn", "novelty", "burst", "pivot", "corroboration")


def _probability(name: str, value: float) -> None:
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be a finite probability in [0, 1]")


@dataclass(frozen=True, slots=True)
class RiskComponents:
    tgn: float
    novelty: float
    burst: float
    pivot: float
    corroboration: float

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            _probability(name, value)

    def to_dict(self) -> dict[str, float]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FusionConfig:
    """Linear weights. Constrained to sum to one, which is what creates the
    veto described in the module docstring."""

    tgn: float = 0.55
    novelty: float = 0.20
    burst: float = 0.10
    pivot: float = 0.10
    corroboration: float = 0.05

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(not math.isfinite(value) or value < 0 for value in values.values()):
            raise ValueError("fusion weights must be finite and non-negative")
        if not math.isclose(sum(values.values()), 1.0, abs_tol=1e-9):
            raise ValueError("fusion weights must sum to one")

    def to_dict(self) -> dict[str, float]:
        return asdict(self)

    def behavioural_ceiling(self) -> float:
        """Highest score reachable with ``tgn`` at zero.

        Exposed so a deployment can assert this clears its decision threshold.
        When it does not, the learned channel silently holds a veto over every
        rule in the system, which is worth failing loudly about rather than
        discovering from a missed campaign.
        """
        return sum(value for name, value in self.to_dict().items() if name != "tgn")


@dataclass(frozen=True, slots=True)
class NoisyOrConfig:
    """Per-channel reliabilities for the noisy-OR gate.

    ``r_i`` answers: if this channel alone were maxed out and every other
    channel were silent, how strongly should the event be suspected? These are
    independent probabilities and intentionally carry no sum-to-one constraint
    -- that constraint is precisely what makes the linear operator vetoable.

    Defaults are deliberately conservative placeholders. They must be fitted
    on labelled validation data and the threshold re-derived at the same
    false-positive budget before being trusted; see
    ``calibrate_noisy_or`` in the fusion calibration harness.
    """

    #: Fitted on the validation partition by coordinate ascent on PR-AUC, then
    #: frozen. The optimiser drove ``novelty`` and ``pivot`` to the floor:
    #: noisy-OR does not win by letting the behavioural channels finally
    #: contribute, it wins by letting a confident model carry the decision
    #: instead of being averaged down. On the offline features the TGN
    #: separates attacks from benign by 360x, and the other channels mostly
    #: add noise on top of that.
    tgn: float = 0.95
    novelty: float = 0.05
    burst: float = 0.30
    pivot: float = 0.05
    corroboration: float = 0.35

    #: The decision threshold these reliabilities were calibrated against, on
    #: validation, at the same 25 FP/10k budget the linear operator used.
    #:
    #: Carried HERE rather than configured separately on purpose. Changing the
    #: fusion operator changes the score distribution, so an operator paired
    #: with the other operator's threshold silently changes the alert rate --
    #: the two must travel together or neither number means anything.
    calibrated_threshold: float = 0.329195

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if name == "calibrated_threshold":
                continue
            _probability(name, value)
        _probability("calibrated_threshold", self.calibrated_threshold)

    def to_dict(self) -> dict[str, float]:
        values = asdict(self)
        values.pop("calibrated_threshold", None)
        return values


@dataclass(frozen=True, slots=True)
class FusedRisk:
    score: float
    components: RiskComponents
    weights: FusionConfig | NoisyOrConfig
    operator: str = "linear"
    #: Names the deterministic rule that raised this score, if any. An alert
    #: produced by a rule must be distinguishable from one the model produced,
    #: or the model gets credit for detections it did not make.
    rule_floor: str | None = None

    def contributions(self) -> dict[str, float]:
        """Per-channel attribution of the final score.

        For the linear operator this is exact: contributions sum to the score.

        For noisy-OR it is the *marginal* contribution -- how far the score
        would fall if this channel alone were silenced. Marginals do not sum
        to the score (the operator is not additive), which is stated here
        rather than hidden, because an analyst comparing the two would
        otherwise think one of them was broken.
        """
        components = self.components.to_dict()
        weights = self.weights.to_dict()
        if self.operator == "linear":
            return {name: components[name] * weights[name] for name in components}

        full = _noisy_or(components, weights)
        marginals: dict[str, float] = {}
        for channel in components:
            without = dict(components)
            without[channel] = 0.0
            marginals[channel] = full - _noisy_or(without, weights)
        return marginals

    def dominant_channel(self) -> str | None:
        """The channel carrying the most of this verdict, or None if silent."""
        contributions = self.contributions()
        best = max(contributions, key=lambda name: contributions[name])
        return best if contributions[best] > 0 else None


def _noisy_or(components: dict[str, float], reliabilities: dict[str, float]) -> float:
    """1 - prod(1 - r_i * s_i), computed directly.

    The product is over at most five terms whose factors are bounded in
    [0, 1], so the naive form is numerically fine here; a log-space version
    would only add a special case for the exact-zero factor.
    """
    survival = 1.0
    for name, signal in components.items():
        survival *= 1.0 - reliabilities[name] * signal
    return min(1.0, max(0.0, 1.0 - survival))


DEFAULT_FUSION_CONFIG = FusionConfig()
DEFAULT_NOISY_OR_CONFIG = NoisyOrConfig()


def fuse_risk(
    components: RiskComponents,
    config: FusionConfig | NoisyOrConfig = DEFAULT_FUSION_CONFIG,
) -> FusedRisk:
    """Fuse evidence channels into one score.

    The operator is selected by the config type, so callers opt into noisy-OR
    by passing a :class:`NoisyOrConfig` and nothing else changes.
    """
    values = components.to_dict()
    weights = config.to_dict()

    if isinstance(config, NoisyOrConfig):
        return FusedRisk(
            score=_noisy_or(values, weights),
            components=components,
            weights=config,
            operator="noisy_or",
        )

    score = sum(values[name] * weights[name] for name in values)
    return FusedRisk(
        score=min(1.0, max(0.0, score)),
        components=components,
        weights=config,
        operator="linear",
    )


#: Validation-calibrated operating points, measured at a 25 FP/10k budget on
#: the 543,615-event corpus. Test PR-AUC is the number that matters, and is
#: reported here so a deployment can see what it is choosing between.
OPERATING_POINTS: dict[str, dict[str, float]] = {
    "linear": {"threshold": 0.362571, "validation_pr_auc": 0.9061, "test_pr_auc": 0.5773},
    "noisy_or": {"threshold": 0.329195, "validation_pr_auc": 0.9792, "test_pr_auc": 0.8048},
    "tgn_only": {"threshold": 0.296960, "validation_pr_auc": 0.9798, "test_pr_auc": 0.8210},
}

#: 95% bootstrap intervals on the test PR-AUC figures above (2,000 stratified
#: resamples, seed 1729). The test partition holds 115,992 events but only 126
#: attacks, so these intervals are wide and the point estimates should never be
#: quoted alone.
#:
#:     linear     0.5773  [0.4983, 0.6564]
#:     noisy_or   0.8048  [0.7411, 0.8671]
#:     tgn_only   0.8210  [0.7639, 0.8784]
#:
#: Paired comparisons on the same resampled events:
#:
#:     noisy_or - linear   +0.2275  [+0.1724, +0.2863]   significant
#:     tgn_only - noisy_or +0.0163  [+0.0060, +0.0305]   significant
#:
#: Regenerated 2026-09-18 from the scored cache rebuilt with the shared signal
#: tracker (Finding 24: the pivot channel is now the one the product computes;
#: the fused figures moved by less than 0.002 because its reliability is 0.05).
#:
#: The second one is the uncomfortable result: **fusion costs ranking quality.**
#: The raw model beats every fused variant, significantly though by a small
#: margin (~2%). Fusion is retained because it buys three things the raw score
#: cannot provide -- per-channel attribution for an analyst, graceful
#: degradation when no checkpoint is loaded, and a place for deterministic
#: rules to raise a floor (see CHAIN_RULE_FLOOR). That is a defensible trade,
#: but it is a trade, and presenting fusion as an accuracy improvement would be
#: false.
TEST_PR_AUC_CI: dict[str, tuple[float, float]] = {
    "linear": (0.4983, 0.6564),
    "noisy_or": (0.7411, 0.8671),
    "tgn_only": (0.7639, 0.8784),
}


def select_fusion(name: str) -> tuple[FusionConfig | NoisyOrConfig, float]:
    """Return a fusion config together with ITS calibrated threshold.

    Returning both as one value is the point. The operator and the threshold
    are a matched pair -- swapping one without the other silently changes the
    alert rate, which is the failure this function exists to make impossible.
    """
    key = (name or "").strip().lower()
    if key in {"noisy_or", "noisy-or", "noisyor"}:
        config = NoisyOrConfig()
        return config, config.calibrated_threshold
    if key == "linear":
        return FusionConfig(), OPERATING_POINTS["linear"]["threshold"]
    if key in {"tgn_only", "tgn-only", "model_only"}:
        # A noisy-OR gate with every other reliability at zero reduces exactly
        # to the model probability: 1 - (1 - 1*tgn) = tgn. Expressed this way
        # rather than as a special case so it travels the same code path,
        # reports the same contributions, and can still take a rule floor.
        config = NoisyOrConfig(
            tgn=1.0, novelty=0.0, burst=0.0, pivot=0.0, corroboration=0.0,
            calibrated_threshold=OPERATING_POINTS["tgn_only"]["threshold"],
        )
        return config, config.calibrated_threshold
    if key in {"transfer", "label_free", "calibrated"}:
        # The label-free transfer model: its score is already a risk on this
        # scale, calibrated on the estate's own traffic, so it passes through
        # alone -- the other channels' reliabilities were fitted on one
        # estate's labels. Threshold is the scale's fixed alert point.
        config = NoisyOrConfig(tgn=1.0, novelty=0.0, burst=0.0, pivot=0.0, corroboration=0.0)
        return config, config.calibrated_threshold
    raise ValueError(
        f"unknown fusion operator {name!r}; expected 'noisy_or', 'linear', 'tgn_only' or 'transfer'"
    )


# ---------------------------------------------------------------------------
# Deterministic rule floors
#
# Some patterns are known-bad by domain knowledge and do not need to be
# learned. The fitted reliabilities cannot express them: a weight is fitted
# from examples, and the corpus the weights come from contains no pivot-based
# lateral movement at all (644 of its 649 red-team events have a source host
# that was never previously a destination). A channel with no positive class
# gets no weight, no matter how good its definition becomes.
#
# So the chain is a RULE, not a weight -- the deterministic layer of the
# standard rules-plus-ML architecture, asserting what the model has never been
# shown. The floor is applied AFTER fusion and recorded on the result, so an
# alert raised this way is never mistaken for one the model produced.
# ---------------------------------------------------------------------------

#: Above the noisy-OR threshold (0.329195) with margin, so the rule alerts
#: without pinning the score at 1.0 and drowning out genuinely higher-risk
#: events in the analyst's queue.
CHAIN_RULE_FLOOR = 0.60


def apply_rule_floor(
    risk: FusedRisk, *, chain_detected: bool, floor: float = CHAIN_RULE_FLOOR
) -> FusedRisk:
    """Raise a fused score to the rule floor when a deterministic rule fires.

    Measured cost of the chain rule (4+ hops within 300s) on the labelled
    corpus: 4.6 false positives per 10,000 benign events, against a budget of
    25. It catches 9 events of the labelled five-hop chain that the fitted
    model scores at 0.1026 and would never alert.

    A floor, not an override: an event already scoring above the floor keeps
    its higher score, because the model having *more* to say than the rule is
    information worth preserving.
    """
    if not chain_detected or risk.score >= floor:
        return risk
    return FusedRisk(
        score=floor,
        components=risk.components,
        weights=risk.weights,
        operator=risk.operator,
        rule_floor="chain_pivot",
    )
