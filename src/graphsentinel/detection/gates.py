"""The automated-response gate, derived from a precision target rather than a score.

What the gate is
----------------
The response layer runs one disruptive action unattended -- ``force_reauth``,
which invalidates an account's sessions -- and only when the fused risk is at
or above this threshold with a high-confidence attribution. Everything harsher
requires a human (enforced by ``test_no_meaningfully_disruptive_action_can_ever_
auto_execute``). So the gate answers exactly one question: *of the events the
system acts on by itself, what share must genuinely be attacks?*

Why it is derived, not chosen
-----------------------------
The previous value, 0.85, was a point on the score scale. Measured against
labels it corresponded to 50.7% precision on the sealed test period (Finding
15) -- a coin flip, not the 85% the number suggests. A gate is a risk
tolerance, and a risk tolerance is a precision, so the constant here is the
lowest score whose **Wilson lower bound** on precision clears a stated target
on the validation partition -- the same partition the alert thresholds are
derived on, so that no operating constant is fitted to test.

Why the realised value is recorded next to the target
-----------------------------------------------------
Precision at a fixed score does not hold across time. On validation the
derived gate delivers 80.5% precision (lower bound 75.1%, 251 alerts); on the sealed test
period, which is later in the stream, the same score delivers 53.2%
[46.3%, 60.0%]. The old 0.85 gate showed the same decay: 78.0% on validation,
50.7% on test, with non-overlapping intervals. A reader who sees only the
target would believe the gate means 75%; it means 75% *at derivation time*,
and roughly half that on the period it was not tuned on. Both numbers travel
with the constant so neither can be quoted without the other.

Which number it is derived on
-----------------------------
The quantity ``plan_for`` compares is the alert's fused risk: the noisy-OR of
the four channels, raised to the chain-rule floor when the rule fires. The
gate is derived on exactly that quantity. It was first derived on the raw
model probability, which is *not* what the product compares -- at the same
score the fused risk admits a different set of events -- and the end-to-end
check caught the mismatch (Finding 24). At the top of the ranking the two
quantities order the same 251 validation events, so the target is met by the
same alerts; the threshold itself moves from 0.877729 to 0.846394 because the
fused risk of an event is bounded by the model reliability (0.95) times its
probability.

What this gate is not
---------------------
The severity bands the console paints (``critical`` at 0.85 and above, in
``api/product.py``, ``api/main.py`` and ``integrations/alert_summary.py``) are
a display convention, and the playbook's ``isolate_host`` minimum is a
*recommendation* threshold for a step a human must approve. Neither executes
anything. They used to share the number 0.85 with this gate, which made
"critical" read as "acted on automatically"; they are deliberately not tied to
it now. A critical-band alert is one an analyst should look at first; a
gate-clearing alert is one the system will act on alone. Different questions,
different numbers.

Provenance
----------
Derived from the committed scored cache (``tests/fixtures/fusion_cache.parquet``,
sha256 ``e6ce1f09945a6b93``): the fused noisy-OR risk of its channels with the
chain-rule floor applied, model ``tgn-auth-causal-v1-bb20801e0b40``.
``test_the_gate_matches_its_derivation`` re-derives it from that fixture with
the product's own ``fuse_risk`` and ``apply_rule_floor``, so the constant
cannot drift from its source without the test saying so.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GateDerivation:
    precision_target: float
    threshold: float
    derived_on: str
    #: The score the gate is derived on and compared against. Must be the
    #: number the response layer actually receives.
    quantity: str
    validation_alerts: int
    validation_precision: float
    validation_lower_bound: float
    test_alerts: int
    test_precision: float
    test_interval: tuple[float, float]
    #: Benign events above the gate per 10,000 benign events. This is the
    #: controllable quantity: it is what the gate *costs*, it does not depend
    #: on how many attacks happened that day, and it is the number to hold
    #: constant if the gate is ever re-derived. Precision is an outcome of it
    #: and of the day's attack volume (Finding 18).
    validation_benign_rate_per_10k: float
    test_benign_rate_per_10k: float
    fixture_sha16: str
    model_version: str

    def to_dict(self) -> dict[str, object]:
        return {
            "precision_target": self.precision_target,
            "threshold": self.threshold,
            "derived_on": self.derived_on,
            "quantity": self.quantity,
            "validation": {
                "alerts": self.validation_alerts,
                "precision": self.validation_precision,
                "lower_bound": self.validation_lower_bound,
                "benign_rate_per_10k": self.validation_benign_rate_per_10k,
            },
            "sealed_test": {
                "alerts": self.test_alerts,
                "precision": self.test_precision,
                "ci95": list(self.test_interval),
                "benign_rate_per_10k": self.test_benign_rate_per_10k,
                "note": (
                    "Realised precision on the period the gate was not tuned on. "
                    "This, not the target, is what the gate delivered out of sample."
                ),
            },
            "fixture_sha16": self.fixture_sha16,
            "model_version": self.model_version,
        }


#: Wilson lower bound on precision that the gate must clear on validation.
#: 0.75 ratifies the old 0.85 gate's *validation* behaviour (78%) with a
#: derivation behind it; 0.90 is not achievable at any threshold with at least
#: 20 alerts, and 0.50 would admit 423 test events at 26.5% precision.
AUTO_EXECUTE_PRECISION_TARGET = 0.75

AUTO_EXECUTE_GATE = GateDerivation(
    precision_target=AUTO_EXECUTE_PRECISION_TARGET,
    threshold=0.846394,
    derived_on="validation",
    quantity="fused noisy-OR risk with the chain-rule floor (what plan_for compares)",
    validation_alerts=251,
    validation_precision=0.8048,
    validation_lower_bound=0.7513,
    test_alerts=201,
    test_precision=0.5323,
    test_interval=(0.4634, 0.6001),
    validation_benign_rate_per_10k=5.22,
    test_benign_rate_per_10k=8.113,
    fixture_sha16="e6ce1f09945a6b93",
    model_version="tgn-auth-causal-v1-bb20801e0b40",
)

#: The number the response layer actually compares against. Import this;
#: never restate it as a literal.
AUTO_EXECUTE_THRESHOLD = AUTO_EXECUTE_GATE.threshold

#: Minimum events above a candidate threshold for its precision to be
#: estimable at all. Below this the Wilson interval spans most of [0, 1].
MINIMUM_GATE_ALERTS = 20
