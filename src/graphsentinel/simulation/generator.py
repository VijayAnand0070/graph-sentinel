"""Generate a synthetic continuation of the corpus with campaigns injected.

Benign traffic is a Poisson process at the measured rate, thinned by the
measured hour-of-day profile, with each event resampled from the behaviour its
user has actually exhibited. Attack events take the compromised account's own
authentication mechanics -- auth type, logon type, orientation -- and change
only where it goes. The movement is the anomaly; nothing else about the event
is made to look suspicious, because an attacker with a valid credential has no
reason to look suspicious in any other way.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np

from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.simulation.campaigns import CampaignSpec
from graphsentinel.simulation.profile import SECONDS_PER_DAY, BenignTuple, CorpusProfile

#: Hard cap on the inter-arrival draw, so a thinned tail cannot open a gap the
#: rolling windows would read as "quiet period" that never happened.
MAX_INTERARRIVAL_SECONDS = 300


@dataclass(frozen=True, slots=True)
class Truth:
    campaign_id: str
    hop_index: int
    #: The ATT&CK technique this event exercises. Campaign hops are lateral
    #: movement; technique scenarios carry their own id.
    technique_id: str = "T1021"


@dataclass
class SyntheticStream:
    events: list[NormalizedAuthEvent]
    truth: dict[int, Truth]  # event_id -> campaign membership
    campaigns: tuple[CampaignSpec, ...]
    benign_count: int
    seed: int
    start_timestamp: int
    end_timestamp: int
    generated_from: dict[str, object] = field(default_factory=dict)

    @property
    def attack_count(self) -> int:
        return len(self.truth)

    def manifest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "seed": self.seed,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "events": len(self.events),
            "benign": self.benign_count,
            "attack": self.attack_count,
            "profile": self.generated_from,
            "campaigns": [c.to_dict() for c in self.campaigns],
            "truth": {
                str(k): {
                    "campaign_id": v.campaign_id,
                    "hop": v.hop_index,
                    "technique_id": v.technique_id,
                }
                for k, v in self.truth.items()
            },
        }


def _event(
    event_id: int,
    timestamp: int,
    user: int,
    behaviour: BenignTuple,
    *,
    src_host: int | None = None,
    dst_host: int | None = None,
    label: int = 0,
) -> NormalizedAuthEvent:
    dst_user, b_src, b_dst, auth, logon, orientation, success = behaviour
    return NormalizedAuthEvent(
        event_id=event_id,
        timestamp=timestamp,
        src_user_id=user,
        dst_user_id=dst_user,
        src_host_id=b_src if src_host is None else src_host,
        dst_host_id=b_dst if dst_host is None else dst_host,
        auth_type_id=auth,
        logon_type_id=logon,
        orientation_id=orientation,
        success=success,
        label_redteam=label,
        day=timestamp // SECONDS_PER_DAY,
        hour=(timestamp % SECONDS_PER_DAY) // 3_600,
    )


def generate_benign(
    profile: CorpusProfile,
    rng: np.random.Generator,
    *,
    start_timestamp: int,
    end_timestamp: int,
    rate_multiplier: float = 1.0,
) -> list[NormalizedAuthEvent]:
    """Benign events over [start, end): measured rate, measured hour profile."""
    if end_timestamp <= start_timestamp:
        raise ValueError("end_timestamp must be after start_timestamp")
    # The hour profile thins by acceptance, so the raw process runs faster
    # than the target by the mean acceptance so the realised rate matches.
    acceptance = float(np.mean(profile.hour_weights)) or 1.0
    raw_rate = profile.events_per_second * rate_multiplier / acceptance
    events: list[NormalizedAuthEvent] = []
    t = start_timestamp
    while True:
        t += max(1, min(int(rng.exponential(1.0 / raw_rate)), MAX_INTERARRIVAL_SECONDS))
        if t >= end_timestamp:
            break
        if rng.random() >= profile.hour_weight(t):
            continue
        user = profile.sample_user(rng)
        events.append(_event(0, t, user, profile.sample_behaviour(user, rng)))
    return events


def attack_events(
    profile: CorpusProfile,
    rng: np.random.Generator,
    campaigns: Sequence[CampaignSpec],
) -> tuple[list[NormalizedAuthEvent], list[Truth]]:
    events: list[NormalizedAuthEvent] = []
    truths: list[Truth] = []
    for campaign in campaigns:
        for hop in campaign.hops:
            behaviour = profile.sample_behaviour(hop.src_user_id, rng)
            # A valid credential succeeds; the mechanics are the account's own.
            behaviour = (*behaviour[:6], 1)
            events.append(
                _event(
                    0,
                    hop.timestamp,
                    hop.src_user_id,
                    behaviour,
                    src_host=hop.src_host_id,
                    dst_host=hop.dst_host_id,
                    label=1,
                )
            )
            truths.append(Truth(campaign.campaign_id, hop.hop_index))
    return events, truths


def generate_stream(
    profile: CorpusProfile,
    *,
    campaigns: Sequence[CampaignSpec],
    start_timestamp: int,
    end_timestamp: int,
    seed: int,
    rate_multiplier: float = 1.0,
    first_event_id: int = 1,
    extra: Sequence[tuple[NormalizedAuthEvent, Truth]] = (),
) -> SyntheticStream:
    """Benign continuation plus injected campaigns, chronological, re-numbered.

    ``extra`` carries labelled events from technique scenarios, which are not
    campaigns (they have no hop semantics) but share the stream and the truth
    table.
    """
    rng = np.random.default_rng(seed)
    for campaign in campaigns:
        if not (
            start_timestamp <= campaign.start_timestamp and campaign.end_timestamp < end_timestamp
        ):
            raise ValueError(f"{campaign.campaign_id} falls outside the stream window")
    for injected, label in extra:
        if not start_timestamp <= injected.timestamp < end_timestamp:
            raise ValueError(f"{label.campaign_id} falls outside the stream window")

    benign = generate_benign(
        profile,
        rng,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        rate_multiplier=rate_multiplier,
    )
    attacks, truths = attack_events(profile, rng, campaigns)

    Tagged = tuple[int, int, NormalizedAuthEvent, Truth | None]
    tagged: list[Tagged] = [(e.timestamp, 0, e, None) for e in benign]
    tagged.extend((e.timestamp, 1, e, t) for e, t in zip(attacks, truths, strict=True))
    tagged.extend((e.timestamp, 1, e, t) for e, t in extra)
    # Stable by (timestamp, benign-before-attack) so a benign event at the same
    # second is processed first -- conservative for the attacker, since the
    # rolling windows then already contain that benign activity.
    tagged.sort(key=lambda item: (item[0], item[1]))

    events: list[NormalizedAuthEvent] = []
    truth: dict[int, Truth] = {}
    for offset, entry in enumerate(tagged):
        event = entry[2]
        membership = entry[3]
        event_id = first_event_id + offset
        events.append(NormalizedAuthEvent(**{**event.to_dict(), "event_id": event_id}))
        if membership is not None:
            truth[event_id] = membership

    return SyntheticStream(
        events=events,
        truth=truth,
        campaigns=tuple(campaigns),
        benign_count=len(benign),
        seed=seed,
        start_timestamp=start_timestamp,
        end_timestamp=end_timestamp,
        generated_from=profile.summary(),
    )
