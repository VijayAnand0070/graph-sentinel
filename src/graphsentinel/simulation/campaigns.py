"""Attack campaigns with ground truth in hops.

Two families, both measured from the real corpus rather than assumed:

``fanout``
    One compromised host reaches many destinations. This is the topology the
    LANL red team actually exhibits (Finding 4: fan-out from a few fixed
    sources, no observable pivot chain). Credentials rotate through accounts
    that have genuinely been used at that host, because that is what a
    harvested credential store looks like.

``chain``
    Each hop's source is the previous hop's destination, under one account:
    A -> B, B -> C, C -> D. This is the pivot the same-account chain rule
    (T1021, 300 s window) exists to catch, and it is the family on which
    "hops prevented" is most meaningful, since stopping hop k stops every host
    after it.

The attacker host is always drawn from ordinary busy workstations with benign
history. That single choice is what makes these campaigns able to test
generalisation at all -- see Finding 14 for why a host that only ever attacks
teaches a model nothing about attacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import numpy as np

from graphsentinel.simulation.profile import CorpusProfile

Family = Literal["fanout", "chain"]
FAMILIES: tuple[Family, ...] = ("fanout", "chain")


@dataclass(frozen=True, slots=True)
class Hop:
    hop_index: int
    timestamp: int
    src_user_id: int
    src_host_id: int
    dst_host_id: int


@dataclass(frozen=True, slots=True)
class CampaignSpec:
    campaign_id: str
    family: Family
    attacker_host_id: int
    interval_seconds: int
    start_timestamp: int
    hops: tuple[Hop, ...]

    @property
    def length(self) -> int:
        return len(self.hops)

    @property
    def end_timestamp(self) -> int:
        return self.hops[-1].timestamp

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "family": self.family,
            "attacker_host_id": self.attacker_host_id,
            "interval_seconds": self.interval_seconds,
            "start_timestamp": self.start_timestamp,
            "hops": [
                {
                    "hop": h.hop_index,
                    "timestamp": h.timestamp,
                    "user": h.src_user_id,
                    "src_host": h.src_host_id,
                    "dst_host": h.dst_host_id,
                }
                for h in self.hops
            ],
        }


def plan_campaign(
    profile: CorpusProfile,
    rng: np.random.Generator,
    *,
    campaign_id: str,
    family: Family,
    hops: int,
    interval_seconds: int,
    start_timestamp: int,
    attacker_host_id: int | None = None,
    reserved: dict[int, set[int]] | None = None,
) -> CampaignSpec:
    """Lay out one campaign's hops concretely, against the profiled population.

    ``reserved`` maps an account to the destinations other campaigns in the
    same stream have already sent it to, and is extended with this
    campaign's. A stream compromises the same widely-used credential many
    times over its days, and the chain rule's novelty is cumulative
    (Finding 27), so without it a later campaign on that account walks into
    hosts an earlier one already reached and its hops are not novel -- a
    contract violation ("the attacker is going somewhere the credential's
    owner does not go") that biased the instrument against the precise rule
    by one campaign in a hundred.
    """
    if family not in FAMILIES:
        raise ValueError(f"unknown campaign family {family!r}")
    if hops < 1:
        raise ValueError("a campaign needs at least one hop")
    if interval_seconds < 1:
        raise ValueError("interval_seconds must be positive")

    if attacker_host_id is None:
        candidates = profile.candidate_attacker_hosts()
        if not candidates:
            raise ValueError("profile has no candidate attacker hosts")
        attacker_host_id = int(rng.choice(candidates))
    accounts = profile.users_by_source_host.get(attacker_host_id)
    if not accounts:
        raise ValueError(f"host {attacker_host_id} has no profiled users to compromise")

    # Destinations are novel for the account used: the attacker is going
    # somewhere the credential's owner does not go. Also never the attacker's
    # own host, and never a host already in this campaign.
    used: set[int] = {attacker_host_id}
    planned: list[Hop] = []

    def known(user: int) -> set[int]:
        destinations = set(profile.user_destinations.get(user, set()))
        if reserved is not None:
            destinations |= reserved.get(user, set())
        return destinations

    if family == "fanout":
        order = list(accounts)
        rng.shuffle(order)
        for index in range(hops):
            user = order[index % len(order)]
            exclude = used | known(user)
            destination = profile.sample_destination(rng, exclude=exclude)
            used.add(destination)
            planned.append(
                Hop(
                    index,
                    start_timestamp + index * interval_seconds,
                    user,
                    attacker_host_id,
                    destination,
                )
            )
    else:
        user = int(rng.choice(accounts))
        exclude_base = known(user)
        source = attacker_host_id
        for index in range(hops):
            destination = profile.sample_destination(rng, exclude=used | exclude_base)
            used.add(destination)
            planned.append(
                Hop(index, start_timestamp + index * interval_seconds, user, source, destination)
            )
            source = destination

    if reserved is not None:
        for hop in planned:
            reserved.setdefault(hop.src_user_id, set()).add(hop.dst_host_id)

    return CampaignSpec(
        campaign_id=campaign_id,
        family=family,
        attacker_host_id=attacker_host_id,
        interval_seconds=interval_seconds,
        start_timestamp=start_timestamp,
        hops=tuple(planned),
    )
