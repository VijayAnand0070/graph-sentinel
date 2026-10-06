"""Behaviour-first injections for the techniques that have no ground truth.

Six of the seven tactic signatures have never been measured against a labelled
attack: the corpus labels lateral movement and nothing else. Their published
"validation" is a benign firing rate, which says how noisy a rule is and
nothing about whether it fires on the thing it names.

The scenarios here are built from MITRE ATT&CK's description of what an
adversary *does*, not from what the corresponding rule *checks*. That
distinction is the whole point: an injection designed to satisfy a rule would
measure the injection, and recall against it would be a tautology. Each
scenario's docstring cites the behaviour it encodes; none of them consult a
threshold in ``detection/tactics.py``. Where a rule keys on something the
behaviour does not necessarily produce, recall will be low, and that is the
finding.

Every scenario runs from an ordinary workstation with benign history and uses
accounts that exist in the profiled population, for the same reason the
campaigns do (Finding 14).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import numpy as np

from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.simulation.generator import Truth, _event
from graphsentinel.simulation.profile import SECONDS_PER_DAY, BenignTuple, CorpusProfile

if TYPE_CHECKING:  # pragma: no cover - annotations only
    from graphsentinel.ingestion.id_map import AuthIdMaps, StableIdMap


@dataclass(frozen=True, slots=True)
class CategoryIds:
    """Dictionary indices for the raw categories the scenarios need."""

    logon_network: int
    logon_interactive: int
    logon_remote_interactive: int
    auth_ntlm: int
    auth_kerberos: int
    orientation_logon: int
    orientation_tgs: int
    orientation_tgt: int

    @classmethod
    def from_id_maps(cls, maps: AuthIdMaps) -> CategoryIds:
        def index(mapping: StableIdMap, name: str) -> int:
            values = cast("list[str]", mapping.to_dict()["values"])
            if name not in values:
                raise ValueError(f"{name!r} is not in the {mapping.namespace} dictionary")
            return int(values.index(name))

        return cls(
            logon_network=index(maps.logon_types, "Network"),
            logon_interactive=index(maps.logon_types, "Interactive"),
            logon_remote_interactive=index(maps.logon_types, "RemoteInteractive"),
            auth_ntlm=index(maps.auth_types, "NTLM"),
            auth_kerberos=index(maps.auth_types, "Kerberos"),
            orientation_logon=index(maps.orientations, "LogOn"),
            orientation_tgs=index(maps.orientations, "TGS"),
            orientation_tgt=index(maps.orientations, "TGT"),
        )


@dataclass(frozen=True, slots=True)
class TechniqueScenario:
    scenario_id: str
    technique_id: str
    attacker_host_id: int
    start_timestamp: int
    events: tuple[NormalizedAuthEvent, ...]

    def truths(self) -> list[Truth]:
        return [
            Truth(self.scenario_id, index, self.technique_id) for index in range(len(self.events))
        ]

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "technique_id": self.technique_id,
            "attacker_host_id": self.attacker_host_id,
            "start_timestamp": self.start_timestamp,
            "events": len(self.events),
        }


# --------------------------------------------------------------------- helpers
def _foreign_account(
    profile: CorpusProfile,
    rng: np.random.Generator,
    attacker_host: int,
    *,
    predicate: Callable[[int], bool] | None = None,
) -> int:
    """An account with history elsewhere -- a credential stolen, not local."""
    local = set(profile.users_by_source_host.get(attacker_host, ()))
    for _ in range(256):
        user = profile.sample_user(rng)
        if user not in local and (predicate is None or predicate(user)):
            return user
    raise RuntimeError("could not find a suitable foreign account")


def _local_account(profile: CorpusProfile, rng: np.random.Generator, attacker_host: int) -> int:
    accounts = profile.users_by_source_host.get(attacker_host)
    if not accounts:
        raise ValueError(f"host {attacker_host} has no profiled accounts")
    return int(rng.choice(accounts))


def _usual(profile: CorpusProfile, rng: np.random.Generator, user: int) -> BenignTuple:
    return profile.sample_behaviour(user, rng)


def _novel_destination(
    profile: CorpusProfile, rng: np.random.Generator, user: int, used: set[int]
) -> int:
    destination = profile.sample_destination(
        rng, exclude=used | profile.user_destinations.get(user, set())
    )
    used.add(destination)
    return destination


def _at_hour(timestamp: int, hour: int) -> int:
    """Move a timestamp to the next occurrence of ``hour`` o'clock."""
    day_start = timestamp - timestamp % SECONDS_PER_DAY
    candidate = day_start + hour * 3_600
    return candidate if candidate > timestamp else candidate + SECONDS_PER_DAY


# ------------------------------------------------------------------- scenarios
def password_guessing(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    failures: int = 12,
    spacing: int = 8,
) -> TechniqueScenario:
    """T1110.001 Password Guessing.

    ATT&CK: "Adversaries with no prior knowledge of legitimate credentials may
    guess passwords... repetitive or iterative attempts." Observable as a run
    of failed authentications for one account against one service, then a
    success once a guess lands. The account is someone else's; the attempts
    come from the compromised workstation.
    """
    user = _foreign_account(profile, rng, attacker_host)
    behaviour = _usual(profile, rng, user)
    target = behaviour[2]  # where this account really authenticates
    events = []
    t = start
    for _ in range(failures):
        events.append(
            _event(
                0,
                t,
                user,
                (
                    behaviour[0],
                    attacker_host,
                    target,
                    behaviour[3],
                    ids.logon_network,
                    ids.orientation_logon,
                    0,
                ),
                src_host=attacker_host,
                dst_host=target,
                label=1,
            )
        )
        t += max(1, int(rng.integers(spacing // 2, spacing * 2)))
    events.append(
        _event(
            0,
            t,
            user,
            (
                behaviour[0],
                attacker_host,
                target,
                behaviour[3],
                ids.logon_network,
                ids.orientation_logon,
                1,
            ),
            src_host=attacker_host,
            dst_host=target,
            label=1,
        )
    )
    return TechniqueScenario(scenario_id, "T1110", attacker_host, start, tuple(events))


def password_spraying(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    accounts: int = 15,
    spacing: int = 20,
) -> TechniqueScenario:
    """T1110.003 Password Spraying.

    ATT&CK: "a single or small list of commonly used passwords against many
    different accounts" to stay under lockout thresholds. One or two failures
    per account, many accounts, one source, one authentication service, and
    finally a success on whichever account used the sprayed password.
    """
    used_accounts: set[int] = set()
    events = []
    t = start
    target: int | None = None
    for _ in range(accounts):
        user = _foreign_account(
            profile, rng, attacker_host, predicate=lambda u: u not in used_accounts
        )
        used_accounts.add(user)
        behaviour = _usual(profile, rng, user)
        target = target or behaviour[2]
        for _ in range(int(rng.integers(1, 3))):
            events.append(
                _event(
                    0,
                    t,
                    user,
                    (
                        behaviour[0],
                        attacker_host,
                        target,
                        behaviour[3],
                        ids.logon_network,
                        ids.orientation_logon,
                        0,
                    ),
                    src_host=attacker_host,
                    dst_host=target,
                    label=1,
                )
            )
            t += max(1, int(rng.integers(spacing // 2, spacing * 2)))
    lucky = int(rng.choice(sorted(used_accounts)))
    behaviour = _usual(profile, rng, lucky)
    assert target is not None  # at least one account was sprayed
    events.append(
        _event(
            0,
            t,
            lucky,
            (
                behaviour[0],
                attacker_host,
                target,
                behaviour[3],
                ids.logon_network,
                ids.orientation_logon,
                1,
            ),
            src_host=attacker_host,
            dst_host=target,
            label=1,
        )
    )
    return TechniqueScenario(scenario_id, "T1110", attacker_host, start, tuple(events))


def remote_system_discovery(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    targets: int = 24,
    spacing: int = 6,
    kerberos: bool = True,
) -> TechniqueScenario:
    """T1018 Remote System Discovery / T1087.002 Domain Account Discovery.

    ATT&CK: "Adversaries may attempt to get a listing of other systems...
    to identify potential lateral movement targets" -- tooling like
    ``net view`` or SMB session enumeration touches many hosts in quick
    succession from the foothold, under the foothold's own account. In a
    Kerberos estate that is a burst of service-ticket requests to hosts the
    account has never contacted. Labelled T1087, the catalogue's discovery id.
    """
    user = _local_account(profile, rng, attacker_host)
    behaviour = _usual(profile, rng, user)
    used: set[int] = {attacker_host}
    events = []
    t = start
    orientation = ids.orientation_tgs if kerberos else ids.orientation_logon
    auth = ids.auth_kerberos if kerberos else behaviour[3]
    for _ in range(targets):
        destination = _novel_destination(profile, rng, user, used)
        events.append(
            _event(
                0,
                t,
                user,
                (behaviour[0], attacker_host, destination, auth, ids.logon_network, orientation, 1),
                src_host=attacker_host,
                dst_host=destination,
                label=1,
            )
        )
        t += max(1, int(rng.integers(1, spacing * 2)))
    return TechniqueScenario(scenario_id, "T1087", attacker_host, start, tuple(events))


def valid_account_abuse(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    logons: int = 3,
    spacing: int = 1_200,
) -> TechniqueScenario:
    """T1078 Valid Accounts.

    ATT&CK: "Adversaries may obtain and abuse credentials of existing
    accounts... to blend in with normal traffic." The credential is real, the
    logon succeeds first time, nothing is brute-forced. What is wrong is the
    context: the account is used from a workstation it does not live on, to
    hosts its owner does not visit, in the small hours. A few logons, spread
    out -- an attacker with a valid credential has no reason to hurry.
    """
    user = _foreign_account(profile, rng, attacker_host)
    behaviour = _usual(profile, rng, user)
    used: set[int] = {attacker_host}
    events = []
    t = _at_hour(start, int(rng.integers(2, 5)))
    for _ in range(logons):
        destination = _novel_destination(profile, rng, user, used)
        events.append(
            _event(
                0,
                t,
                user,
                (*behaviour[:6], 1),
                src_host=attacker_host,
                dst_host=destination,
                label=1,
            )
        )
        t += max(60, int(rng.integers(spacing // 2, spacing * 2)))
    return TechniqueScenario(
        scenario_id, "T1078", attacker_host, t if not events else events[0].timestamp, tuple(events)
    )


def pass_the_ticket(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    requests: int = 4,
    spacing: int = 90,
) -> TechniqueScenario:
    """T1550.003 Pass the Ticket.

    ATT&CK: "Adversaries may 'pass the ticket' using stolen Kerberos tickets
    to move laterally... bypassing normal system access controls." A stolen
    service ticket is presented directly: the host asks for service tickets
    for an account without that account ever having authenticated (obtained a
    TGT) from that host. So: TGS requests only, no TGT, for a foreign account
    that does use Kerberos, against hosts the account never reaches.
    """

    def uses_kerberos(user: int) -> bool:
        return any(row[5] == ids.orientation_tgt for row in profile.user_profiles[user])

    user = _foreign_account(profile, rng, attacker_host, predicate=uses_kerberos)
    behaviour = _usual(profile, rng, user)
    used: set[int] = {attacker_host}
    events = []
    t = start
    for _ in range(requests):
        destination = _novel_destination(profile, rng, user, used)
        events.append(
            _event(
                0,
                t,
                user,
                (
                    behaviour[0],
                    attacker_host,
                    destination,
                    ids.auth_kerberos,
                    ids.logon_network,
                    ids.orientation_tgs,
                    1,
                ),
                src_host=attacker_host,
                dst_host=destination,
                label=1,
            )
        )
        t += max(1, int(rng.integers(spacing // 2, spacing * 2)))
    return TechniqueScenario(scenario_id, "T1550.003", attacker_host, start, tuple(events))


def pass_the_hash(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    logons: int = 4,
    spacing: int = 120,
) -> TechniqueScenario:
    """T1550.002 Pass the Hash.

    ATT&CK: "Adversaries may 'pass the hash' using stolen password hashes...
    In this technique, valid password hashes for the account are captured...
    and used to authenticate." A hash authenticates over NTLM, so in an
    estate that normally speaks Kerberos, a Kerberos-using account suddenly
    authenticates by NTLM from a foreign workstation to hosts it never
    reaches -- successfully, because the hash is valid.
    """

    def uses_kerberos(user: int) -> bool:
        return any(row[3] == ids.auth_kerberos for row in profile.user_profiles[user])

    user = _foreign_account(profile, rng, attacker_host, predicate=uses_kerberos)
    behaviour = _usual(profile, rng, user)
    used: set[int] = {attacker_host}
    events = []
    t = start
    for _ in range(logons):
        destination = _novel_destination(profile, rng, user, used)
        events.append(
            _event(
                0,
                t,
                user,
                (
                    behaviour[0],
                    attacker_host,
                    destination,
                    ids.auth_ntlm,
                    ids.logon_network,
                    ids.orientation_logon,
                    1,
                ),
                src_host=attacker_host,
                dst_host=destination,
                label=1,
            )
        )
        t += max(1, int(rng.integers(spacing // 2, spacing * 2)))
    return TechniqueScenario(scenario_id, "T1550.002", attacker_host, start, tuple(events))


def machine_account_misuse(
    profile: CorpusProfile,
    rng: np.random.Generator,
    ids: CategoryIds,
    *,
    scenario_id: str,
    start: int,
    attacker_host: int,
    machine_accounts: Sequence[int],
    logons: int = 3,
    spacing: int = 300,
) -> TechniqueScenario:
    """T1078.002 Domain Accounts -- machine account variant.

    A computer account (``HOST$``) exists so a machine can authenticate as
    itself; it is never used by a person. ATT&CK notes such accounts "may be
    used by adversaries for persistence and lateral movement" precisely
    because monitoring tends to ignore them. The observable is a machine
    account performing the kind of logon only a person performs -- interactive
    -- from a workstation, to hosts it has no business with.
    """
    candidates = [m for m in machine_accounts if m in profile.user_profiles]
    if not candidates:
        raise ValueError("no profiled machine accounts to misuse")
    user = int(rng.choice(candidates))
    behaviour = _usual(profile, rng, user)
    used: set[int] = {attacker_host}
    events = []
    t = start
    for _ in range(logons):
        destination = _novel_destination(profile, rng, user, used)
        logon = ids.logon_remote_interactive if rng.random() < 0.5 else ids.logon_interactive
        events.append(
            _event(
                0,
                t,
                user,
                (
                    behaviour[0],
                    attacker_host,
                    destination,
                    behaviour[3],
                    logon,
                    ids.orientation_logon,
                    1,
                ),
                src_host=attacker_host,
                dst_host=destination,
                label=1,
            )
        )
        t += max(1, int(rng.integers(spacing // 2, spacing * 2)))
    return TechniqueScenario(scenario_id, "T1078.002", attacker_host, start, tuple(events))


#: Every scenario builder, keyed by the technique it exercises. Two builders
#: share T1110 because guessing and spraying are distinct behaviours under
#: one technique, and a rule tuned for one can miss the other.
SCENARIOS: dict[str, tuple[Callable[..., TechniqueScenario], ...]] = {
    "T1110": (password_guessing, password_spraying),
    "T1087": (remote_system_discovery,),
    "T1078": (valid_account_abuse,),
    "T1550.003": (pass_the_ticket,),
    "T1550.002": (pass_the_hash,),
    "T1078.002": (machine_account_misuse,),
}
