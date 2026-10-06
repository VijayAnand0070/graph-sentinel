"""Which entity dictionary a synthetic stream was written with.

The synthetic live stream stores integer ids, and a name is only meaningful
through the dictionary that assigned it. The generator writes the stream with
``artifacts/id_maps_lanl_bounded``; the server runs with whatever frozen
dictionary its checkpoint requires (``id_maps_lanl_1m_cuda`` as shipped).
Naming the stream's ids through the serving dictionary renamed every account
and host in the demo -- id 80 is ``U66@DOM1`` in the generator's dictionary
and ``C791$@DOM1`` in the serving one -- so the manifest's ground truth no
longer matched the stream, the console tagged the wrong accounts as attack
chains, and the replayed identities no longer lined up with the warm history
the model holds for them.

The manifest carries its own evidence: every chain records the attacker's id
*and* the name the generator resolved it to. The right dictionary is the one
under which those pairs hold. That test needs no configuration, and it cannot
silently pick a dictionary the stream was not written with.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

GENERATOR_DICTIONARY = Path("artifacts/id_maps_lanl_bounded")

logger = logging.getLogger("graphsentinel.api")


def _users(directory: Path) -> list[str] | None:
    path = directory / "users.json"
    if not path.is_file():
        return None
    try:
        values = json.loads(path.read_text(encoding="utf-8"))["values"]
    except (OSError, ValueError, KeyError):
        return None
    return values if isinstance(values, list) else None


def manifest_agrees(users: list[str], manifest: Mapping[str, Any]) -> bool:
    """True when every chain's (attacker id, attacker name) pair holds."""
    pairs = [
        (chain.get("attacker_user_id"), chain.get("attacker_user_name"))
        for chain in manifest.get("attack_chains", [])
        if isinstance(chain, Mapping)
    ]
    checkable = [(i, n) for i, n in pairs if isinstance(i, int) and isinstance(n, str)]
    if not checkable:
        return False
    return all(0 <= i < len(users) and users[i] == n for i, n in checkable)


def stream_dictionary(
    manifest: Mapping[str, Any] | None,
    candidates: Iterable[Path | None],
) -> tuple[Path | None, str]:
    """The dictionary to name the stream's ids with, and why.

    Order of preference: the directory the manifest declares; then any
    candidate under which the manifest's own id -> name pairs hold; then, if
    nothing can be checked, the first usable candidate -- reported as a guess.
    """
    ordered: list[Path] = []
    if manifest and isinstance(manifest.get("id_map_dir"), str):
        ordered.append(Path(manifest["id_map_dir"]))
    for candidate in candidates:
        if candidate is not None and candidate not in ordered:
            ordered.append(candidate)

    usable = [(d, users) for d in ordered if (users := _users(d)) is not None]
    if not usable:
        return None, "no usable entity dictionary"
    if manifest:
        for directory, users in usable:
            if manifest_agrees(users, manifest):
                return directory, "the manifest's attacker ids resolve to its attacker names"
        logger.warning(
            "No entity dictionary reproduces the synthetic manifest's attacker names; "
            "the stream will be named with %s and its ground truth may not line up.",
            usable[0][0],
        )
        return usable[0][0], "no dictionary reproduces the manifest; first usable one"
    return usable[0][0], "no manifest to check against; first usable one"


__all__ = ["GENERATOR_DICTIONARY", "manifest_agrees", "stream_dictionary"]
