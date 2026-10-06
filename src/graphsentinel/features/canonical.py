"""Organisation-independent encodings of authentication event types.

The first model read ``auth_type_id``, ``logon_type_id`` and ``orientation_id``
as numbers. Those ids are the order in which one ingest happened to meet each
string: LANL's ``Negotiate`` is 7 because it was the seventh auth type seen,
while another estate's Windows adapter emits ``Kerberos`` / ``NTLM`` in a
different order, or strings LANL never had. A model that reads the id reads
an accident of one dataset, and nothing it learns about "7" means anything
elsewhere.

These map every spelling the adapters produce onto a small fixed vocabulary
that means the same thing in every estate, and encode it one-hot.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

AUTH_CATEGORIES = ("kerberos", "ntlm", "negotiate", "other")
LOGON_CATEGORIES = ("network", "interactive", "remote_interactive", "service_batch", "other")
ORIENTATION_CATEGORIES = ("logon", "tgs", "tgt", "authmap", "other")
#: Width of the one-hot block: the three vocabularies plus the success bit.
CATEGORICAL_WIDTH = len(AUTH_CATEGORIES) + len(LOGON_CATEGORIES) + len(ORIENTATION_CATEGORIES) + 1


def canonical_auth(value: str) -> str:
    v = (value or "").strip().casefold()
    if "kerberos" in v:
        return "kerberos"
    if "ntlm" in v or v.startswith("microsoft_authentication") or v in {"msv1_0", "msv"}:
        return "ntlm"
    if "negotiate" in v:
        return "negotiate"
    return "other"


_LOGON = {
    "network": "network", "networkcleartext": "network", "3": "network", "8": "network",
    "interactive": "interactive", "cachedinteractive": "interactive", "unlock": "interactive",
    "2": "interactive", "7": "interactive", "11": "interactive",
    "remoteinteractive": "remote_interactive", "10": "remote_interactive",
    "service": "service_batch", "batch": "service_batch", "4": "service_batch", "5": "service_batch",
}


def canonical_logon(value: str) -> str:
    v = (value or "").strip().casefold().replace(" ", "").replace("_", "")
    return _LOGON.get(v, "other")


def canonical_orientation(value: str) -> str:
    v = (value or "").strip().casefold()
    return v if v in {"logon", "tgs", "tgt", "authmap"} else "other"


def category_index(values: Sequence[str], kind: str) -> np.ndarray:
    """For an id map's ``values`` list (id -> string), the canonical category
    index of every id."""
    if kind == "auth":
        fn, vocab = canonical_auth, AUTH_CATEGORIES
    elif kind == "logon":
        fn, vocab = canonical_logon, LOGON_CATEGORIES
    elif kind == "orientation":
        fn, vocab = canonical_orientation, ORIENTATION_CATEGORIES
    else:
        raise ValueError(f"unknown category kind {kind!r}")
    return np.array([vocab.index(fn(v)) for v in values], dtype=np.int64)


def one_hot(auth: np.ndarray, logon: np.ndarray, orientation: np.ndarray, success: np.ndarray) -> np.ndarray:
    """Canonical category indices -> the ``CATEGORICAL_WIDTH`` one-hot block."""
    n = len(auth)
    out = np.zeros((n, CATEGORICAL_WIDTH), dtype=np.float32)
    rows = np.arange(n)
    out[rows, auth] = 1
    out[rows, len(AUTH_CATEGORIES) + logon] = 1
    out[rows, len(AUTH_CATEGORIES) + len(LOGON_CATEGORIES) + orientation] = 1
    out[:, -1] = success
    return out
