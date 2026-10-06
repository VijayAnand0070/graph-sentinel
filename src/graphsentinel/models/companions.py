"""Label-free companion detectors served beside the temporal graph network.

On LANL the temporal graph network alone did not hold up on the untouched
final window, while two simple label-free detectors ranked attack events well:
a rarity score read from the causal features, and an isolation forest fitted on
the estate's own traffic. Averaging the three percentiles -- each read against
the estate's warm-up traffic -- was the best of 81 label-free combinations on
the development window (average precision 0.0136 against 0.0017 for the network
alone) and caught three times as many attack-days as the network on the final
window. The served risk is the percentile of that average.

The isolation forest is fitted during onboarding on the estate's own
standardised features, without labels. It is stored with its SHA-256 digest
recorded in the deployment profile, and is loaded only if the file still
matches it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np

#: members of the served combination, in order
ENSEMBLE_MEMBERS: tuple[str, ...] = ("tgn", "rarity", "iforest")
RARITY_FEATURES = ("pair_rarity", "is_new_pair", "destination_novelty", "user_new_dst_ratio_1h")


def rarity_score(numeric: Mapping[str, np.ndarray]) -> np.ndarray:
    """How rare the account-to-destination move is (the evaluation's rarity detector)."""
    return np.minimum(
        1.0,
        0.5 * numeric["pair_rarity"]
        + 0.25 * numeric["is_new_pair"]
        + 0.15 * numeric["destination_novelty"]
        + 0.10 * np.minimum(numeric["user_new_dst_ratio_1h"], 1.0),
    ).astype(np.float64)


def fit_isolation_forest(x: np.ndarray, *, seed: int = 1729, max_samples: int = 200_000) -> Any:
    """Fit on the estate's own (unlabelled) standardised features and one-hot categories."""
    from sklearn.ensemble import IsolationForest

    rng = np.random.default_rng(seed)
    sample = x if len(x) <= max_samples else x[rng.choice(len(x), max_samples, replace=False)]
    return IsolationForest(n_estimators=100, random_state=seed, n_jobs=-1).fit(sample)


def isolation_score(model: Any, x: np.ndarray) -> np.ndarray:
    """Higher means more isolated (more unusual)."""
    return (-model.score_samples(x)).astype(np.float64)


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save_forest(model: Any, path: Path) -> str:
    import joblib

    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    return file_digest(path)


def load_forest(path: Path, expected_sha256: str) -> Any:
    """Load the onboarding forest only if it is the file onboarding wrote."""
    import joblib

    if not path.is_file():
        raise FileNotFoundError(path)
    actual = file_digest(path)
    if actual != expected_sha256:
        raise ValueError(f"isolation forest {path} does not match the deployment profile (sha256 {actual[:12]})")
    return joblib.load(path)


def combine(percentiles: Mapping[str, np.ndarray], members: tuple[str, ...] = ENSEMBLE_MEMBERS) -> np.ndarray:
    return np.mean(np.stack([np.asarray(percentiles[m], dtype=np.float64) for m in members]), axis=0)


__all__ = [
    "ENSEMBLE_MEMBERS",
    "RARITY_FEATURES",
    "combine",
    "file_digest",
    "fit_isolation_forest",
    "isolation_score",
    "load_forest",
    "rarity_score",
    "save_forest",
]
