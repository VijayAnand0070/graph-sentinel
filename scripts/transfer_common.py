"""Shared loading for the label-free (transfer) model experiments on the full-rate corpus."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import polars as pl
import torch

from graphsentinel.features.canonical import AUTH_CATEGORIES, CATEGORICAL_WIDTH, LOGON_CATEGORIES, category_index
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler

STREAM_COLUMNS = ["event_id", "timestamp", "user", "src", "dst", "auth_id", "logon_id", "orient_id", "success", "label"]
_LOGON_OFFSET = len(AUTH_CATEGORIES)
_ORIENT_OFFSET = len(AUTH_CATEGORIES) + len(LOGON_CATEGORIES)


def category_maps(id_maps: Path) -> dict[str, np.ndarray]:
    """Raw ingest id -> canonical category index, for auth, logon and orientation."""

    def values(name: str) -> list[str]:
        return list(json.loads((id_maps / f"{name}.json").read_text(encoding="utf-8"))["values"])

    return {
        "auth_id": category_index(values("auth_types"), "auth"),
        "logon_id": category_index(values("logon_types"), "logon"),
        "orient_id": category_index(values("orientations"), "orientation"),
    }


def canonical_codes(frame: pl.DataFrame, maps: dict[str, np.ndarray]) -> np.ndarray:
    """(n, 4) canonical auth, logon, orientation codes and the success bit."""
    return np.stack(
        [maps[c][frame[c].to_numpy().astype(np.int64)] for c in ("auth_id", "logon_id", "orient_id")]
        + [frame["success"].to_numpy().astype(np.int64)],
        axis=1,
    )


def node_offsets(id_maps: Path) -> tuple[int, int]:
    """(number of user ids, number of host ids) -- hosts are indexed after users."""
    users = len(json.loads((id_maps / "users.json").read_text(encoding="utf-8"))["values"])
    hosts = len(json.loads((id_maps / "hosts.json").read_text(encoding="utf-8"))["values"])
    return users, hosts


@dataclass
class DayStream:
    """One day of real events on the device, in stream order."""

    event_id: np.ndarray
    t: torch.Tensor
    user: torch.Tensor
    src: torch.Tensor
    dst: torch.Tensor
    codes: torch.Tensor  # (n, 4): auth, logon, orientation, success
    label: np.ndarray
    bucket_edges: np.ndarray  # index boundaries of time buckets

    def __len__(self) -> int:
        return len(self.event_id)


def load_stream(
    days_dir: Path, day: int, users: int, device: torch.device, bucket_seconds: int, maps: dict[str, np.ndarray]
) -> DayStream:
    frame = pl.read_parquet(days_dir / f"day{day:02d}.parquet", columns=STREAM_COLUMNS)
    t = frame["timestamp"].to_numpy().astype(np.int64)
    bucket = t // bucket_seconds
    edges = np.flatnonzero(np.diff(bucket)) + 1
    edges = np.concatenate(([0], edges, [len(t)]))
    codes = canonical_codes(frame, maps)
    return DayStream(
        event_id=frame["event_id"].to_numpy(),
        t=torch.from_numpy(t).to(device),
        user=torch.from_numpy(frame["user"].to_numpy().astype(np.int64)).to(device),
        src=torch.from_numpy(frame["src"].to_numpy().astype(np.int64) + users).to(device),
        dst=torch.from_numpy(frame["dst"].to_numpy().astype(np.int64) + users).to(device),
        codes=torch.from_numpy(codes).to(device),
        label=frame["label"].to_numpy(),
        bucket_edges=edges,
    )


def one_hot(codes: torch.Tensor) -> torch.Tensor:
    """(n, 4) canonical codes -> (n, CATEGORICAL_WIDTH) float one-hot block."""
    n = codes.shape[0]
    out = torch.zeros(n, CATEGORICAL_WIDTH, device=codes.device)
    rows = torch.arange(n, device=codes.device)
    out[rows, codes[:, 0]] = 1
    out[rows, _LOGON_OFFSET + codes[:, 1]] = 1
    out[rows, _ORIENT_OFFSET + codes[:, 2]] = 1
    out[:, -1] = codes[:, 3].float()
    return out


def read_features(path: Path, columns: list[str] | None = None, filter_ids: np.ndarray | None = None) -> pl.DataFrame:
    frame = pl.read_parquet(path, columns=columns)
    if filter_ids is not None:
        frame = frame.filter(pl.col("event_id").is_in(pl.Series(filter_ids)))
    return frame


def fit_scaler(days_dir: Path, days: list[int], per_day: int, seed: int) -> FeatureScaler:
    """Standardisation from a uniform sample of the estate's own unlabelled events."""
    rng = np.random.default_rng(seed)
    parts = []
    for day in days:
        frame = pl.read_parquet(days_dir / f"day{day:02d}.parquet", columns=list(NUMERIC_FEATURES))
        idx = rng.choice(frame.height, size=min(per_day, frame.height), replace=False)
        parts.append(frame[np.sort(idx)])
    sample = pl.concat(parts)
    return FeatureScaler.fit({c: sample[c].to_numpy() for c in NUMERIC_FEATURES})


def scaled(frame: pl.DataFrame, scaler: FeatureScaler) -> np.ndarray:
    return scaler.transform({c: frame[c].to_numpy() for c in NUMERIC_FEATURES})
