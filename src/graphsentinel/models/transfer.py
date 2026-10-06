"""A temporal graph network that learns without attack labels and carries nothing
from one organisation to the next except how authentication behaves.

The first GraphSentinel model was trained on LANL's red-team labels, read a
frozen LANL entity dictionary and LANL-specific category ids, and standardised
its inputs with LANL statistics. Every one of those ties it to one estate: on
LANL its test score rested on one attacker host (0.821 -> 0.002 without it),
and on an unseen lab network it alerted on 2 of 21 attacks.

This model removes each tie.

* **No labels.** It is trained self-supervised to tell real authentications
  from counterfactual ones -- the same account and time with another source or
  destination host -- so it learns what *plausible* movement looks like and
  scores implausible movement as anomalous. Nothing about any particular
  campaign can be memorised because no campaign is ever shown to it.
* **No identities.** Node memory is state, indexed by a table that grows as
  entities appear; there are no per-entity parameters and no dictionary to
  overflow into shared buckets.
* **No dataset accidents.** Event types enter as canonical one-hots
  (:mod:`graphsentinel.features.canonical`); count features are log-scaled and
  standardised with the *deploying* organisation's own statistics
  (:class:`FeatureScaler`), estimated on its unlabelled warm-up traffic.

Scoring follows the score-before-update contract of the first model: within a
time bucket every event is scored against memory from before the bucket, then
all of the bucket's events update the memories of the account, the source and
the destination.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
from torch import Tensor, nn

from graphsentinel.features.canonical import CATEGORICAL_WIDTH
from graphsentinel.models.tgn import AttentionMessageAggregator, HarmonicTimeEncoder

#: Numeric inputs, in order. The engine's categorical ids and ``success`` are
#: excluded: event types enter through the canonical one-hot block instead.
NUMERIC_FEATURES = (
    "hour_sin",
    "hour_cos",
    "delta_user_log",
    "delta_pair_log",
    "user_seen_before",
    "pair_seen_before",
    "is_new_pair",
    "pair_frequency_1h",
    "pair_rarity",
    "user_unique_dst_5m",
    "user_unique_dst_1h",
    "user_unique_dst_24h",
    "user_auth_rate_5m",
    "user_failure_rate_15m",
    "failures_before_success_15m",
    "user_new_dst_ratio_1h",
    "src_host_unique_dst_1h",
    "dst_inbound_users_1h",
    "destination_novelty",
    "user_historical_degree",
    "src_host_historical_degree",
    "dst_historical_degree",
    "rare_logon_score",
    "user_src_seen_before",
    "src_dst_seen_before",
    "src_host_unique_users_1h",
)
#: Counts whose scale depends on the estate's size and activity: log-scaled
#: before standardisation so an estate ten times larger is a shift, not a stretch.
LOG_FEATURES = frozenset(
    {
        "pair_frequency_1h",
        "user_unique_dst_5m",
        "user_unique_dst_1h",
        "user_unique_dst_24h",
        "user_auth_rate_5m",
        "failures_before_success_15m",
        "src_host_unique_dst_1h",
        "dst_inbound_users_1h",
        "user_historical_degree",
        "src_host_historical_degree",
        "dst_historical_degree",
        "src_host_unique_users_1h",
    }
)
#: Seconds used as "time since last seen" for an entity never seen before, so a
#: new entity looks the same in every estate instead of depending on the epoch.
NEVER_SEEN_SECONDS = 30 * 86_400


@dataclass
class FeatureScaler:
    """Per-organisation standardisation, fitted on that organisation's own
    unlabelled traffic (warm-up). Log-scales the count features first."""

    center: np.ndarray
    scale: np.ndarray

    @staticmethod
    def _prepare(columns: dict[str, np.ndarray]) -> np.ndarray:
        stacked = np.stack(
            [
                np.log1p(np.maximum(columns[name].astype(np.float64), 0))
                if name in LOG_FEATURES
                else columns[name].astype(np.float64)
                for name in NUMERIC_FEATURES
            ],
            axis=1,
        )
        return stacked

    @classmethod
    def fit(cls, columns: dict[str, np.ndarray]) -> FeatureScaler:
        x = cls._prepare(columns)
        center = x.mean(axis=0)
        scale = x.std(axis=0)
        scale[scale < 1e-6] = 1.0
        return cls(center=center.astype(np.float32), scale=scale.astype(np.float32))

    def transform(self, columns: dict[str, np.ndarray]) -> np.ndarray:
        x = (self._prepare(columns) - self.center) / self.scale
        return np.clip(x, -8, 8).astype(np.float32)

    def to_dict(self) -> dict[str, Any]:
        return {"features": list(NUMERIC_FEATURES), "center": self.center.tolist(), "scale": self.scale.tolist()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeatureScaler:
        if list(data["features"]) != list(NUMERIC_FEATURES):
            raise ValueError("scaler was fitted for a different feature list")
        return cls(center=np.asarray(data["center"], np.float32), scale=np.asarray(data["scale"], np.float32))


@dataclass
class MemoryState:
    """Node memory and last-activity time; grows as entities appear."""

    memory: Tensor
    last_update: Tensor  # int64, -1 = never seen

    @classmethod
    def initial(cls, num_nodes: int, memory_dim: int, device: torch.device | str) -> MemoryState:
        return cls(
            memory=torch.zeros(num_nodes, memory_dim, device=device),
            last_update=torch.full((num_nodes,), -1, dtype=torch.long, device=device),
        )

    def ensure(self, num_nodes: int) -> MemoryState:
        n = self.memory.shape[0]
        if num_nodes <= n:
            return self
        extra = max(num_nodes - n, n // 2)
        return MemoryState(
            memory=torch.cat((self.memory, self.memory.new_zeros(extra, self.memory.shape[1]))),
            last_update=torch.cat((self.last_update, self.last_update.new_full((extra,), -1))),
        )

    def detach(self) -> MemoryState:
        return MemoryState(self.memory.detach(), self.last_update)


class TransferTGN(nn.Module):
    """Self-supervised plausibility model over (account, source, destination)."""

    def __init__(
        self,
        *,
        feature_dim: int = len(NUMERIC_FEATURES),
        category_dim: int = CATEGORICAL_WIDTH,
        memory_dim: int = 64,
        time_dim: int = 16,
        hidden_dim: int = 128,
        dropout: float = 0.1,
        use_memory: bool = True,
        use_features: bool = True,
    ) -> None:
        super().__init__()
        self.feature_dim = feature_dim
        self.category_dim = category_dim
        self.memory_dim = memory_dim
        self.time_dim = time_dim
        self.hidden_dim = hidden_dim
        self.dropout = dropout
        #: Ablations: memory off reads zeros for every node memory; features off
        #: reads zeros for the numeric features. Together they attribute a
        #: result to the graph memory or to the hand-built features.
        self.use_memory = use_memory
        self.use_features = use_features
        self.time_encoder = HarmonicTimeEncoder(time_dim)
        message_in = 3 * memory_dim + category_dim + time_dim + 3
        self.message_function = nn.Sequential(
            nn.Linear(message_in, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Linear(hidden_dim, memory_dim),
        )
        self.aggregator = AttentionMessageAggregator(memory_dim, memory_dim)
        self.pre_gru_norm = nn.LayerNorm(memory_dim)
        self.memory_updater = nn.GRUCell(memory_dim, memory_dim)
        score_in = 3 * memory_dim + feature_dim + category_dim + 3 * time_dim
        self.score_proj = nn.Linear(score_in, hidden_dim, bias=False)
        self.scorer = nn.Sequential(
            nn.Linear(score_in, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.GELU(),
        )
        self.head = nn.Linear(hidden_dim, 1)

    # ------------------------------------------------------------------ helpers
    def _elapsed(self, state: MemoryState, nodes: Tensor, t: Tensor) -> Tensor:
        last = state.last_update[nodes]
        delta = torch.where(last < 0, torch.full_like(t, NEVER_SEEN_SECONDS), (t - last).clamp_min(0))
        return self.time_encoder(delta)

    def score(
        self,
        state: MemoryState,
        user: Tensor,
        src: Tensor,
        dst: Tensor,
        t: Tensor,
        features: Tensor,
        categories: Tensor,
    ) -> Tensor:
        """Plausibility logits (higher = more like real traffic). Never mutates state."""
        mem = state.memory
        mu, ms, md = mem[user], mem[src], mem[dst]
        if not self.use_memory:
            mu, ms, md = torch.zeros_like(mu), torch.zeros_like(ms), torch.zeros_like(md)
        if not self.use_features:
            features = torch.zeros_like(features)
        inputs = torch.cat(
            (
                mu, ms, md, features, categories,
                self._elapsed(state, user, t), self._elapsed(state, src, t), self._elapsed(state, dst, t),
            ),
            dim=1,
        )
        hidden = self.scorer(inputs) + self.score_proj(inputs)
        return self.head(hidden).squeeze(-1)

    def update(
        self, state: MemoryState, user: Tensor, src: Tensor, dst: Tensor, t: Tensor, categories: Tensor
    ) -> MemoryState:
        """Fold one bucket of real events into the memories of all three endpoints."""
        mem = state.memory
        mu, ms, md = mem[user], mem[src], mem[dst]
        n = len(user)
        roles = torch.eye(3, device=mem.device, dtype=mem.dtype)
        parts = []
        for own, a, b, nodes, role in ((mu, ms, md, user, 0), (ms, mu, md, src, 1), (md, mu, ms, dst, 2)):
            parts.append(
                torch.cat(
                    (own, a, b, categories, self._elapsed(state, nodes, t), roles[role].expand(n, 3)), dim=1
                )
            )
        messages = self.message_function(torch.cat(parts))
        nodes = torch.cat((user, src, dst))
        unique_nodes, inverse = torch.unique(nodes, sorted=True, return_inverse=True)
        aggregated = self.aggregator(unique_nodes, inverse, messages, mem)
        updated = self.memory_updater(self.pre_gru_norm(aggregated), mem[unique_nodes])
        latest = torch.full((len(unique_nodes),), -1, dtype=torch.long, device=mem.device)
        latest = latest.scatter_reduce(0, inverse, torch.cat((t, t, t)), reduce="amax", include_self=True)
        return MemoryState(
            memory=mem.index_copy(0, unique_nodes, updated),
            last_update=state.last_update.index_copy(0, unique_nodes, latest),
        )

    def configuration(self) -> dict[str, Any]:
        return {
            "feature_dim": self.feature_dim,
            "category_dim": self.category_dim,
            "memory_dim": self.memory_dim,
            "time_dim": self.time_dim,
            "hidden_dim": self.hidden_dim,
            "dropout": self.dropout,
            "use_memory": self.use_memory,
            "use_features": self.use_features,
        }


def anomaly_from_logits(logits: Tensor) -> Tensor:
    """Plausibility logit -> anomaly in [0, 1] (1 = implausible)."""
    return torch.sigmoid(-logits)
