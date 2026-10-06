"""The served transfer model must reproduce the offline (evaluated) scores exactly."""

from __future__ import annotations

import numpy as np
import pytest
import torch

from graphsentinel.features.canonical import one_hot
from graphsentinel.models.serving import InferenceEvent
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler, MemoryState, TransferTGN
from graphsentinel.models.transfer_serving import (
    MESSAGE_WIDTH,
    DeploymentProfile,
    TransferInferenceSession,
    TransferProvenance,
)

BUCKET = 60


def _events(seed: int, n: int) -> list[InferenceEvent]:
    rng = np.random.default_rng(seed)
    t = np.sort(rng.integers(0, 600, n)) + 1_700_000_000
    events = []
    for i in range(n):
        numeric = rng.normal(size=len(NUMERIC_FEATURES)).round(3).tolist()
        codes = [int(rng.integers(0, 4)), int(rng.integers(0, 5)), int(rng.integers(0, 5)), int(rng.integers(0, 2))]
        events.append(
            InferenceEvent(
                event_id=i, timestamp=int(t[i]), user_id=int(rng.integers(0, 7)),
                source_host_id=int(rng.integers(0, 9)), destination_host_id=int(rng.integers(0, 9)),
                message=tuple(float(v) for v in numeric + codes),
            )
        )
    return events


def _scaler() -> FeatureScaler:
    return FeatureScaler(center=np.zeros(len(NUMERIC_FEATURES), np.float32), scale=np.ones(len(NUMERIC_FEATURES), np.float32))


def _offline(model: TransferTGN, scaler: FeatureScaler, events: list[InferenceEvent]) -> np.ndarray:
    """The evaluation's order: per bucket, score against memory before it, then fold it."""
    nodes: dict[tuple[str, int], int] = {}

    def node(kind: str, ident: int) -> int:
        return nodes.setdefault((kind, ident), len(nodes))

    u, s, d = [], [], []
    for e in events:  # assign in arrival order, as the session does
        u.append(node("u", e.user_id))
        s.append(node("h", e.source_host_id))
        d.append(node("h", e.destination_host_id))
    msg = np.asarray([e.message for e in events])
    x = torch.from_numpy(scaler.transform({n: msg[:, k] for k, n in enumerate(NUMERIC_FEATURES)}))
    codes = msg[:, len(NUMERIC_FEATURES):].astype(np.int64)
    cats = torch.from_numpy(one_hot(codes[:, 0], codes[:, 1], codes[:, 2], codes[:, 3]))
    t = torch.tensor([e.timestamp for e in events])
    ut, st, dt = torch.tensor(u), torch.tensor(s), torch.tensor(d)
    state = MemoryState.initial(len(nodes), model.memory_dim, "cpu")
    buckets = np.array([e.timestamp // BUCKET for e in events])
    edges = np.concatenate(([0], np.flatnonzero(np.diff(buckets)) + 1, [len(events)]))
    out = []
    with torch.inference_mode():
        for b in range(len(edges) - 1):
            i0, i1 = int(edges[b]), int(edges[b + 1])
            out.append(torch.sigmoid(-model.score(state, ut[i0:i1], st[i0:i1], dt[i0:i1], t[i0:i1], x[i0:i1], cats[i0:i1])))
            state = model.update(state, ut[i0:i1], st[i0:i1], dt[i0:i1], t[i0:i1], cats[i0:i1])
    return torch.cat(out).numpy()


def _session(model: TransferTGN, profile: DeploymentProfile | None = None) -> TransferInferenceSession:
    return TransferInferenceSession(
        model=model, scaler=_scaler(), bucket_seconds=BUCKET,
        provenance=TransferProvenance(model_version="test", checkpoint_sha256="0" * 64), profile=profile,
    )


@pytest.mark.parametrize("batch", [1, 7, 50, 400])
def test_served_scores_equal_offline_scores(batch: int) -> None:
    torch.manual_seed(0)
    model = TransferTGN(memory_dim=16, time_dim=8, hidden_dim=32).eval()
    events = _events(3, 400)
    expected = _offline(model, _scaler(), events)
    session = _session(model)
    got: list[float] = []
    for lo in range(0, len(events), batch):
        preview = session.preview(events[lo: lo + batch])
        session.commit(preview)
        got.extend(preview.anomalies)
    np.testing.assert_allclose(np.asarray(got), expected, rtol=1e-5, atol=1e-6)


def test_percentiles_come_from_the_estate_profile() -> None:
    torch.manual_seed(0)
    model = TransferTGN(memory_dim=16, time_dim=8, hidden_dim=32).eval()
    profile = DeploymentProfile(scaler=_scaler(), reference=np.linspace(0, 1, 101), warmup_events=101)
    session = _session(model, profile)
    preview = session.preview(_events(5, 20))
    for anomaly, probability in zip(preview.anomalies, preview.probabilities, strict=True):
        percentile = float(np.searchsorted(profile.reference, anomaly, "right")) / 101
        assert probability == pytest.approx(float(profile.risk(np.array([percentile]))[0]))


def test_budgets_land_on_the_product_thresholds() -> None:
    from graphsentinel.detection.gates import AUTO_EXECUTE_THRESHOLD
    from graphsentinel.models.transfer_serving import ALERT_RISK

    profile = DeploymentProfile(scaler=_scaler(), reference=np.linspace(0, 1, 11), warmup_events=11,
                                alert_budget=1e-3, action_budget=1e-5)
    risk = profile.risk(np.array([0.0, 1 - 1e-3, 1 - 1e-5, 1.0]))
    np.testing.assert_allclose(risk, [0.0, ALERT_RISK, AUTO_EXECUTE_THRESHOLD, 1.0])
    assert np.all(np.diff(profile.risk(np.linspace(0, 1, 1001))) >= 0)


def test_stale_preview_is_refused_and_state_survives_a_restart(tmp_path) -> None:  # type: ignore[no-untyped-def]
    torch.manual_seed(0)
    model = TransferTGN(memory_dim=16, time_dim=8, hidden_dim=32).eval()
    events = _events(9, 120)
    session = _session(model)
    session.commit(session.preview(events[:60]))
    stale = session.preview(events[60:90])
    session.commit(session.preview(events[60:90]))
    with pytest.raises(RuntimeError, match="stale"):
        session.commit(stale)
    session.save_memory(tmp_path / "memory.pt")
    restored = _session(model)
    restored.load_memory(tmp_path / "memory.pt")
    a = session.preview(events[90:]).anomalies
    b = restored.preview(events[90:]).anomalies
    np.testing.assert_allclose(a, b, rtol=1e-6)


def test_message_width_is_enforced() -> None:
    model = TransferTGN(memory_dim=16, time_dim=8, hidden_dim=32).eval()
    session = _session(model)
    bad = InferenceEvent(event_id=0, timestamp=1, user_id=0, source_host_id=0, destination_host_id=1, message=(0.0,))
    with pytest.raises(ValueError, match=str(MESSAGE_WIDTH)):
        session.preview([bad])


def test_ensemble_risk_is_the_percentile_of_the_mean_of_member_percentiles() -> None:
    from graphsentinel.models.companions import combine, fit_isolation_forest, isolation_score, rarity_score

    torch.manual_seed(0)
    model = TransferTGN(memory_dim=16, time_dim=8, hidden_dim=32).eval()
    warm = _events(21, 300)
    msg = np.asarray([e.message for e in warm])
    numeric = {n: msg[:, k] for k, n in enumerate(NUMERIC_FEATURES)}
    codes = msg[:, len(NUMERIC_FEATURES):].astype(np.int64)
    xm = np.concatenate([_scaler().transform(numeric), one_hot(codes[:, 0], codes[:, 1], codes[:, 2], codes[:, 3])], 1)
    forest = fit_isolation_forest(xm, seed=1)
    refs = {"rarity": np.sort(rarity_score(numeric)), "iforest": np.sort(isolation_score(forest, xm))}
    tgn_ref = np.linspace(0, 1, 301)
    profile = DeploymentProfile(
        scaler=_scaler(), reference=tgn_ref, warmup_events=300, alert_budget=0.05, action_budget=0.01,
        companion_references=refs, combined_reference=np.linspace(0, 1, 301), forest_file="f", forest_sha256="x")
    session = TransferInferenceSession(
        model=model, scaler=_scaler(), bucket_seconds=BUCKET,
        provenance=TransferProvenance(model_version="test", checkpoint_sha256="0" * 64),
        profile=profile, forest=forest)
    events = _events(22, 40)
    preview = session.preview(events)
    m = np.asarray([e.message for e in events])
    num = {n: m[:, k] for k, n in enumerate(NUMERIC_FEATURES)}
    c = m[:, len(NUMERIC_FEATURES):].astype(np.int64)
    x2 = np.concatenate([_scaler().transform(num), one_hot(c[:, 0], c[:, 1], c[:, 2], c[:, 3])], 1)
    pct = {
        "tgn": profile.percentile(np.asarray(preview.anomalies)),
        "rarity": np.searchsorted(refs["rarity"], rarity_score(num), "right") / 300,
        "iforest": np.searchsorted(refs["iforest"], isolation_score(forest, x2), "right") / 300,
    }
    expected = profile.risk(np.searchsorted(profile.combined_reference, combine(pct), "right") / 301)
    np.testing.assert_allclose(preview.probabilities, expected, rtol=1e-6, atol=1e-9)
