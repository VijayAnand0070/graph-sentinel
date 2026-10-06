"""The label-free transfer model inside the product: a new estate, end to end."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import torch

from graphsentinel.api.live import LiveDetectionEngine
from graphsentinel.api.schemas import LiveAuthBatch, LiveAuthEvent
from graphsentinel.api.service import DetectionService
from graphsentinel.ingestion.auth import NormalizedAuthEvent
from graphsentinel.ingestion.id_map import AuthIdMaps
from graphsentinel.models.transfer import NUMERIC_FEATURES, FeatureScaler, TransferTGN
from graphsentinel.models.transfer_serving import (
    ALERT_RISK,
    PASS_THROUGH_FUSION,
    is_transfer_checkpoint,
    load_transfer_session,
)
from graphsentinel.onboarding.calibrate import run_onboarding


def _checkpoint(path: Path) -> Path:
    torch.manual_seed(0)
    model = TransferTGN(memory_dim=8, time_dim=4, hidden_dim=16)
    scaler = FeatureScaler(center=np.zeros(len(NUMERIC_FEATURES), np.float32), scale=np.ones(len(NUMERIC_FEATURES), np.float32))
    torch.save(
        {
            "model": "TransferTGN", "configuration": model.configuration(), "state_dict": model.state_dict(),
            "scaler": scaler.to_dict(), "users": 0, "hosts": 0, "bucket_seconds": 60, "train_days": [0],
            "val_day": 1, "seed": 0, "epoch": 1, "val_auc": 0.5, "labels_used": False,
        },
        path,
    )
    return path


def _events(n: int = 400, seed: int = 3) -> list[tuple[int, str, str, str]]:
    rng = np.random.default_rng(seed)
    t = np.sort(rng.integers(0, 20_000, n)) + 1_700_000_000
    users = [f"u{i}@corp" for i in range(12)]
    hosts = [f"ws{i:02d}" for i in range(20)]
    out = []
    for i in range(n):
        s, d = rng.choice(len(hosts), 2, replace=False)
        out.append((int(t[i]), users[int(rng.integers(0, len(users)))], hosts[int(s)], hosts[int(d)]))
    return out


def test_a_new_estate_needs_no_dictionary_and_gets_label_free_settings(tmp_path: Path) -> None:
    session = load_transfer_session(_checkpoint(tmp_path / "t.pt"))
    assert is_transfer_checkpoint(tmp_path / "t.pt")
    service = DetectionService(threshold=0.5, model_session=session)
    assert service.model_kind == "transfer" and not service.requires_frozen_dictionary
    assert service.fusion == PASS_THROUGH_FUSION and service.threshold == ALERT_RISK
    live = LiveDetectionEngine(service, id_map_dir=None)
    events = [LiveAuthEvent(timestamp=t, user=u, source_host=s, destination_host=d, success=True,
                            auth_type="Kerberos", logon_type="Network", orientation="LogOn")
              for t, u, s, d in _events(120)]
    last = None
    for t in sorted({e.timestamp for e in events}):
        group = tuple(e for e in events if e.timestamp == t)
        response = live.detect(LiveAuthBatch(events=group))
        assert all(0.0 <= r.risk <= 1.0 for r in response.results)
        last = response
    assert last is not None
    assert session.memory_coverage()["entities_known"] > 20  # entities from the estate, not a dictionary


def test_fan_out_raises_the_risk_to_the_rule_floor(tmp_path: Path) -> None:
    session = load_transfer_session(_checkpoint(tmp_path / "t.pt"))
    service = DetectionService(threshold=0.5, model_session=session)
    live = LiveDetectionEngine(service, id_map_dir=None)
    risks = []
    for k in range(12):  # one beachhead, a new account and a new host every minute
        batch = LiveAuthBatch(events=(LiveAuthEvent(
            timestamp=1_700_000_000 + 60 * k, user=f"stolen{k}@corp", source_host="beachhead",
            destination_host=f"srv{k}", success=True, auth_type="NTLM", logon_type="Network", orientation="LogOn"),))
        risks.append(live.detect(batch).results[0].risk)
    floor = service.chain_rule_floor
    # the default rule needs 8 accounts and 5 novel moves before the hop
    assert all(r >= floor for r in risks[8:]), risks
    assert all(r < floor for r in risks[:5]), risks


def test_onboarding_calibrates_on_the_estates_own_history(tmp_path: Path) -> None:
    maps = AuthIdMaps()
    history = _events(600, seed=11)
    events = []
    for i, (t, u, s, d) in enumerate(history):
        events.append(NormalizedAuthEvent(
            event_id=i, timestamp=t, src_user_id=maps.users.encode(u), dst_user_id=maps.users.encode(u),
            src_host_id=maps.hosts.encode(s), dst_host_id=maps.hosts.encode(d),
            auth_type_id=maps.auth_types.encode("Kerberos"), logon_type_id=maps.logon_types.encode("Network"),
            orientation_id=maps.orientations.encode("LogOn"), success=1, label_redteam=0,
            day=t // 86_400, hour=(t % 86_400) // 3_600,
        ))
    maps.save(tmp_path / "maps")
    ckpt = _checkpoint(tmp_path / "t.pt")
    result = run_onboarding(events, id_maps_dir=tmp_path / "maps", checkpoint=ckpt, output_dir=tmp_path / "out",
                            alert_budget=0.05, action_budget=0.01)
    assert result.events == 600
    session = load_transfer_session(ckpt, profile_path=result.profile_path)
    assert session.calibrated
    assert np.all(np.diff(session.profile.reference) >= 0)  # type: ignore[union-attr]
    coverage = session.load_memory(tmp_path / "out" / "transfer_memory.pt")
    assert coverage["entities_known"] > 20
    # the budget holds on the estate's own history, by construction
    reference = session.profile.reference  # type: ignore[union-attr]
    share = float((session.profile.percentile(reference) > 1 - 0.05).mean())  # type: ignore[union-attr]
    assert share <= 0.05 + 1e-9


def test_onboarding_serves_the_label_free_combination(tmp_path: Path) -> None:
    """Onboarding fits the companions on the estate's own history; the served risk
    is the percentile of mean(tgn, rarity, isolation forest), and the forest is
    loaded only if it is the file onboarding wrote."""
    import pytest

    from graphsentinel.models.transfer_serving import DeploymentProfile

    maps = AuthIdMaps()
    events = []
    for i, (t, u, s, d) in enumerate(_events(600, seed=13)):
        events.append(NormalizedAuthEvent(
            event_id=i, timestamp=t, src_user_id=maps.users.encode(u), dst_user_id=maps.users.encode(u),
            src_host_id=maps.hosts.encode(s), dst_host_id=maps.hosts.encode(d),
            auth_type_id=maps.auth_types.encode("Kerberos"), logon_type_id=maps.logon_types.encode("Network"),
            orientation_id=maps.orientations.encode("LogOn"), success=1, label_redteam=0,
            day=t // 86_400, hour=(t % 86_400) // 3_600,
        ))
    maps.save(tmp_path / "maps")
    ckpt = _checkpoint(tmp_path / "t.pt")
    result = run_onboarding(events, id_maps_dir=tmp_path / "maps", checkpoint=ckpt, output_dir=tmp_path / "out",
                            alert_budget=0.05, action_budget=0.01)
    profile = DeploymentProfile.load(result.profile_path)
    assert profile.ensemble and set(profile.companion_references) == {"rarity", "iforest"}
    assert (tmp_path / "out" / profile.forest_file).is_file()
    session = load_transfer_session(ckpt, profile_path=result.profile_path)
    assert session.forest is not None
    # the combined budget holds on the estate's own history, by construction
    combined = profile.combined_reference
    assert combined is not None
    share = float((np.searchsorted(combined, combined, "right") / len(combined) > 1 - 0.05).mean())
    assert share <= 0.05 + 1e-9
    # a tampered forest is refused
    (tmp_path / "out" / profile.forest_file).write_bytes(b"not the forest")
    with pytest.raises(ValueError, match="does not match"):
        load_transfer_session(ckpt, profile_path=result.profile_path)


def test_a_network_only_profile_still_loads(tmp_path: Path) -> None:
    from graphsentinel.models.transfer_serving import DeploymentProfile

    maps = AuthIdMaps()
    events = []
    for i, (t, u, s, d) in enumerate(_events(300, seed=17)):
        events.append(NormalizedAuthEvent(
            event_id=i, timestamp=t, src_user_id=maps.users.encode(u), dst_user_id=maps.users.encode(u),
            src_host_id=maps.hosts.encode(s), dst_host_id=maps.hosts.encode(d),
            auth_type_id=maps.auth_types.encode("Kerberos"), logon_type_id=maps.logon_types.encode("Network"),
            orientation_id=maps.orientations.encode("LogOn"), success=1, label_redteam=0,
            day=t // 86_400, hour=(t % 86_400) // 3_600,
        ))
    maps.save(tmp_path / "maps")
    ckpt = _checkpoint(tmp_path / "t.pt")
    result = run_onboarding(events, id_maps_dir=tmp_path / "maps", checkpoint=ckpt, output_dir=tmp_path / "out",
                            alert_budget=0.05, action_budget=0.01, ensemble=False)
    profile = DeploymentProfile.load(result.profile_path)
    assert not profile.ensemble
    assert load_transfer_session(ckpt, profile_path=result.profile_path).forest is None
