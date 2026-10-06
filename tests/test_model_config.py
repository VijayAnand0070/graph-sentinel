from pathlib import Path

import pytest

from graphsentinel.features.causal import MODEL_FEATURE_NAMES
from graphsentinel.models.config import load_tgn_training_config


def test_canonical_model_config_matches_feature_and_training_contract() -> None:
    config = load_tgn_training_config(epochs=3, patience=2)

    assert len(MODEL_FEATURE_NAMES) == 27
    assert config.epochs == 3
    assert config.patience == 2
    assert config.memory_dim == 64
    assert config.oov_user_buckets == 4_096
    assert config.oov_host_buckets == 16_384
    assert config.require_baseline_improvement is True


def test_model_config_rejects_contract_drift(tmp_path: Path) -> None:
    path = tmp_path / "model.yaml"
    source = Path("configs/model_tgn.yaml").read_text(encoding="utf-8")
    path.write_text(source.replace("message_dim: 27", "message_dim: 128"), encoding="utf-8")

    with pytest.raises(ValueError, match="causal feature contract"):
        load_tgn_training_config(path)


def test_default_config_has_no_positive_weight_cap() -> None:
    config = load_tgn_training_config()
    assert config.positive_weight_cap is None


def test_regularized_v2_config_loads_with_expected_overrides() -> None:
    config = load_tgn_training_config(Path("configs/model_tgn_v2_regularized.yaml"))
    assert config.dropout == pytest.approx(0.30)
    assert config.weight_decay == pytest.approx(0.01)
    assert config.positive_weight_cap == pytest.approx(50.0)
    assert config.train_fraction == pytest.approx(0.61358)
    assert config.validation_fraction == pytest.approx(0.17305)


def test_model_config_requires_positive_weight_cap_key(tmp_path: Path) -> None:
    path = tmp_path / "model.yaml"
    source = Path("configs/model_tgn.yaml").read_text(encoding="utf-8")
    path.write_text(source.replace("  positive_weight_cap: null\n", ""), encoding="utf-8")

    with pytest.raises(ValueError, match="training fields do not match contract"):
        load_tgn_training_config(path)
