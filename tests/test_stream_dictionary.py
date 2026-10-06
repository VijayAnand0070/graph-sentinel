"""The synthetic stream is named with the dictionary it was written with.

An id means a different account in each entity dictionary. Naming the demo
stream's ids through the serving dictionary instead of the generator's renamed
every identity in it and broke its ground truth; the manifest's own attacker
(id, name) pairs decide which dictionary is right.
"""

from __future__ import annotations

import json
from pathlib import Path

from graphsentinel.api.stream_dictionary import manifest_agrees, stream_dictionary


def _dictionary(root: Path, name: str, users: list[str]) -> Path:
    directory = root / name
    directory.mkdir()
    (directory / "users.json").write_text(json.dumps({"values": users}), encoding="utf-8")
    return directory


MANIFEST = {
    "attack_chains": [
        {"chain_id": "ATK-001", "attacker_user_id": 2, "attacker_user_name": "U66@DOM1"},
        {"chain_id": "ATK-002", "attacker_user_id": 3, "attacker_user_name": "C1708$@DOM1"},
    ]
}


def test_the_dictionary_that_reproduces_the_manifest_is_chosen(tmp_path: Path) -> None:
    serving = _dictionary(tmp_path, "serving", ["<unk>", "x", "C791$@DOM1", "C2287$@DOM1"])
    generator = _dictionary(tmp_path, "generator", ["<unk>", "x", "U66@DOM1", "C1708$@DOM1"])

    # The serving dictionary is offered first and still loses: it names id 2
    # as a different account than the one the stream was written about.
    chosen, why = stream_dictionary(MANIFEST, [serving, generator])

    assert chosen == generator
    assert "resolve to its attacker names" in why


def test_a_declared_dictionary_is_preferred(tmp_path: Path) -> None:
    generator = _dictionary(tmp_path, "generator", ["<unk>", "x", "U66@DOM1", "C1708$@DOM1"])
    other = _dictionary(tmp_path, "other", ["<unk>", "x", "U66@DOM1", "C1708$@DOM1"])

    chosen, _why = stream_dictionary({**MANIFEST, "id_map_dir": str(generator)}, [other])

    assert chosen == generator


def test_agreement_is_checked_on_every_chain(tmp_path: Path) -> None:
    half = ["<unk>", "x", "U66@DOM1", "SOMEONE-ELSE"]
    assert manifest_agrees(half, MANIFEST) is False
    assert manifest_agrees(["<unk>", "x", "U66@DOM1", "C1708$@DOM1"], MANIFEST) is True
    assert manifest_agrees(["<unk>"], MANIFEST) is False  # ids out of range


def test_nothing_agrees_falls_back_and_says_so(tmp_path: Path) -> None:
    wrong = _dictionary(tmp_path, "wrong", ["<unk>", "a", "b", "c"])
    chosen, why = stream_dictionary(MANIFEST, [wrong])
    assert chosen == wrong and "no dictionary reproduces" in why


def test_no_usable_dictionary_is_reported(tmp_path: Path) -> None:
    chosen, why = stream_dictionary(MANIFEST, [tmp_path / "missing", None])
    assert chosen is None and "no usable" in why


def test_the_shipped_manifest_matches_the_generator_dictionary() -> None:
    """The artifacts in the repository must agree with each other."""
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "artifacts" / "synthetic" / "ground_truth_manifest.json"
    generator = root / "artifacts" / "id_maps_lanl_bounded" / "users.json"
    if not manifest_path.is_file() or not generator.is_file():
        import pytest

        pytest.skip("synthetic artifacts not present in this checkout")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    users = json.loads(generator.read_text(encoding="utf-8"))["values"]
    assert manifest.get("id_map_dir") == "artifacts/id_maps_lanl_bounded"
    assert manifest_agrees(users, manifest)
