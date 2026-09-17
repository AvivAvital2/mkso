from __future__ import annotations

import json

import pytest

from mkso.manifest import load_manifest


def test_non_leaf_requires_composition_obligation(tmp_path, manifest_factory):
    path = manifest_factory(tmp_path, include_composition=False)

    with pytest.raises(ValueError, match="must own a composition obligation"):
        load_manifest(path)


def test_checker_invocation_is_part_of_manifest_digest(tmp_path, manifest_factory):
    path = manifest_factory(tmp_path)
    first = load_manifest(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["obligations"][0]["evidence"][0]["command"].append("--changed")
    path.write_text(json.dumps(raw), encoding="utf-8")
    second = load_manifest(path)

    assert first.digest != second.digest


def test_behavior_obligation_requires_source_binding(tmp_path, manifest_factory):
    path = manifest_factory(tmp_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["bindings"] = []
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="must bind to at least one symbol"):
        load_manifest(path)
