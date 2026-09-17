from __future__ import annotations

import copy
import json

from mkso.modelcheck import check_certificate, load_model, prove


def _write_model(path, transitions):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "states": sorted(transitions),
                "transitions": transitions,
                "properties": [
                    {
                        "id": "A-LEADS-TO-B",
                        "kind": "all_paths_eventually",
                        "source_states": ["a"],
                        "target_states": ["b"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_rank_certificate_proves_all_paths_eventually(tmp_path):
    path = tmp_path / "model.json"
    _write_model(path, {"a": ["x", "y"], "x": ["b"], "y": ["b"], "b": ["b"]})
    model = load_model(path)

    certificate = prove(model, "A-LEADS-TO-B")
    valid, message = check_certificate(model, certificate)

    assert certificate["result"] == "proved"
    assert valid, message
    assert certificate["ranks"]["a"] == 2


def test_rank_certificate_rejects_non_decreasing_edge(tmp_path):
    path = tmp_path / "model.json"
    _write_model(path, {"a": ["x"], "x": ["b"], "b": ["b"]})
    model = load_model(path)
    certificate = prove(model, "A-LEADS-TO-B")
    tampered = copy.deepcopy(certificate)
    tampered["ranks"]["x"] = tampered["ranks"]["a"]

    valid, message = check_certificate(model, tampered)

    assert not valid
    assert "does not decrease" in message


def test_counterexample_closes_cycle_away_from_target(tmp_path):
    path = tmp_path / "model.json"
    _write_model(path, {"a": ["x"], "x": ["x", "b"], "b": ["b"]})
    model = load_model(path)

    certificate = prove(model, "A-LEADS-TO-B")
    valid, message = check_certificate(model, certificate)

    assert certificate["result"] == "disproved"
    assert certificate["counterexample"] == ["a", "x", "x"]
    assert valid, message
