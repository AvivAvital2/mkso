from __future__ import annotations

import sys

import pytest

from mkso.cli import main
from mkso.domain import EvidenceKind, NodeStatus
from mkso.evaluation import Evaluator
from mkso.evidence import run_evidence
from mkso.manifest import apply_manifest
from mkso.store import Store
from mkso.stubs import render_stubs


def _write_checkers(root):
    (root / "check_behavior.py").write_text(
        "from pathlib import Path\n"
        "source = Path('src/calculator.py').read_text()\n"
        "assert 'return a + b' in source\n",
        encoding="utf-8",
    )
    (root / "check_composition.py").write_text(
        "from pathlib import Path\nassert Path('src/calculator.py').is_file()\n",
        encoding="utf-8",
    )


def test_hierarchy_requires_fresh_leaf_and_composition_evidence(
    tmp_path, manifest_factory, ingest_calculator_scip
):
    behavior_command = [sys.executable, "check_behavior.py"]
    composition_command = [sys.executable, "check_composition.py"]
    store = Store.initialize(tmp_path)
    manifest = manifest_factory(
        tmp_path,
        behavior_command=behavior_command,
        composition_command=composition_command,
    )
    apply_manifest(store, manifest)
    [source] = render_stubs(store)
    source.write_text(
        source.read_text(encoding="utf-8").replace(
            'raise NotImplementedError("OBL-ADD")', "return a + b"
        ),
        encoding="utf-8",
    )
    _write_checkers(tmp_path)
    resolved, errors = ingest_calculator_scip(store)
    assert (resolved, errors) == (1, [])

    assert Evaluator(store).check_project().status is NodeStatus.INCOMPLETE
    run_evidence(
        store,
        obligation_id="OBL-ADD",
        kind=EvidenceKind.TEST,
        tool="behavior-checker",
        command=behavior_command,
    )
    task = Evaluator(store).check_item("TASK-ADD")
    assert task.status is NodeStatus.VERIFIED
    assert Evaluator(store).check_project().status is NodeStatus.INCOMPLETE

    run_evidence(
        store,
        obligation_id="OBL-SYSTEM-COMPOSE",
        kind=EvidenceKind.COMPOSITION,
        tool="composition-checker",
        command=composition_command,
    )
    assert Evaluator(store).check_project().status is NodeStatus.VERIFIED

    checker = tmp_path / "check_behavior.py"
    original_checker = checker.read_text(encoding="utf-8")
    checker.write_text(original_checker + "# changed checker\n", encoding="utf-8")
    task = Evaluator(store).check_item("TASK-ADD")
    assert task.status is NodeStatus.INCOMPLETE
    assert "missing fresh test evidence" in task.children[0].reasons
    checker.write_text(original_checker, encoding="utf-8")
    assert Evaluator(store).check_project().status is NodeStatus.VERIFIED

    source.write_text(
        source.read_text(encoding="utf-8").replace("return a + b", "return a - b"),
        encoding="utf-8",
    )
    result = Evaluator(store).check_project()
    assert result.status is NodeStatus.INCOMPLETE
    task = Evaluator(store).check_item("TASK-ADD")
    assert "source index is stale: src/calculator.py" in task.children[0].reasons


def test_runner_rejects_checker_not_frozen_in_plan(
    tmp_path, manifest_factory, ingest_calculator_scip
):
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path))
    render_stubs(store)
    ingest_calculator_scip(store)

    with pytest.raises(ValueError, match="not frozen in the accepted plan"):
        run_evidence(
            store,
            obligation_id="OBL-ADD",
            kind=EvidenceKind.TEST,
            tool="fake",
            command=[sys.executable, "-c", "raise SystemExit(0)"],
        )


def test_missing_checker_input_fails_closed(tmp_path, manifest_factory, ingest_calculator_scip):
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path))
    render_stubs(store)
    ingest_calculator_scip(store)

    result = Evaluator(store).check_item("TASK-ADD")
    assert result.status is NodeStatus.INCOMPLETE
    assert "checker input is missing: check_behavior.py" in result.children[0].reasons


def test_cli_preserves_options_before_checker_separator(
    tmp_path, manifest_factory, monkeypatch, ingest_calculator_scip
):
    command = [sys.executable, "check_behavior.py"]
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path, behavior_command=command))
    render_stubs(store)
    (tmp_path / "check_behavior.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    ingest_calculator_scip(store)
    monkeypatch.chdir(tmp_path)

    exit_code = main(
        [
            "evidence",
            "run",
            "OBL-ADD",
            "--kind",
            "test",
            "--tool",
            "behavior-checker",
            "--",
            *command,
        ]
    )

    assert exit_code == 0
    assert Evaluator(store).check_item("TASK-ADD").status is NodeStatus.VERIFIED
