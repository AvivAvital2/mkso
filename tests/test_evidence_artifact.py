from __future__ import annotations

import json
import sys

from mkso.domain import EvidenceKind, NodeStatus
from mkso.evaluation import Evaluator
from mkso.evidence import run_evidence
from mkso.manifest import apply_manifest
from mkso.store import Store
from mkso.stubs import render_stubs


def test_mutated_artifact_invalidates_formal_evidence(
    tmp_path, manifest_factory, ingest_calculator_scip
):
    command = [sys.executable, "write_certificate.py"]
    path = manifest_factory(tmp_path, behavior_command=command)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["obligations"][0]["evidence"][0].update(
        {
            "kind": "formal_proof",
            "tool": "certificate-writer",
            "inputs": ["write_certificate.py"],
            "artifact_path": "proof.json",
        }
    )
    path.write_text(json.dumps(raw), encoding="utf-8")
    store = Store.initialize(tmp_path)
    apply_manifest(store, path)
    render_stubs(store)
    ingest_calculator_scip(store)
    (tmp_path / "write_certificate.py").write_text(
        "from pathlib import Path\nPath('proof.json').write_text('valid')\n",
        encoding="utf-8",
    )

    evidence = run_evidence(
        store,
        obligation_id="OBL-ADD",
        kind=EvidenceKind.FORMAL_PROOF,
        tool="certificate-writer",
        command=command,
        artifact=tmp_path / "proof.json",
    )
    assert evidence.artifact_sha256
    assert Evaluator(store).check_item("TASK-ADD").status is NodeStatus.VERIFIED

    (tmp_path / "proof.json").write_text("tampered", encoding="utf-8")
    result = Evaluator(store).check_item("TASK-ADD")
    assert result.status is NodeStatus.INCOMPLETE
    assert "missing fresh formal_proof evidence" in result.children[0].reasons
