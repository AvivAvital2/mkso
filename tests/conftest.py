from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from mkso.hashing import sha256_file
from mkso.scip import (
    ScipExpectation,
    ScipIndexerInvocation,
)
from mkso.scip_codec import SCIP_SCHEMA_PATH, ScipDecoder
from tests.scip_support import scip_subject_binding, source_index_contract


@pytest.fixture(scope="session")
def scip_decoder() -> ScipDecoder:
    executable = shutil.which("protoc")
    if executable is None:
        pytest.fail("bootstrap SCIP tests require protoc")
    path = Path(executable).resolve()
    return ScipDecoder(
        protoc_path=path,
        expected_protoc_sha256=sha256_file(path),
        expected_protobuf_runtime_version="6.33.2",
    )


@pytest.fixture
def encode_scip(scip_decoder):
    def encode(root: Path, textproto: str) -> Path:
        try:
            result = subprocess.run(
                [
                    scip_decoder.identity.protoc_path,
                    "--encode=scip.Index",
                    f"--proto_path={SCIP_SCHEMA_PATH.parent}",
                    SCIP_SCHEMA_PATH.name,
                ],
                input=textproto.encode("utf-8"),
                check=True,
                capture_output=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            pytest.fail(f"unable to encode bootstrap SCIP fixture: {exc.stderr.decode()}")
        path = root / "index.scip"
        path.write_bytes(result.stdout)
        return path

    return encode


@pytest.fixture
def ingest_calculator_scip(scip_decoder):
    def ingest(store):
        source = store.project_root / "src" / "calculator.py"
        lines = source.read_text(encoding="utf-8").splitlines()
        definition_line = next(
            offset for offset, line in enumerate(lines) if line.startswith("def add(")
        )
        symbol = "scip-python python calculator 0.0.0 calculator/add()."
        textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "src/calculator.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: {definition_line} range: 4 range: 7
    symbol: "{symbol}"
    symbol_roles: 1
    enclosing_range: {definition_line} enclosing_range: 0
    enclosing_range: {len(lines)} enclosing_range: 0
  }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''
        expectation = ScipExpectation("test-scip", "1.0.0", (), "file:///workspace")
        invocation = ScipIndexerInvocation(
            executable_path=Path(scip_decoder.identity.protoc_path),
            executable_sha256=scip_decoder.identity.protoc_sha256,
            arguments=(
                "--encode=scip.Index",
                f"--proto_path={SCIP_SCHEMA_PATH.parent}",
                SCIP_SCHEMA_PATH.name,
            ),
            environment=(),
            input_files=("src/calculator.py",),
            indexed_files=("src/calculator.py",),
            timeout_seconds=30,
        )
        contract_path = store.project_root / "contract.json"
        contract_path.write_text(
            json.dumps(
                {
                    **source_index_contract(("src/calculator.py",)),
                    "subjects": [
                        {
                            "id": "subject.add",
                            "language": "python",
                            "location": {"path": "src/calculator.py"},
                            "binding": scip_subject_binding(symbol),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        receipt = store.admit_scip_index(
            scip_decoder,
            expectation,
            invocation,
            contract_path,
            stdin_payload=textproto.encode("utf-8"),
        )
        return receipt.resolved_bindings, []

    return ingest


@pytest.fixture
def manifest_factory():
    def create(
        root: Path,
        *,
        include_composition: bool = True,
        behavior_command: list[str] | None = None,
        composition_command: list[str] | None = None,
    ) -> Path:
        behavior_command = behavior_command or [
            sys.executable,
            "check_behavior.py",
        ]
        composition_command = composition_command or [
            sys.executable,
            "check_composition.py",
        ]
        obligations: list[dict[str, Any]] = [
            {
                "id": "OBL-ADD",
                "work_item_id": "TASK-ADD",
                "title": "Add values",
                "statement": "add(a, b) returns the mathematical sum of a and b",
                "role": "behavior",
                "assumptions": ["a and b are Python integers"],
                "guarantees": ["result == a + b"],
                "evidence": [
                    {
                        "kind": "test",
                        "tool": "behavior-checker",
                        "command": behavior_command,
                        "inputs": ["check_behavior.py"],
                    }
                ],
            }
        ]
        if include_composition:
            obligations.append(
                {
                    "id": "OBL-SYSTEM-COMPOSE",
                    "work_item_id": "THEME-SYSTEM",
                    "title": "Compose the system",
                    "statement": "The verified task guarantees imply the system guarantee",
                    "role": "composition",
                    "assumptions": ["OBL-ADD guarantee holds"],
                    "guarantees": ["the system exposes correct addition"],
                    "evidence": [
                        {
                            "kind": "composition",
                            "tool": "composition-checker",
                            "command": composition_command,
                            "inputs": ["check_composition.py"],
                        }
                    ],
                }
            )
        data = {
            "schema_version": 1,
            "project": {"id": "calculator", "name": "Calculator"},
            "work_items": [
                {
                    "id": "THEME-SYSTEM",
                    "kind": "theme",
                    "title": "Verified calculator",
                    "description": "Top-level system behavior",
                },
                {
                    "id": "TASK-ADD",
                    "kind": "task",
                    "title": "Implement addition",
                    "parent_id": "THEME-SYSTEM",
                },
            ],
            "obligations": obligations,
            "bindings": [
                {
                    "obligation_id": "OBL-ADD",
                    "file": "src/calculator.py",
                    "qualified_name": "calculator.add",
                    "signature": "def add(a: int, b: int) -> int:",
                    "rationale": "This is the narrow implementation boundary for addition.",
                    "expected_symbol": "scip-python python calculator 0.0.0 calculator/add().",
                }
            ],
        }
        path = root / "mkso.plan.json"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    return create
