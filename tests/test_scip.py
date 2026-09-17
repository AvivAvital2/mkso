from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from mkso.hashing import sha256_file
from mkso.manifest import apply_manifest
from mkso.scip import (
    ScipExpectation,
    ScipIndexerInvocation,
    ScipValidationError,
    load_scip_index,
    run_scip_indexer,
    verify_contract_subjects,
)
from mkso.scip_codec import SCIP_SCHEMA_PATH, ScipCodecError, ScipDecoder
from mkso.store import Store
from mkso.stubs import render_stubs
from tests.scip_support import scip_subject_binding, source_index_contract

EXPECTATION = ScipExpectation("test-scip", "1.0.0", (), "file:///workspace")


def _run_textproto_indexer(
    tmp_path,
    scip_decoder,
    textproto,
    indexed_files,
    *,
    input_files=None,
):
    invocation = _textproto_invocation(
        scip_decoder,
        indexed_files,
        input_files=input_files,
    )
    return run_scip_indexer(
        scip_decoder,
        tmp_path,
        EXPECTATION,
        invocation,
        stdin_payload=textproto.encode("utf-8"),
    )


def _textproto_invocation(
    scip_decoder,
    indexed_files,
    *,
    input_files=None,
):
    return ScipIndexerInvocation(
        executable_path=Path(scip_decoder.identity.protoc_path),
        executable_sha256=scip_decoder.identity.protoc_sha256,
        arguments=(
            "--encode=scip.Index",
            f"--proto_path={SCIP_SCHEMA_PATH.parent}",
            SCIP_SCHEMA_PATH.name,
        ),
        environment=(),
        input_files=indexed_files if input_files is None else input_files,
        indexed_files=indexed_files,
        timeout_seconds=30,
    )


def test_standard_scip_definition_resolves_exact_planned_symbol(
    tmp_path, manifest_factory, ingest_calculator_scip
):
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path))
    [created] = render_stubs(store)

    resolved, errors = ingest_calculator_scip(store)

    assert created == tmp_path / "src" / "calculator.py"
    assert (resolved, errors) == (1, [])
    binding = store.bindings("OBL-ADD")[0]
    assert binding.symbol_id == binding.expected_symbol
    assert binding.indexed_admission_hash == store.metadata("active_scip_admission_hash")
    snapshot = store.scip_snapshot()
    assert snapshot is not None
    assert snapshot == store.scip_snapshot(store.metadata("active_scip_admission_hash"))
    assert len(snapshot["documents"]) == 1
    assert len(snapshot["symbols"]) == 1
    assert len(snapshot["occurrences"]) == 1
    assert snapshot["index"]["raw_index_size"] > 0


def test_binding_rejects_a_different_scip_symbol(
    tmp_path, manifest_factory, ingest_calculator_scip
):
    store = Store.initialize(tmp_path)
    path = manifest_factory(tmp_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["bindings"][0]["expected_symbol"] = (
        "scip-python python calculator 0.0.0 calculator/subtract()."
    )
    path.write_text(json.dumps(raw), encoding="utf-8")
    apply_manifest(store, path)
    render_stubs(store)

    with pytest.raises(ValueError, match="not an exact contract subject"):
        ingest_calculator_scip(store)
    assert store.metadata("active_scip_admission_hash") is None
    with store.connect() as conn:
        assert conn.execute("SELECT count(*) FROM scip_indexes").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM scip_admissions").fetchone()[0] == 0


def test_rejects_missing_language_and_position_encoding(tmp_path, scip_decoder, encode_scip):
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    index_path = encode_scip(
        tmp_path,
        f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  occurrences {{ range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1 }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
''',
    )

    with pytest.raises(ScipValidationError) as raised:
        load_scip_index(scip_decoder, index_path, tmp_path, EXPECTATION)

    assert "documents[0].language is empty" in raised.value.errors
    assert "documents[0].position_encoding is unspecified or unsupported" in raised.value.errors


def test_contract_reference_must_occur_inside_subject_enclosing_range(
    tmp_path, scip_decoder, encode_scip
):
    source = tmp_path / "service.py"
    source.write_text(
        "def target():\n    return 1\n\ndef caller():\n    return target()\n",
        encoding="utf-8",
    )
    target = "scip-python python demo 0.0.0 service/target()."
    caller = "scip-python python demo 0.0.0 service/caller()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "service.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 0 range: 4 range: 10 symbol: "{target}" symbol_roles: 1
    enclosing_range: 0 enclosing_range: 0 enclosing_range: 2 enclosing_range: 0
  }}
  occurrences {{
    range: 3 range: 4 range: 10 symbol: "{caller}" symbol_roles: 1
    enclosing_range: 3 enclosing_range: 0 enclosing_range: 5 enclosing_range: 0
  }}
  occurrences {{ range: 4 range: 11 range: 17 symbol: "{target}" symbol_roles: 8 }}
  symbols {{ symbol: "{target}" kind: Function }}
  symbols {{ symbol: "{caller}" kind: Function }}
}}
'''
    index_path = encode_scip(tmp_path, textproto)
    contract = {
        **source_index_contract(("service.py",)),
        "subjects": [
            {
                "id": "subject.target",
                "language": "python",
                "location": {"path": "service.py"},
                "binding": scip_subject_binding(target),
            },
            {
                "id": "subject.caller",
                "language": "python",
                "location": {"path": "service.py"},
                "binding": scip_subject_binding(
                    caller,
                    [
                        {
                            "kind": "reference",
                            "target_subject_id": "subject.target",
                            "required": True,
                        }
                    ],
                ),
            },
        ],
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    index = load_scip_index(scip_decoder, index_path, tmp_path, EXPECTATION)

    contract_admission = verify_contract_subjects(
        index,
        contract_path,
        project_root=tmp_path,
    )

    assert {binding.subject_id for binding in contract_admission.subject_bindings} == {
        "subject.target",
        "subject.caller",
    }
    assert [
        (
            relationship.source_subject_id,
            relationship.kind,
            relationship.target_subject_id,
            relationship.required,
        )
        for relationship in contract_admission.subject_relationships
    ] == [("subject.caller", "reference", "subject.target", True)]

    store = Store.initialize(tmp_path)
    receipt = store.admit_scip_index(
        scip_decoder,
        EXPECTATION,
        _textproto_invocation(scip_decoder, ("service.py",)),
        contract_path,
        stdin_payload=textproto.encode("utf-8"),
    )
    snapshot = store.scip_snapshot(receipt.admission_hash)
    assert snapshot is not None
    assert snapshot["contract_relationships"] == [
        {
            "admission_hash": receipt.admission_hash,
            "source_subject_id": "subject.caller",
            "kind": "reference",
            "target_subject_id": "subject.target",
            "required": 1,
        }
    ]

    without_reference = replace(index, occurrences=index.occurrences[:-1])
    with pytest.raises(ScipValidationError) as raised:
        verify_contract_subjects(
            without_reference,
            contract_path,
            project_root=tmp_path,
        )
    assert any(
        "required reference edge to subject.target is absent" in value
        for value in raised.value.errors
    )

    contract["subjects"][1]["binding"]["selector"]["expected_relationships"] = []
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ScipValidationError, match="observed undeclared reference edge"):
        verify_contract_subjects(
            index,
            contract_path,
            project_root=tmp_path,
        )

    contract["subjects"][1]["binding"]["selector"]["expected_relationships"] = [
        {
            "kind": "reference",
            "target_subject_id": "subject.target",
            "required": False,
        }
    ]
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    optional_admission = verify_contract_subjects(
        index,
        contract_path,
        project_root=tmp_path,
    )
    assert optional_admission.subject_relationships[0].required is False
    verify_contract_subjects(
        without_reference,
        contract_path,
        project_root=tmp_path,
    )

    contract["subjects"][1]["binding"]["selector"]["expected_relationships"] *= 2
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ScipValidationError, match="duplicates the declared inter-subject edge"):
        verify_contract_subjects(
            index,
            contract_path,
            project_root=tmp_path,
        )

    contract["subjects"][1]["binding"]["selector"]["expected_relationships"] = []
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    caller_without_enclosing = replace(index.occurrences[1], enclosing_range=None)
    no_caller_enclosing = replace(
        index,
        occurrences=(index.occurrences[0], caller_without_enclosing),
    )
    with pytest.raises(ScipValidationError, match="closed-world inter-subject"):
        verify_contract_subjects(
            no_caller_enclosing,
            contract_path,
            project_root=tmp_path,
        )


def test_contract_binding_rejects_symlinked_and_external_paths(tmp_path, scip_decoder):
    project_root = tmp_path / "project"
    project_root.mkdir()
    (project_root / "subject.py").write_text("def subject():\n    return 1\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{ range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1 }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''
    index, _, _ = _run_textproto_indexer(
        project_root,
        scip_decoder,
        textproto,
        ("subject.py",),
    )
    real_contract = project_root / "contract.real.json"
    real_contract.write_text('{"subjects": []}', encoding="utf-8")
    linked_contract = project_root / "contract.json"
    linked_contract.symlink_to(real_contract.name)

    with pytest.raises(ScipValidationError, match="symbolic link"):
        verify_contract_subjects(
            index,
            linked_contract,
            project_root=project_root,
        )

    external_contract = tmp_path / "external.json"
    external_contract.write_text('{"subjects": []}', encoding="utf-8")
    with pytest.raises(ScipValidationError, match="contract path"):
        verify_contract_subjects(
            index,
            external_contract,
            project_root=project_root,
        )


def test_codec_rejects_a_different_protoc_digest(scip_decoder):
    with pytest.raises(ScipCodecError, match="protoc digest mismatch"):
        ScipDecoder(
            protoc_path=Path(scip_decoder.identity.protoc_path),
            expected_protoc_sha256="0" * 64,
            expected_protobuf_runtime_version=scip_decoder.identity.protobuf_runtime_version,
        )


def test_codec_rejects_fields_unknown_to_the_frozen_schema(tmp_path, scip_decoder, encode_scip):
    index_path = encode_scip(
        tmp_path,
        """
metadata {
  tool_info { name: "test-scip" version: "1.0.0" }
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}
""",
    )
    payload = index_path.read_bytes() + b"\xf8\x07\x01"

    with pytest.raises(ScipCodecError, match="fields unknown"):
        scip_decoder.decode_bytes(payload)


def test_indexer_rejects_a_different_executable_digest(tmp_path, scip_decoder):
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    invocation = ScipIndexerInvocation(
        executable_path=Path(scip_decoder.identity.protoc_path),
        executable_sha256="0" * 64,
        arguments=(),
        environment=(),
        input_files=("subject.py",),
        indexed_files=("subject.py",),
        timeout_seconds=30,
    )

    with pytest.raises(ScipValidationError, match="indexer executable digest mismatch"):
        run_scip_indexer(scip_decoder, tmp_path, EXPECTATION, invocation)


def test_indexer_rejects_an_incomplete_document_set(tmp_path, scip_decoder):
    (tmp_path / "subject.py").write_text("def subject():\n    return 1\n", encoding="utf-8")
    (tmp_path / "extra.py").write_text("VALUE = 2\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{ range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1 }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''

    with pytest.raises(ScipValidationError, match="differs from the frozen source manifest"):
        _run_textproto_indexer(
            tmp_path,
            scip_decoder,
            textproto,
            ("extra.py", "subject.py"),
        )


def test_rejects_disagreeing_typed_and_deprecated_ranges(tmp_path, scip_decoder, encode_scip):
    (tmp_path / "subject.py").write_text("def subject():\n    return 1\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    index_path = encode_scip(
        tmp_path,
        f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 0 range: 4 range: 11
    single_line_range {{ line: 0 start_character: 4 end_character: 10 }}
    symbol: "{symbol}"
    symbol_roles: 1
  }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
''',
    )

    with pytest.raises(ScipValidationError) as raised:
        load_scip_index(scip_decoder, index_path, tmp_path, EXPECTATION)
    assert any("typed and deprecated encodings disagree" in value for value in raised.value.errors)


def test_store_rejects_unknown_fields_emitted_by_its_invoked_indexer(tmp_path, scip_decoder):
    (tmp_path / "subject.py").write_text("def subject():\n    return 1\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{ range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1 }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''
    _, _, raw_index = _run_textproto_indexer(
        tmp_path,
        scip_decoder,
        textproto,
        ("subject.py",),
    )
    unknown_field_index = raw_index + b"\xf8\x07\x01"
    indexer_script = tmp_path / "emit_index.py"
    indexer_script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        f"Path(sys.argv[1]).write_bytes(bytes.fromhex({unknown_field_index.hex()!r}))\n",
        encoding="utf-8",
    )
    executable = Path(sys.executable).resolve()
    invocation = ScipIndexerInvocation(
        executable_path=executable,
        executable_sha256=sha256_file(executable),
        arguments=("emit_index.py", "{output}"),
        environment=(),
        input_files=("emit_index.py", "subject.py"),
        indexed_files=("subject.py",),
        timeout_seconds=30,
    )
    store = Store.initialize(tmp_path)
    contract_path = tmp_path / "contract.json"
    contract_path.write_text('{"subjects": []}', encoding="utf-8")

    with pytest.raises(ScipCodecError, match="fields unknown"):
        store.admit_scip_index(
            scip_decoder,
            EXPECTATION,
            invocation,
            contract_path,
        )


def test_non_document_indexer_input_participates_in_freshness(tmp_path, scip_decoder):
    source = tmp_path / "subject.py"
    source.write_text("def subject():\n    return 1\n", encoding="utf-8")
    configuration = tmp_path / "pyproject.toml"
    configuration.write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1
    enclosing_range: 0 enclosing_range: 0 enclosing_range: 2 enclosing_range: 0
  }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''
    invocation = _textproto_invocation(
        scip_decoder,
        ("subject.py",),
        input_files=("pyproject.toml", "subject.py"),
    )
    contract_path = tmp_path / "contract.json"
    contract = {
        **source_index_contract(
            ("subject.py",),
            input_paths=("pyproject.toml", "subject.py"),
        ),
        "subjects": [
            {
                "id": "subject.subject",
                "language": "python",
                "location": {"path": "subject.py"},
                "binding": scip_subject_binding(symbol),
            }
        ],
    }
    contract_text = json.dumps(contract)
    contract_path.write_text(contract_text, encoding="utf-8")
    store = Store.initialize(tmp_path)

    contract["source_index_policy"]["tool_requirement_id"] = "tool.unknown"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ScipValidationError, match=r"refers to unknown tool tool\.unknown"):
        store.admit_scip_index(
            scip_decoder,
            EXPECTATION,
            invocation,
            contract_path,
            stdin_payload=textproto.encode("utf-8"),
        )
    assert store.metadata("active_scip_admission_hash") is None

    contract.update(source_index_contract(("subject.py",)))
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(ValueError, match="indexer inputs differ from the frozen contract scope"):
        store.admit_scip_index(
            scip_decoder,
            EXPECTATION,
            invocation,
            contract_path,
            stdin_payload=textproto.encode("utf-8"),
        )
    assert store.metadata("active_scip_admission_hash") is None

    contract_path.write_text(contract_text, encoding="utf-8")
    receipt = store.admit_scip_index(
        scip_decoder,
        EXPECTATION,
        invocation,
        contract_path,
        stdin_payload=textproto.encode("utf-8"),
    )

    assert receipt.admission_hash == store.metadata("active_scip_admission_hash")
    assert receipt.resolved_bindings == 0
    assert store.scip_freshness_reasons() == []
    snapshot = store.scip_snapshot()
    assert snapshot is not None
    assert snapshot["index"]["indexed_files"] == ["subject.py"]
    assert len(snapshot["index"]["input_manifest"]) == 2
    assert snapshot["source_index_policy"]["input_paths"] == [
        "pyproject.toml",
        "subject.py",
    ]

    contract_path.write_text(contract_text + "\n", encoding="utf-8")
    assert store.scip_freshness_reasons() == ["SCIP contract is stale: contract.json"]
    contract_path.write_text(contract_text, encoding="utf-8")
    assert store.scip_freshness_reasons() == []

    configuration.write_text("[project]\nname = 'changed'\n", encoding="utf-8")
    assert store.scip_freshness_reasons() == ["SCIP generation input is stale: pyproject.toml"]


def test_direct_scip_binds_code_and_excludes_managed_artifact_paths(tmp_path, scip_decoder):
    (tmp_path / "subject.py").write_text("def subject():\n    return 1\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    symbol = "scip-python python demo 0.0.0 subject()."
    textproto = f'''
metadata {{
  tool_info {{ name: "test-scip" version: "1.0.0" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "subject.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 0 range: 4 range: 11 symbol: "{symbol}" symbol_roles: 1
    enclosing_range: 0 enclosing_range: 0 enclosing_range: 2 enclosing_range: 0
  }}
  symbols {{ symbol: "{symbol}" kind: Function }}
}}
'''
    index, _, _ = _run_textproto_indexer(
        tmp_path,
        scip_decoder,
        textproto,
        ("subject.py",),
        input_files=("pyproject.toml", "subject.py"),
    )
    contract = {
        **source_index_contract(
            ("subject.py",),
            input_paths=("pyproject.toml", "subject.py"),
        ),
        "subjects": [
            {
                "id": "subject.code",
                "language": "python",
                "location": {"path": "subject.py"},
                "binding": scip_subject_binding(symbol),
            },
            {
                "id": "subject.configuration",
                "language": "toml",
                "location": {"path": "pyproject.toml"},
                "binding": {
                    "family": "managed_artifact",
                    "profile_id": "uv-project-manifest-v1",
                    "media_type": "application/toml",
                    "projection_selector": "project.dependencies",
                    "expected_projection_hash": "sha256:" + ("0" * 64),
                    "tool_requirement_id": "tool.uv",
                },
            },
        ],
    }
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(json.dumps(contract), encoding="utf-8")

    admission = verify_contract_subjects(index, contract_path, project_root=tmp_path)
    assert [binding.subject_id for binding in admission.subject_bindings] == ["subject.code"]

    contract["source_index_policy"]["indexed_paths"].append("pyproject.toml")
    contract["source_index_policy"]["indexed_paths"].sort()
    contract_path.write_text(json.dumps(contract), encoding="utf-8")
    with pytest.raises(
        ScipValidationError,
        match="managed-artifact subject path appears in indexed_paths",
    ):
        verify_contract_subjects(index, contract_path, project_root=tmp_path)
