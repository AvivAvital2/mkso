from __future__ import annotations

from copy import deepcopy

import pytest

from mkso.manifest import apply_manifest
from mkso.scip_compare import compare_scip_admissions
from mkso.store import Store
from mkso.stubs import render_stubs


def _snapshot(admission_hash: str, ingestion_hash: str) -> dict[str, object]:
    return {
        "admission": {
            "admission_hash": admission_hash,
            "ingestion_hash": ingestion_hash,
            "contract_path": "contract.json",
            "contract_sha256": "a" * 64,
        },
        "index": {
            "ingestion_hash": ingestion_hash,
            "index_hash": "b" * 64,
            "raw_index_size": 100,
            "schema_release": "v0.9.0",
            "schema_sha256": "c" * 64,
            "protoc_path": "/tool/protoc",
            "protoc_sha256": "d" * 64,
            "protoc_version": "libprotoc 34.0",
            "protobuf_runtime_version": "6.33.2",
            "tool_name": "scip-python",
            "tool_version": "1.0.0",
            "tool_arguments": ["index", "."],
            "project_root_uri": "file:///workspace",
            "text_document_encoding": 2,
            "indexer_executable_path": "/tool/scip-python",
            "indexer_executable_sha256": "e" * 64,
            "indexer_arguments": ["index", "--output", "{output}"],
            "indexer_environment_hash": "f" * 64,
            "input_manifest": [["subject.py", "1" * 64]],
            "indexed_files": ["subject.py"],
            "indexer_stdin_hash": None,
            "indexer_stdout_hash": "2" * 64,
            "indexer_stderr_hash": "3" * 64,
            "indexer_exit_code": 0,
        },
        "documents": [
            {
                "ingestion_hash": ingestion_hash,
                "relative_path": "subject.py",
                "language": "Python",
                "position_encoding": 2,
                "source_hash": "1" * 64,
            }
        ],
        "symbols": [
            {
                "ingestion_hash": ingestion_hash,
                "symbol_key": "demo/subject().",
                "symbol": "demo/subject().",
                "document_path": "subject.py",
                "external": 0,
                "kind": 17,
                "display_name": "subject",
                "signature_language": "Python",
                "signature_text": "def subject() -> int",
                "enclosing_symbol": "",
            }
        ],
        "relationships": [
            {
                "ingestion_hash": ingestion_hash,
                "source_symbol_key": "demo/subject().",
                "ordinal": 0,
                "target_symbol_key": "demo/value#",
                "is_reference": 1,
                "is_implementation": 0,
                "is_type_definition": 0,
                "is_definition": 0,
            }
        ],
        "occurrences": [
            {
                "ingestion_hash": ingestion_hash,
                "document_path": "subject.py",
                "ordinal": 0,
                "symbol": "demo/subject().",
                "symbol_key": "demo/subject().",
                "symbol_roles": 1,
                "start_line": 0,
                "start_character": 4,
                "end_line": 0,
                "end_character": 11,
                "enclosing_start_line": 0,
                "enclosing_start_character": 0,
                "enclosing_end_line": 1,
                "enclosing_end_character": 12,
            }
        ],
        "subject_bindings": [
            {
                "admission_hash": admission_hash,
                "subject_id": "subject.demo",
                "symbol": "demo/subject().",
                "document_path": "subject.py",
                "definition_start_line": 0,
                "definition_start_character": 4,
                "definition_end_line": 0,
                "definition_end_character": 11,
                "enclosing_start_line": 0,
                "enclosing_start_character": 0,
                "enclosing_end_line": 1,
                "enclosing_end_character": 12,
                "source_hash": "1" * 64,
            }
        ],
        "contract_relationships": [
            {
                "admission_hash": admission_hash,
                "source_subject_id": "subject.demo",
                "kind": "reference",
                "target_subject_id": "subject.demo",
                "required": 0,
            }
        ],
        "source_index_policy": {
            "tool_requirement_id": "tool.scip-python",
            "mode": "full_target",
            "indexed_paths": ["subject.py"],
            "input_paths": ["subject.py"],
            "language_ids": [["python", "Python"]],
            "inter_subject_relationship_policy": "closed_world_declared_edges",
            "unmappable_structure_effect": "CONTRACT_VIOLATION_REQUIRES_AMENDMENT",
        },
    }


class _SnapshotStore:
    def __init__(self, snapshots: dict[str, dict[str, object]]) -> None:
        self.snapshots = snapshots

    def scip_snapshot(self, admission_hash: str) -> dict[str, object] | None:
        return deepcopy(self.snapshots.get(admission_hash))


def test_identical_admission_has_an_empty_exact_diff():
    admission_hash = "4" * 64
    store = _SnapshotStore({admission_hash: _snapshot(admission_hash, "5" * 64)})

    result = compare_scip_admissions(store, admission_hash, admission_hash)  # type: ignore[arg-type]

    assert result.is_empty


def test_historical_admissions_compare_their_bound_source_bytes(
    tmp_path,
    manifest_factory,
    ingest_calculator_scip,
):
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path))
    [source] = render_stubs(store)
    ingest_calculator_scip(store)
    before_hash = store.metadata("active_scip_admission_hash")
    assert before_hash is not None
    source.write_text(
        source.read_text(encoding="utf-8").replace("narrow", "strict"),
        encoding="utf-8",
    )
    ingest_calculator_scip(store)
    after_hash = store.metadata("active_scip_admission_hash")
    assert after_hash is not None and after_hash != before_hash

    result = compare_scip_admissions(store, before_hash, after_hash)

    assert not result.index_bytes_changed
    assert result.changed_generation_fields == ()
    assert result.changed_input_paths == ("src/calculator.py",)
    assert result.changed_document_paths == ("src/calculator.py",)
    assert result.changed_symbol_keys == ()
    assert result.changed_relationship_source_keys == ()
    assert result.changed_occurrence_document_paths == ()
    assert result.changed_subject_ids == ("subject.add",)
    assert result.changed_contract_relationship_source_ids == ()
    assert result.changed_source_index_policy_fields == ()


def test_exact_diff_reports_each_changed_stored_dimension():
    before_hash = "4" * 64
    after_hash = "6" * 64
    before = _snapshot(before_hash, "5" * 64)
    after = _snapshot(after_hash, "7" * 64)
    after["admission"]["contract_sha256"] = "8" * 64  # type: ignore[index]
    after["admission"]["future_policy_hash"] = "frozen"  # type: ignore[index]
    after["index"]["index_hash"] = "9" * 64  # type: ignore[index]
    after["index"]["tool_version"] = "1.0.1"  # type: ignore[index]
    after["index"]["future_tool_field"] = "changed"  # type: ignore[index]
    after["index"]["input_manifest"][0][1] = "a" * 64  # type: ignore[index]
    after["documents"][0]["source_hash"] = "a" * 64  # type: ignore[index]
    after["symbols"][0]["display_name"] = "renamed"  # type: ignore[index]
    after["relationships"][0]["target_symbol_key"] = "demo/other#"  # type: ignore[index]
    after["occurrences"][0]["end_character"] = 12  # type: ignore[index]
    after["subject_bindings"][0]["source_hash"] = "a" * 64  # type: ignore[index]
    after["contract_relationships"][0]["required"] = 1  # type: ignore[index]
    after["source_index_policy"]["input_paths"] = ["pyproject.toml", "subject.py"]  # type: ignore[index]
    store = _SnapshotStore({before_hash: before, after_hash: after})

    result = compare_scip_admissions(store, before_hash, after_hash)  # type: ignore[arg-type]

    assert result.index_bytes_changed
    assert result.changed_contract_fields == ("contract_sha256", "future_policy_hash")
    assert result.changed_generation_fields == ("future_tool_field", "tool_version")
    assert result.changed_input_paths == ("subject.py",)
    assert result.changed_document_paths == ("subject.py",)
    assert result.changed_symbol_keys == ("demo/subject().",)
    assert result.changed_relationship_source_keys == ("demo/subject().",)
    assert result.changed_occurrence_document_paths == ("subject.py",)
    assert result.changed_subject_ids == ("subject.demo",)
    assert result.changed_contract_relationship_source_ids == ("subject.demo",)
    assert result.changed_source_index_policy_fields == ("input_paths",)
    assert not result.is_empty


def test_relationship_and_occurrence_storage_order_is_not_a_structural_change():
    admission_hash = "4" * 64
    snapshot = _snapshot(admission_hash, "5" * 64)
    reordered = deepcopy(snapshot)
    second_relationship = deepcopy(reordered["relationships"][0])  # type: ignore[index]
    second_relationship["ordinal"] = 1
    second_relationship["target_symbol_key"] = "demo/other#"
    reordered["relationships"].append(second_relationship)  # type: ignore[union-attr]
    second_occurrence = deepcopy(reordered["occurrences"][0])  # type: ignore[index]
    second_occurrence["ordinal"] = 1
    second_occurrence["start_character"] = 12
    reordered["occurrences"].append(second_occurrence)  # type: ignore[union-attr]
    before = deepcopy(reordered)
    reordered["relationships"].reverse()  # type: ignore[union-attr]
    reordered["occurrences"].reverse()  # type: ignore[union-attr]
    for ordinal, row in enumerate(reordered["relationships"]):  # type: ignore[union-attr]
        row["ordinal"] = ordinal
    for ordinal, row in enumerate(reordered["occurrences"]):  # type: ignore[union-attr]
        row["ordinal"] = ordinal
    store = _SnapshotStore({admission_hash: before})
    store.snapshots["6" * 64] = reordered
    reordered["admission"]["admission_hash"] = "6" * 64  # type: ignore[index]
    for binding in reordered["subject_bindings"]:  # type: ignore[union-attr]
        binding["admission_hash"] = "6" * 64

    result = compare_scip_admissions(store, admission_hash, "6" * 64)  # type: ignore[arg-type]

    assert result.changed_relationship_source_keys == ()
    assert result.changed_occurrence_document_paths == ()


def test_comparison_rejects_a_missing_admission():
    admission_hash = "4" * 64
    store = _SnapshotStore({admission_hash: _snapshot(admission_hash, "5" * 64)})

    with pytest.raises(ValueError, match="both SCIP admissions must exist"):
        compare_scip_admissions(store, admission_hash, "6" * 64)  # type: ignore[arg-type]
