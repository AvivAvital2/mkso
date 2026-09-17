from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from mkso.impact import ContractImpactError, compute_scip_impact
from mkso.scip import ScipExpectation, ScipIndexerInvocation
from mkso.scip_codec import SCIP_SCHEMA_PATH
from mkso.store import Store
from tests.scip_support import scip_subject_binding, source_index_contract

TARGET_SYMBOL = "scip-python python impact 0.0.0 target/target()."
CALLER_SYMBOL = "scip-python python impact 0.0.0 caller/caller()."
ROUTE_SYMBOL = "scip-python python impact 0.0.0 route/route()."
INDEXED_PATHS = ("caller.py", "route.py", "target.py")


def _contract(
    *,
    include_configuration_input: bool = False,
    bind_configuration_subject: bool = False,
    include_subject_relationships: bool = True,
    include_work_dependencies: bool = True,
) -> dict[str, Any]:
    input_paths = INDEXED_PATHS
    if include_configuration_input:
        input_paths = ("caller.py", "pyproject.toml", "route.py", "target.py")
    contract: dict[str, Any] = {
        **source_index_contract(INDEXED_PATHS, input_paths=input_paths),
        "work_items": [
            {
                "id": "goal.feature",
                "parent_id": None,
                "dependency_ids": [],
            },
            {
                "id": "task.target",
                "parent_id": "goal.feature",
                "dependency_ids": [],
            },
            {
                "id": "task.caller",
                "parent_id": "goal.feature",
                "dependency_ids": ["task.target"] if include_work_dependencies else [],
            },
            {
                "id": "task.route",
                "parent_id": "goal.feature",
                "dependency_ids": ["task.caller"] if include_work_dependencies else [],
            },
        ],
        "obligations": [
            {
                "id": "obligation.target",
                "work_item_id": "task.target",
                "subject_ids": ["subject.target"],
                "role": "behavior",
            },
            {
                "id": "obligation.caller",
                "work_item_id": "task.caller",
                "subject_ids": ["subject.caller"],
                "role": "behavior",
            },
            {
                "id": "obligation.route",
                "work_item_id": "task.route",
                "subject_ids": ["subject.route"],
                "role": "behavior",
            },
            {
                "id": "obligation.feature.composition",
                "work_item_id": "goal.feature",
                "subject_ids": ["subject.caller", "subject.route", "subject.target"],
                "role": "composition",
            },
        ],
        "subjects": [
            {
                "id": "subject.caller",
                "language": "python",
                "location": {"path": "caller.py"},
                "binding": scip_subject_binding(
                    CALLER_SYMBOL,
                    (
                        [
                            {
                                "kind": "reference",
                                "target_subject_id": "subject.target",
                                "required": True,
                            }
                        ]
                        if include_subject_relationships
                        else []
                    ),
                ),
            },
            {
                "id": "subject.route",
                "language": "python",
                "location": {"path": "route.py"},
                "binding": scip_subject_binding(
                    ROUTE_SYMBOL,
                    (
                        [
                            {
                                "kind": "reference",
                                "target_subject_id": "subject.caller",
                                "required": True,
                            }
                        ]
                        if include_subject_relationships
                        else []
                    ),
                ),
            },
            {
                "id": "subject.target",
                "language": "python",
                "location": {"path": "target.py"},
                "binding": scip_subject_binding(TARGET_SYMBOL),
            },
        ],
    }
    if bind_configuration_subject:
        contract["work_items"].append(
            {
                "id": "task.configuration",
                "parent_id": "goal.feature",
                "dependency_ids": [],
            }
        )
        contract["subjects"].append(
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
            }
        )
        contract["obligations"].append(
            {
                "id": "obligation.configuration",
                "work_item_id": "task.configuration",
                "subject_ids": ["subject.configuration"],
                "role": "behavior",
            }
        )
        composition = next(
            item
            for item in contract["obligations"]
            if item["id"] == "obligation.feature.composition"
        )
        composition["subject_ids"].append("subject.configuration")
    return contract


def _textproto(
    *,
    tool_version: str = "1.0.0",
    include_relationship_occurrences: bool = True,
) -> str:
    caller_reference = (
        f'occurrences {{ range: 3 range: 11 range: 17 symbol: "{TARGET_SYMBOL}" symbol_roles: 8 }}'
        if include_relationship_occurrences
        else ""
    )
    route_reference = (
        f'occurrences {{ range: 3 range: 11 range: 17 symbol: "{CALLER_SYMBOL}" symbol_roles: 8 }}'
        if include_relationship_occurrences
        else ""
    )
    return f'''
metadata {{
  tool_info {{ name: "test-scip" version: "{tool_version}" }}
  project_root: "file:///workspace"
  text_document_encoding: UTF8
}}
documents {{
  relative_path: "caller.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 2 range: 4 range: 10 symbol: "{CALLER_SYMBOL}" symbol_roles: 1
    enclosing_range: 2 enclosing_range: 0 enclosing_range: 4 enclosing_range: 0
  }}
  {caller_reference}
  symbols {{ symbol: "{CALLER_SYMBOL}" kind: Function }}
}}
documents {{
  relative_path: "route.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 2 range: 4 range: 9 symbol: "{ROUTE_SYMBOL}" symbol_roles: 1
    enclosing_range: 2 enclosing_range: 0 enclosing_range: 4 enclosing_range: 0
  }}
  {route_reference}
  symbols {{ symbol: "{ROUTE_SYMBOL}" kind: Function }}
}}
documents {{
  relative_path: "target.py"
  language: "Python"
  position_encoding: UTF8CodeUnitOffsetFromLineStart
  occurrences {{
    range: 0 range: 4 range: 10 symbol: "{TARGET_SYMBOL}" symbol_roles: 1
    enclosing_range: 0 enclosing_range: 0 enclosing_range: 2 enclosing_range: 0
  }}
  symbols {{ symbol: "{TARGET_SYMBOL}" kind: Function }}
}}
'''


def _initialize_project(
    tmp_path: Path,
    *,
    include_configuration_input: bool = False,
    bind_configuration_subject: bool = False,
    include_subject_relationships: bool = True,
    include_work_dependencies: bool = True,
) -> Store:
    (tmp_path / "caller.py").write_text(
        "from target import target\n\ndef caller():\n    return target()\n",
        encoding="utf-8",
    )
    (tmp_path / "route.py").write_text(
        "from caller import caller\n\ndef route():\n    return caller()\n",
        encoding="utf-8",
    )
    (tmp_path / "target.py").write_text("def target():\n    return 1\n", encoding="utf-8")
    if include_configuration_input:
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "impact"\n', encoding="utf-8")
    (tmp_path / "contract.json").write_text(
        json.dumps(
            _contract(
                include_configuration_input=include_configuration_input,
                bind_configuration_subject=bind_configuration_subject,
                include_subject_relationships=include_subject_relationships,
                include_work_dependencies=include_work_dependencies,
            )
        ),
        encoding="utf-8",
    )
    return Store.initialize(tmp_path)


def _admit(
    store: Store,
    scip_decoder,
    *,
    tool_version: str = "1.0.0",
    include_configuration_input: bool = False,
    include_relationship_occurrences: bool = True,
) -> str:
    input_paths = INDEXED_PATHS
    if include_configuration_input:
        input_paths = ("caller.py", "pyproject.toml", "route.py", "target.py")
    invocation = ScipIndexerInvocation(
        executable_path=Path(scip_decoder.identity.protoc_path),
        executable_sha256=scip_decoder.identity.protoc_sha256,
        arguments=(
            "--encode=scip.Index",
            f"--proto_path={SCIP_SCHEMA_PATH.parent}",
            SCIP_SCHEMA_PATH.name,
        ),
        environment=(),
        input_files=input_paths,
        indexed_files=INDEXED_PATHS,
        timeout_seconds=30,
    )
    expectation = ScipExpectation("test-scip", tool_version, (), "file:///workspace")
    receipt = store.admit_scip_index(
        scip_decoder,
        expectation,
        invocation,
        store.project_root / "contract.json",
        stdin_payload=_textproto(
            tool_version=tool_version,
            include_relationship_occurrences=include_relationship_occurrences,
        ).encode("utf-8"),
    )
    return receipt.admission_hash


def test_contract_graph_closes_changed_leaf_through_subjects_work_and_composition(
    tmp_path, scip_decoder
):
    store = _initialize_project(tmp_path, include_work_dependencies=False)
    before = _admit(store, scip_decoder)
    (tmp_path / "target.py").write_text("def target():\n    return 2\n", encoding="utf-8")
    after = _admit(store, scip_decoder)

    impact = compute_scip_impact(store, before, after)

    assert impact.seed_subject_ids == ("subject.target",)
    assert impact.affected_subject_ids == (
        "subject.caller",
        "subject.route",
        "subject.target",
    )
    assert impact.affected_obligation_ids == (
        "obligation.caller",
        "obligation.feature.composition",
        "obligation.route",
        "obligation.target",
    )
    assert impact.affected_work_item_ids == (
        "goal.feature",
        "task.caller",
        "task.route",
        "task.target",
    )


def test_contract_graph_follows_dependencies_only_toward_dependents(tmp_path, scip_decoder):
    store = _initialize_project(tmp_path, include_work_dependencies=False)
    before = _admit(store, scip_decoder)
    (tmp_path / "caller.py").write_text(
        "from target import target\n\ndef caller():\n    return target() + 0\n",
        encoding="utf-8",
    )
    after = _admit(store, scip_decoder)

    impact = compute_scip_impact(store, before, after)

    assert impact.seed_subject_ids == ("subject.caller",)
    assert impact.affected_subject_ids == ("subject.caller", "subject.route")
    assert impact.affected_obligation_ids == (
        "obligation.caller",
        "obligation.feature.composition",
        "obligation.route",
    )
    assert impact.affected_work_item_ids == (
        "goal.feature",
        "task.caller",
        "task.route",
    )


def test_contract_graph_closes_work_dependencies_without_subject_edges(tmp_path, scip_decoder):
    store = _initialize_project(tmp_path, include_subject_relationships=False)
    before = _admit(store, scip_decoder, include_relationship_occurrences=False)
    (tmp_path / "target.py").write_text("def target():\n    return 2\n", encoding="utf-8")
    after = _admit(store, scip_decoder, include_relationship_occurrences=False)

    impact = compute_scip_impact(store, before, after)

    assert impact.seed_subject_ids == ("subject.target",)
    assert impact.affected_subject_ids == (
        "subject.caller",
        "subject.route",
        "subject.target",
    )
    assert impact.affected_obligation_ids == (
        "obligation.caller",
        "obligation.feature.composition",
        "obligation.route",
        "obligation.target",
    )
    assert impact.affected_work_item_ids == (
        "goal.feature",
        "task.caller",
        "task.route",
        "task.target",
    )


def test_unmapped_configuration_delta_requires_contract_amendment(tmp_path, scip_decoder):
    store = _initialize_project(tmp_path, include_configuration_input=True)
    before = _admit(store, scip_decoder, include_configuration_input=True)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "impact-renamed"\n',
        encoding="utf-8",
    )
    after = _admit(store, scip_decoder, include_configuration_input=True)

    with pytest.raises(
        ContractImpactError,
        match=r"changed indexer input pyproject\.toml is not mapped",
    ):
        compute_scip_impact(store, before, after)


def test_managed_configuration_delta_maps_to_frozen_subject(tmp_path, scip_decoder):
    store = _initialize_project(
        tmp_path,
        include_configuration_input=True,
        bind_configuration_subject=True,
    )
    before = _admit(store, scip_decoder, include_configuration_input=True)
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "impact-renamed"\n',
        encoding="utf-8",
    )
    after = _admit(store, scip_decoder, include_configuration_input=True)

    impact = compute_scip_impact(store, before, after)

    assert impact.seed_subject_ids == ("subject.configuration",)
    assert impact.affected_subject_ids == ("subject.configuration",)
    assert impact.affected_obligation_ids == (
        "obligation.configuration",
        "obligation.feature.composition",
    )
    assert impact.affected_work_item_ids == ("goal.feature", "task.configuration")


def test_tool_identity_delta_requires_contract_revision(tmp_path, scip_decoder):
    store = _initialize_project(tmp_path)
    before = _admit(store, scip_decoder)
    after = _admit(store, scip_decoder, tool_version="1.0.1")

    with pytest.raises(
        ContractImpactError,
        match="tool or generation identity changed without a contract revision: tool_version",
    ):
        compute_scip_impact(store, before, after)
