from __future__ import annotations

from typing import Any


def source_index_contract(
    indexed_paths: tuple[str, ...],
    *,
    input_paths: tuple[str, ...] | None = None,
) -> dict[str, object]:
    """Build the one strict test-only SCIP policy and its referenced tool."""
    return {
        "source_index_policy": {
            "tool_requirement_id": "tool.test-scip",
            "mode": "full_target",
            "indexed_paths": list(indexed_paths),
            "input_paths": list(indexed_paths if input_paths is None else input_paths),
            "language_ids": [{"contract_language": "python", "scip_language": "Python"}],
            "inter_subject_relationship_policy": "closed_world_declared_edges",
            "unmappable_structure_effect": "CONTRACT_VIOLATION_REQUIRES_AMENDMENT",
        },
        "tool_requirements": [{"id": "tool.test-scip"}],
    }


def scip_subject_binding(
    expected_symbol: str,
    expected_relationships: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the current-only explicit SCIP subject binding used by tests."""
    return {
        "family": "scip",
        "profile_id": "python-scip-v1",
        "selector": {
            "state": "planned",
            "symbol": None,
            "expected_symbol": expected_symbol,
            "expected_relationships": (
                [] if expected_relationships is None else expected_relationships
            ),
        },
    }
