"""Contract-authoritative impact closure over two admitted SCIP snapshots."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mkso.hashing import hash_object
from mkso.scip import (
    ContractSourceIndexPolicy,
    load_contract_document,
    load_contract_source_index_policy,
)
from mkso.scip_compare import ScipAdmissionDiff, compare_scip_admissions
from mkso.store import Store


class ContractImpactError(ValueError):
    """The requested impact calculation is not admitted by the frozen contract."""


@dataclass(frozen=True, slots=True)
class ImpactClosure:
    before_admission_hash: str
    after_admission_hash: str
    contract_path: str
    contract_sha256: str
    comparison_hash: str
    seed_subject_ids: tuple[str, ...]
    affected_subject_ids: tuple[str, ...]
    affected_obligation_ids: tuple[str, ...]
    affected_work_item_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ContractGraph:
    subject_ids: frozenset[str]
    subject_by_document: dict[str, tuple[str, ...]]
    subject_dependency_edges: tuple[tuple[str, str], ...]
    obligation_subjects: dict[str, frozenset[str]]
    obligation_work_items: dict[str, str]
    obligation_roles: dict[str, str]
    work_parents: dict[str, str | None]
    work_dependencies: dict[str, frozenset[str]]


def _mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ContractImpactError(f"{location} must be a string-keyed object")
    return dict(value)


def _object_array(value: object, location: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ContractImpactError(f"{location} must be an array")
    return [_mapping(item, f"{location}[]") for item in value]


def _unique_by_id(value: object, location: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in _object_array(value, location):
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise ContractImpactError(f"{location} item has no non-empty ID")
        if item_id in result:
            raise ContractImpactError(f"{location} contains duplicate ID {item_id}")
        result[item_id] = item
    return result


def _snapshot_rows(snapshot: Mapping[str, object], section: str) -> list[dict[str, Any]]:
    return _object_array(snapshot.get(section), f"SCIP snapshot {section}")


def _require_acyclic(edges: Mapping[str, frozenset[str]], location: str) -> None:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ContractImpactError(f"{location} contains a cycle at {node}")
        if node in visited:
            return
        visiting.add(node)
        for target in edges[node]:
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in sorted(edges):
        visit(node)


def _expected_policy(policy: ContractSourceIndexPolicy) -> dict[str, object]:
    return json.loads(json.dumps(asdict(policy), sort_keys=True, separators=(",", ":")))


def _persisted_relationships(
    snapshot: Mapping[str, object],
) -> tuple[tuple[str, str, str, bool], ...]:
    relationships: list[tuple[str, str, str, bool]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in _snapshot_rows(snapshot, "contract_relationships"):
        source = row.get("source_subject_id")
        kind = row.get("kind")
        target = row.get("target_subject_id")
        required = row.get("required")
        if (
            not isinstance(source, str)
            or not source
            or not isinstance(kind, str)
            or not kind
            or not isinstance(target, str)
            or not target
            or type(required) is not int
            or required not in (0, 1)
        ):
            raise ContractImpactError("SCIP snapshot contains a malformed contract relationship")
        key = (source, kind, target)
        if key in seen:
            raise ContractImpactError("SCIP snapshot repeats a contract relationship")
        seen.add(key)
        relationships.append((*key, bool(required)))
    return tuple(sorted(relationships))


def _contract_graph(
    contract: dict[str, Any],
    before: Mapping[str, object],
    after: Mapping[str, object],
    expected_policy: dict[str, object],
) -> _ContractGraph:
    subjects = _unique_by_id(contract.get("subjects"), "contract subjects")
    work_items = _unique_by_id(contract.get("work_items"), "contract work_items")
    obligations = _unique_by_id(contract.get("obligations"), "contract obligations")

    subject_by_document: dict[str, list[str]] = {}
    scip_subject_by_document: dict[str, list[str]] = {}
    expected_bindings: dict[str, tuple[str, str]] = {}
    declared_relationships: list[tuple[str, str, str, bool]] = []
    declared_relationship_keys: set[tuple[str, str, str]] = set()
    dependency_edges: set[tuple[str, str]] = set()
    for subject_id, subject in subjects.items():
        location = _mapping(subject.get("location"), f"subject {subject_id} location")
        binding = _mapping(subject.get("binding"), f"subject {subject_id} binding")
        path = location.get("path")
        if not isinstance(path, str) or not path:
            raise ContractImpactError(f"subject {subject_id} has no exact path")
        subject_by_document.setdefault(path, []).append(subject_id)
        family = binding.get("family")
        if family == "managed_artifact":
            continue
        if family != "scip":
            raise ContractImpactError(f"subject {subject_id} has an unsupported binding family")
        scip = _mapping(binding.get("selector"), f"subject {subject_id} SCIP selector")
        symbol = scip.get("expected_symbol")
        if not isinstance(symbol, str) or not symbol:
            raise ContractImpactError(f"subject {subject_id} has no exact SCIP symbol")
        expected_bindings[subject_id] = (path, symbol)
        scip_subject_by_document.setdefault(path, []).append(subject_id)
        for relationship in _object_array(
            scip.get("expected_relationships"),
            f"subject {subject_id} expected_relationships",
        ):
            kind = relationship.get("kind")
            target = relationship.get("target_subject_id")
            required = relationship.get("required", True)
            if not isinstance(kind, str) or not isinstance(target, str) or target not in subjects:
                raise ContractImpactError(f"subject {subject_id} has an unresolved relationship")
            if not isinstance(required, bool):
                raise ContractImpactError(
                    f"subject {subject_id} relationship required is not boolean"
                )
            relationship_key = (subject_id, kind, target)
            if relationship_key in declared_relationship_keys:
                raise ContractImpactError(f"subject {subject_id} repeats a relationship")
            declared_relationship_keys.add(relationship_key)
            record = (*relationship_key, required)
            declared_relationships.append(record)
            dependency_edges.add((subject_id, target))

    for label, snapshot in (("before", before), ("after", after)):
        rows = _snapshot_rows(snapshot, "subject_bindings")
        actual: dict[str, tuple[str, str]] = {}
        for row in rows:
            subject_id = row.get("subject_id")
            path = row.get("document_path")
            symbol = row.get("symbol")
            if not all(isinstance(value, str) and value for value in (subject_id, path, symbol)):
                raise ContractImpactError(f"{label} admission has a malformed subject binding")
            if subject_id in actual:
                raise ContractImpactError(f"{label} admission repeats subject {subject_id}")
            actual[subject_id] = (path, symbol)
        if actual != expected_bindings:
            raise ContractImpactError(
                f"{label} admission subject bindings differ from the frozen contract"
            )
        if _persisted_relationships(snapshot) != tuple(sorted(declared_relationships)):
            raise ContractImpactError(
                f"{label} admission relationships differ from the frozen contract"
            )
        if (
            _mapping(
                snapshot.get("source_index_policy"),
                f"{label} source_index_policy",
            )
            != expected_policy
        ):
            raise ContractImpactError(
                f"{label} admission source-index policy differs from the frozen contract"
            )

    indexed_paths = expected_policy.get("indexed_paths")
    if not isinstance(indexed_paths, list) or set(indexed_paths) != set(scip_subject_by_document):
        raise ContractImpactError(
            "every indexed document must map to at least one frozen contract subject"
        )

    work_parents: dict[str, str | None] = {}
    work_dependencies: dict[str, frozenset[str]] = {}
    for work_id, work in work_items.items():
        parent = work.get("parent_id")
        if parent is not None and (not isinstance(parent, str) or parent not in work_items):
            raise ContractImpactError(f"work item {work_id} has an unresolved parent")
        raw_dependencies = work.get("dependency_ids", [])
        if not isinstance(raw_dependencies, list) or not all(
            isinstance(value, str) and value in work_items for value in raw_dependencies
        ):
            raise ContractImpactError(f"work item {work_id} has unresolved dependencies")
        if len(raw_dependencies) != len(set(raw_dependencies)):
            raise ContractImpactError(f"work item {work_id} repeats a dependency")
        work_parents[work_id] = parent
        work_dependencies[work_id] = frozenset(raw_dependencies)
    hierarchy_edges = {
        work_id: frozenset(() if parent is None else (parent,))
        for work_id, parent in work_parents.items()
    }
    _require_acyclic(hierarchy_edges, "contract work hierarchy")
    _require_acyclic(work_dependencies, "contract work dependency graph")

    obligation_subjects: dict[str, frozenset[str]] = {}
    obligation_work_items: dict[str, str] = {}
    obligation_roles: dict[str, str] = {}
    covered_subjects: set[str] = set()
    for obligation_id, obligation in obligations.items():
        work_id = obligation.get("work_item_id")
        raw_subjects = obligation.get("subject_ids")
        role = obligation.get("role")
        if not isinstance(work_id, str) or work_id not in work_items:
            raise ContractImpactError(f"obligation {obligation_id} has an unresolved work item")
        if (
            not isinstance(raw_subjects, list)
            or not raw_subjects
            or not all(
                isinstance(subject_id, str) and subject_id in subjects
                for subject_id in raw_subjects
            )
        ):
            raise ContractImpactError(f"obligation {obligation_id} has unresolved subjects")
        if len(raw_subjects) != len(set(raw_subjects)):
            raise ContractImpactError(f"obligation {obligation_id} repeats a subject")
        if not isinstance(role, str) or not role:
            raise ContractImpactError(f"obligation {obligation_id} has no role")
        obligation_subjects[obligation_id] = frozenset(raw_subjects)
        obligation_work_items[obligation_id] = work_id
        obligation_roles[obligation_id] = role
        covered_subjects.update(raw_subjects)
    if covered_subjects != set(subjects):
        raise ContractImpactError("every contract subject must bind to at least one obligation")

    return _ContractGraph(
        subject_ids=frozenset(subjects),
        subject_by_document={
            path: tuple(sorted(subject_ids)) for path, subject_ids in subject_by_document.items()
        },
        subject_dependency_edges=tuple(sorted(dependency_edges)),
        obligation_subjects=obligation_subjects,
        obligation_work_items=obligation_work_items,
        obligation_roles=obligation_roles,
        work_parents=work_parents,
        work_dependencies=work_dependencies,
    )


def _seed_subjects(
    diff: ScipAdmissionDiff,
    graph: _ContractGraph,
    before: Mapping[str, object],
    after: Mapping[str, object],
) -> set[str]:
    if diff.changed_contract_fields:
        raise ContractImpactError("contract identity changed; a signed amendment is required")
    if diff.changed_contract_relationship_source_ids:
        raise ContractImpactError("declared contract relationships changed across admissions")
    if diff.changed_source_index_policy_fields:
        raise ContractImpactError("source-index policy changed; a signed amendment is required")
    allowed_execution_changes = {
        "indexer_stdin_hash",
        "indexer_stdout_hash",
        "indexer_stderr_hash",
    }
    unexpected_execution_changes = set(diff.changed_generation_fields) - allowed_execution_changes
    if unexpected_execution_changes:
        raise ContractImpactError(
            "tool or generation identity changed without a contract revision: "
            + ", ".join(sorted(unexpected_execution_changes))
        )

    seeds: set[str] = set(diff.changed_subject_ids)
    if not seeds <= graph.subject_ids:
        raise ContractImpactError("a changed subject is absent from the frozen contract")

    def add_document(path: str, source: str) -> None:
        subjects = graph.subject_by_document.get(path)
        if subjects is None:
            raise ContractImpactError(
                f"changed {source} {path} is not mapped to a frozen contract subject"
            )
        seeds.update(subjects)

    for path in diff.changed_input_paths:
        add_document(path, "indexer input")
    for path in diff.changed_document_paths:
        add_document(path, "SCIP document")
    for path in diff.changed_occurrence_document_paths:
        add_document(path, "SCIP occurrence document")

    symbol_subjects: dict[str, set[str]] = {}
    for snapshot in (before, after):
        for row in _snapshot_rows(snapshot, "subject_bindings"):
            symbol = row.get("symbol")
            subject_id = row.get("subject_id")
            if isinstance(symbol, str) and isinstance(subject_id, str):
                symbol_subjects.setdefault(symbol, set()).add(subject_id)
    for symbol_key in (*diff.changed_symbol_keys, *diff.changed_relationship_source_keys):
        subjects = symbol_subjects.get(symbol_key)
        if not subjects:
            raise ContractImpactError(
                f"changed SCIP symbol {symbol_key} is not a frozen contract subject"
            )
        seeds.update(subjects)

    if not seeds and (
        diff.index_bytes_changed or diff.changed_generation_fields or not diff.is_empty
    ):
        raise ContractImpactError("the SCIP delta cannot be mapped to the frozen contract graph")
    return seeds


def _close_impact(graph: _ContractGraph, seeds: set[str]) -> tuple[set[str], set[str], set[str]]:
    subjects = set(seeds)
    obligations: set[str] = set()
    work_items: set[str] = set()
    changed = True
    while changed:
        changed = False
        for source, target in graph.subject_dependency_edges:
            if target in subjects and source not in subjects:
                subjects.add(source)
                changed = True
        for obligation_id, bound_subjects in graph.obligation_subjects.items():
            if bound_subjects & subjects and obligation_id not in obligations:
                obligations.add(obligation_id)
                work_items.add(graph.obligation_work_items[obligation_id])
                changed = True
        for work_id, dependencies in graph.work_dependencies.items():
            if dependencies & work_items and work_id not in work_items:
                work_items.add(work_id)
                for obligation_id, obligation_work in graph.obligation_work_items.items():
                    if obligation_work != work_id:
                        continue
                    obligations.add(obligation_id)
                    if graph.obligation_roles[obligation_id] != "composition":
                        subjects.update(graph.obligation_subjects[obligation_id])
                changed = True
        for work_id in tuple(work_items):
            parent = graph.work_parents[work_id]
            if parent is None:
                continue
            if parent not in work_items:
                work_items.add(parent)
                changed = True
            for obligation_id, obligation_work in graph.obligation_work_items.items():
                if (
                    obligation_work == parent
                    and graph.obligation_roles[obligation_id] == "composition"
                    and obligation_id not in obligations
                ):
                    obligations.add(obligation_id)
                    changed = True
    return subjects, obligations, work_items


def compute_scip_impact(
    store: Store,
    before_admission_hash: str,
    after_admission_hash: str,
) -> ImpactClosure:
    """Derive the exact D-033 closure or reject the off-contract delta."""
    if store.metadata("active_scip_admission_hash") != after_admission_hash:
        raise ContractImpactError("the after admission is not the active SCIP admission")
    freshness_reasons = store.scip_freshness_reasons()
    if freshness_reasons:
        raise ContractImpactError("the after admission is stale: " + "; ".join(freshness_reasons))
    before = store.scip_snapshot(before_admission_hash)
    after = store.scip_snapshot(after_admission_hash)
    if before is None or after is None:
        raise ContractImpactError("both SCIP admissions must exist")
    before_admission = _mapping(before.get("admission"), "before SCIP admission")
    after_admission = _mapping(after.get("admission"), "after SCIP admission")
    contract_path = before_admission.get("contract_path")
    contract_sha256 = before_admission.get("contract_sha256")
    if (
        not isinstance(contract_path, str)
        or not isinstance(contract_sha256, str)
        or after_admission.get("contract_path") != contract_path
        or after_admission.get("contract_sha256") != contract_sha256
    ):
        raise ContractImpactError("admissions use different contract revisions")
    loaded_path, _, loaded_hash, contract = load_contract_document(
        Path(contract_path),
        project_root=store.project_root,
    )
    if loaded_path != contract_path or loaded_hash != contract_sha256:
        raise ContractImpactError("the admitted contract revision is not current")
    policy = load_contract_source_index_policy(
        Path(contract_path),
        project_root=store.project_root,
    )
    expected_policy = _expected_policy(policy)
    graph = _contract_graph(contract, before, after, expected_policy)
    diff = compare_scip_admissions(store, before_admission_hash, after_admission_hash)
    seeds = _seed_subjects(diff, graph, before, after)
    subjects, obligations, work_items = _close_impact(graph, seeds)
    return ImpactClosure(
        before_admission_hash=before_admission_hash,
        after_admission_hash=after_admission_hash,
        contract_path=contract_path,
        contract_sha256=contract_sha256,
        comparison_hash=hash_object(asdict(diff)),
        seed_subject_ids=tuple(sorted(seeds)),
        affected_subject_ids=tuple(sorted(subjects)),
        affected_obligation_ids=tuple(sorted(obligations)),
        affected_work_item_ids=tuple(sorted(work_items)),
    )
