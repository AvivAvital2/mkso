"""Accepted-plan loading and deterministic structural validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mkso.domain import (
    NODE_KIND_RANK,
    CheckerPolicy,
    EvidenceKind,
    NodeKind,
    Obligation,
    ObligationRole,
    PlannedBinding,
    WorkItem,
)
from mkso.hashing import canonical_json, sha256_text
from mkso.signatures import normalize_python_function_signature
from mkso.store import Store

_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")


@dataclass(frozen=True, slots=True)
class Manifest:
    project_id: str
    project_name: str
    work_items: tuple[WorkItem, ...]
    obligations: tuple[Obligation, ...]
    bindings: tuple[PlannedBinding, ...]
    raw: dict[str, Any]

    @property
    def canonical(self) -> str:
        return canonical_json(self.raw)

    @property
    def digest(self) -> str:
        return sha256_text(self.canonical)


def _expect_text(value: Any, location: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"{location} must be a non-empty string")
    return value.strip() if not allow_empty else value


def _expect_id(value: Any, location: str) -> str:
    result = _expect_text(value, location)
    if not _ID.fullmatch(result):
        raise ValueError(f"{location} must match {_ID.pattern!r}; got {result!r}")
    return result


def _text_list(value: Any, location: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{location} must be a list")
    return tuple(_expect_text(item, f"{location}[]") for item in value)


def load_manifest(path: Path) -> Manifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("manifest root must be an object")
    if raw.get("schema_version") != 1:
        raise ValueError("manifest schema_version must be 1")
    project = raw.get("project")
    if not isinstance(project, dict):
        raise ValueError("project must be an object")
    project_id = _expect_id(project.get("id"), "project.id")
    project_name = _expect_text(project.get("name"), "project.name")

    raw_items = raw.get("work_items")
    raw_obligations = raw.get("obligations")
    raw_bindings = raw.get("bindings", [])
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("work_items must be a non-empty list")
    if not isinstance(raw_obligations, list) or not raw_obligations:
        raise ValueError("obligations must be a non-empty list")
    if not isinstance(raw_bindings, list):
        raise ValueError("bindings must be a list")

    items: list[WorkItem] = []
    for index, value in enumerate(raw_items):
        if not isinstance(value, dict):
            raise ValueError(f"work_items[{index}] must be an object")
        location = f"work_items[{index}]"
        parent = value.get("parent_id")
        items.append(
            WorkItem(
                id=_expect_id(value.get("id"), f"{location}.id"),
                kind=NodeKind(_expect_text(value.get("kind"), f"{location}.kind")),
                title=_expect_text(value.get("title"), f"{location}.title"),
                description=_expect_text(
                    value.get("description", ""),
                    f"{location}.description",
                    allow_empty=True,
                ),
                parent_id=None if parent is None else _expect_id(parent, f"{location}.parent_id"),
                position=int(value.get("position", index)),
            )
        )

    obligations: list[Obligation] = []
    for index, value in enumerate(raw_obligations):
        if not isinstance(value, dict):
            raise ValueError(f"obligations[{index}] must be an object")
        location = f"obligations[{index}]"
        raw_evidence = value.get("evidence")
        if not isinstance(raw_evidence, list) or not raw_evidence:
            raise ValueError(f"{location}.evidence must be a non-empty list")
        policies: list[CheckerPolicy] = []
        for evidence_index, evidence in enumerate(raw_evidence):
            evidence_location = f"{location}.evidence[{evidence_index}]"
            if not isinstance(evidence, dict):
                raise ValueError(f"{evidence_location} must be an object")
            command = evidence.get("command")
            if (
                not isinstance(command, list)
                or not command
                or not all(isinstance(part, str) and part for part in command)
            ):
                raise ValueError(f"{evidence_location}.command must be a non-empty string list")
            raw_inputs = evidence.get("inputs")
            if not isinstance(raw_inputs, list) or not raw_inputs:
                raise ValueError(
                    f"{evidence_location}.inputs must be a non-empty project-file list"
                )
            inputs: list[str] = []
            for input_index, input_value in enumerate(raw_inputs):
                input_text = _expect_text(input_value, f"{evidence_location}.inputs[{input_index}]")
                input_path = Path(input_text)
                if input_path.is_absolute() or ".." in input_path.parts:
                    raise ValueError(
                        f"{evidence_location}.inputs[{input_index}] must stay inside the project"
                    )
                inputs.append(input_path.as_posix())
            if len(set(inputs)) != len(inputs):
                raise ValueError(f"{evidence_location}.inputs contains duplicates")
            artifact_path = evidence.get("artifact_path")
            if artifact_path is not None:
                artifact_path = _expect_text(artifact_path, f"{evidence_location}.artifact_path")
                artifact = Path(artifact_path)
                if artifact.is_absolute() or ".." in artifact.parts:
                    raise ValueError(
                        f"{evidence_location}.artifact_path must stay inside the project"
                    )
                artifact_path = artifact.as_posix()
            policies.append(
                CheckerPolicy(
                    kind=EvidenceKind(
                        _expect_text(evidence.get("kind"), f"{evidence_location}.kind")
                    ),
                    tool=_expect_text(evidence.get("tool"), f"{evidence_location}.tool"),
                    command=tuple(command),
                    inputs=tuple(inputs),
                    artifact_path=artifact_path,
                )
            )
        required_evidence = tuple(policy.kind for policy in policies)
        if len(set(required_evidence)) != len(required_evidence):
            raise ValueError(f"{location}.required_evidence contains duplicates")
        obligations.append(
            Obligation(
                id=_expect_id(value.get("id"), f"{location}.id"),
                work_item_id=_expect_id(value.get("work_item_id"), f"{location}.work_item_id"),
                title=_expect_text(value.get("title"), f"{location}.title"),
                statement=_expect_text(value.get("statement"), f"{location}.statement"),
                role=ObligationRole(
                    _expect_text(value.get("role", "behavior"), f"{location}.role")
                ),
                required_evidence=required_evidence,
                checker_policies=tuple(policies),
                assumptions=_text_list(value.get("assumptions"), f"{location}.assumptions"),
                guarantees=_text_list(value.get("guarantees"), f"{location}.guarantees"),
            )
        )

    bindings: list[PlannedBinding] = []
    for index, value in enumerate(raw_bindings):
        if not isinstance(value, dict):
            raise ValueError(f"bindings[{index}] must be an object")
        location = f"bindings[{index}]"
        file = _expect_text(value.get("file"), f"{location}.file")
        path_value = Path(file)
        if path_value.is_absolute() or ".." in path_value.parts:
            raise ValueError(f"{location}.file must stay within the project root")
        signature = _expect_text(value.get("signature"), f"{location}.signature")
        if path_value.suffix == ".py":
            try:
                _, signature_name = normalize_python_function_signature(signature)
            except ValueError as exc:
                raise ValueError(f"{location}.signature: {exc}") from exc
            qualified_name = _expect_text(value.get("qualified_name"), f"{location}.qualified_name")
            if qualified_name.rsplit(".", 1)[-1] != signature_name:
                raise ValueError(
                    f"{location}.signature declares {signature_name!r}, but qualified_name "
                    f"ends in {qualified_name.rsplit('.', 1)[-1]!r}"
                )
        else:
            qualified_name = _expect_text(value.get("qualified_name"), f"{location}.qualified_name")
        bindings.append(
            PlannedBinding(
                obligation_id=_expect_id(value.get("obligation_id"), f"{location}.obligation_id"),
                file=path_value.as_posix(),
                qualified_name=qualified_name,
                signature=signature,
                rationale=_expect_text(value.get("rationale"), f"{location}.rationale"),
                expected_symbol=_expect_text(
                    value.get("expected_symbol"), f"{location}.expected_symbol"
                ),
            )
        )

    manifest = Manifest(
        project_id=project_id,
        project_name=project_name,
        work_items=tuple(items),
        obligations=tuple(obligations),
        bindings=tuple(bindings),
        raw=raw,
    )
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: Manifest) -> None:
    item_by_id = {item.id: item for item in manifest.work_items}
    if len(item_by_id) != len(manifest.work_items):
        raise ValueError("work item IDs must be unique")
    obligation_by_id = {value.id: value for value in manifest.obligations}
    if len(obligation_by_id) != len(manifest.obligations):
        raise ValueError("obligation IDs must be unique")

    roots = [item for item in manifest.work_items if item.parent_id is None]
    if not roots:
        raise ValueError("the work-item graph must contain at least one root")
    for item in manifest.work_items:
        if item.parent_id is None:
            continue
        parent = item_by_id.get(item.parent_id)
        if parent is None:
            raise ValueError(f"{item.id} has unknown parent {item.parent_id}")
        if NODE_KIND_RANK[parent.kind] <= NODE_KIND_RANK[item.kind]:
            raise ValueError(
                f"{parent.id} ({parent.kind}) must be higher-level than {item.id} ({item.kind})"
            )

    for item in manifest.work_items:
        seen: set[str] = set()
        current = item
        while current.parent_id is not None:
            if current.id in seen:
                raise ValueError(f"cycle in work-item graph at {current.id}")
            seen.add(current.id)
            current = item_by_id[current.parent_id]

    obligations_by_item: dict[str, list[Obligation]] = {}
    for obligation in manifest.obligations:
        if obligation.work_item_id not in item_by_id:
            raise ValueError(f"{obligation.id} has unknown work item {obligation.work_item_id}")
        obligations_by_item.setdefault(obligation.work_item_id, []).append(obligation)

    children_by_item: dict[str, list[WorkItem]] = {}
    for item in manifest.work_items:
        if item.parent_id is not None:
            children_by_item.setdefault(item.parent_id, []).append(item)
    for item in manifest.work_items:
        direct = obligations_by_item.get(item.id, [])
        if children_by_item.get(item.id) and not any(
            obligation.role is ObligationRole.COMPOSITION for obligation in direct
        ):
            raise ValueError(
                f"non-leaf {item.id} must own a composition obligation; "
                "verified children do not automatically verify their parent"
            )
        if not direct:
            raise ValueError(f"{item.id} must own at least one obligation")

    bindings_by_obligation: dict[str, list[PlannedBinding]] = {}
    binding_keys: set[tuple[str, str, str]] = set()
    for binding in manifest.bindings:
        obligation = obligation_by_id.get(binding.obligation_id)
        if obligation is None:
            raise ValueError(f"binding has unknown obligation {binding.obligation_id}")
        key = (binding.obligation_id, binding.file, binding.qualified_name)
        if key in binding_keys:
            raise ValueError(f"duplicate binding {key}")
        binding_keys.add(key)
        bindings_by_obligation.setdefault(binding.obligation_id, []).append(binding)

    for obligation in manifest.obligations:
        if obligation.role is ObligationRole.BEHAVIOR and not bindings_by_obligation.get(
            obligation.id
        ):
            raise ValueError(
                f"behavior obligation {obligation.id} must bind to at least one symbol"
            )


def apply_manifest(store: Store, path: Path) -> Manifest:
    manifest = load_manifest(path)
    store.replace_plan(
        plan_hash=manifest.digest,
        applied_at=datetime.now(UTC).isoformat(),
        manifest_json=manifest.canonical,
        work_items=manifest.work_items,
        obligations=manifest.obligations,
        bindings=manifest.bindings,
    )
    with store.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('project_id', ?)",
            (manifest.project_id,),
        )
        conn.execute(
            "INSERT OR REPLACE INTO metadata(key, value) VALUES('project_name', ?)",
            (manifest.project_name,),
        )
    return manifest
