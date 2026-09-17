"""Freshness-aware obligation checking and hierarchical composition gates."""

from __future__ import annotations

from mkso.domain import (
    CheckResult,
    EvidenceStatus,
    NodeStatus,
    Obligation,
    ObligationRole,
    PlannedBinding,
    WorkItem,
)
from mkso.hashing import hash_object, sha256_file
from mkso.store import Store


class Evaluator:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.items = {item.id: item for item in store.work_items()}
        self.obligations = {value.id: value for value in store.obligations()}
        self.by_item: dict[str, list[Obligation]] = {}
        for obligation in self.obligations.values():
            self.by_item.setdefault(obligation.work_item_id, []).append(obligation)
        self.children: dict[str | None, list[WorkItem]] = {}
        for item in self.items.values():
            self.children.setdefault(item.parent_id, []).append(item)
        for values in self.children.values():
            values.sort(key=lambda item: (item.position, item.id))

    def _binding_payload(self, binding: PlannedBinding) -> dict[str, object]:
        path = self.store.project_root / binding.file
        current_hash = sha256_file(path) if path.is_file() else None
        return {
            "obligation_id": binding.obligation_id,
            "file": binding.file,
            "qualified_name": binding.qualified_name,
            "signature": binding.signature,
            "rationale": binding.rationale,
            "expected_symbol": binding.expected_symbol,
            "symbol_id": binding.symbol_id,
            "indexed_admission_hash": binding.indexed_admission_hash,
            "current_source_hash": current_hash,
        }

    @staticmethod
    def _obligation_record(obligation: Obligation) -> dict[str, object]:
        return {
            "id": obligation.id,
            "work_item_id": obligation.work_item_id,
            "title": obligation.title,
            "statement": obligation.statement,
            "role": obligation.role.value,
            "required_evidence": [value.value for value in obligation.required_evidence],
            "checker_policies": [
                {
                    "kind": policy.kind.value,
                    "tool": policy.tool,
                    "command": list(policy.command),
                    "inputs": list(policy.inputs),
                    "artifact_path": policy.artifact_path,
                }
                for policy in obligation.checker_policies
            ],
            "assumptions": list(obligation.assumptions),
            "guarantees": list(obligation.guarantees),
        }

    def _checker_input_payload(self, obligation: Obligation) -> list[dict[str, object]]:
        values: list[dict[str, object]] = []
        for policy in obligation.checker_policies:
            for relative in policy.inputs:
                path = self.store.project_root / relative
                values.append(
                    {
                        "kind": policy.kind.value,
                        "path": relative,
                        "sha256": sha256_file(path) if path.is_file() else None,
                    }
                )
        return values

    def _subtree_payload(self, item_id: str) -> dict[str, object]:
        item = self.items[item_id]
        obligations = sorted(self.by_item.get(item_id, []), key=lambda value: value.id)
        return {
            "item": {
                "id": item.id,
                "kind": item.kind.value,
                "title": item.title,
                "description": item.description,
                "parent_id": item.parent_id,
            },
            "obligations": [
                {
                    **self._obligation_record(obligation),
                    "checker_inputs": self._checker_input_payload(obligation),
                    "bindings": [
                        self._binding_payload(binding)
                        for binding in self.store.bindings(obligation.id)
                    ],
                }
                for obligation in obligations
            ],
            "children": [
                self._subtree_payload(child.id) for child in self.children.get(item_id, [])
            ],
        }

    def subject_digest(self, obligation_id: str) -> str:
        obligation = self.obligations.get(obligation_id)
        if obligation is None:
            raise KeyError(f"unknown obligation: {obligation_id}")
        if obligation.role is ObligationRole.COMPOSITION:
            payload: object = self._subtree_payload(obligation.work_item_id)
        else:
            payload = {
                "obligation": self._obligation_record(obligation),
                "checker_inputs": self._checker_input_payload(obligation),
                "bindings": [
                    self._binding_payload(binding) for binding in self.store.bindings(obligation.id)
                ],
            }
        return hash_object(
            {
                "active_scip_admission_hash": self.store.metadata("active_scip_admission_hash"),
                "subject": payload,
            }
        )

    def _binding_reasons(self, obligation: Obligation) -> list[str]:
        reasons = self.store.scip_freshness_reasons()
        for policy in obligation.checker_policies:
            for relative in policy.inputs:
                if not (self.store.project_root / relative).is_file():
                    reasons.append(f"checker input is missing: {relative}")
        bindings = self.store.bindings(obligation.id)
        if obligation.role is ObligationRole.BEHAVIOR and not bindings:
            reasons.append("no implementation binding")
        for binding in bindings:
            if not binding.symbol_id:
                reasons.append(f"unresolved SCIP symbol {binding.file}:{binding.expected_symbol}")
                continue
            if binding.indexed_admission_hash != self.store.metadata("active_scip_admission_hash"):
                reasons.append(f"SCIP admission is stale: {binding.file}")
                continue
            path = self.store.project_root / binding.file
            if not path.is_file():
                reasons.append(f"bound source is missing: {binding.file}")
                continue
            current = sha256_file(path)
            if current != binding.indexed_source_hash:
                reasons.append(f"source index is stale: {binding.file}")
        return reasons

    def check_obligation(self, obligation_id: str) -> CheckResult:
        obligation = self.obligations[obligation_id]
        reasons = self._binding_reasons(obligation)
        current_digest = self.subject_digest(obligation_id)
        details: dict[str, object] = {
            "role": obligation.role.value,
            "required_evidence": [value.value for value in obligation.required_evidence],
            "subject_digest": current_digest,
            "evidence": {},
        }
        failed = False
        all_evidence = self.store.evidence(obligation_id)
        for required_kind in obligation.required_evidence:
            candidates = [value for value in all_evidence if value.kind is required_kind]
            fresh = []
            stale_count = 0
            for candidate in candidates:
                if candidate.subject_digest != current_digest:
                    stale_count += 1
                    continue
                if candidate.artifact_path:
                    artifact = self.store.project_root / candidate.artifact_path
                    if not artifact.is_file() or sha256_file(artifact) != candidate.artifact_sha256:
                        stale_count += 1
                        continue
                fresh.append(candidate)
            latest = fresh[0] if fresh else None
            evidence_detail = {
                "fresh": latest.id if latest else None,
                "status": latest.status.value if latest else None,
                "stale_count": stale_count,
            }
            details["evidence"][required_kind.value] = evidence_detail  # type: ignore[index]
            if latest is None:
                reasons.append(f"missing fresh {required_kind.value} evidence")
            elif latest.status is not EvidenceStatus.PASSED:
                failed = True
                reasons.append(
                    f"latest {required_kind.value} evidence {latest.id} is {latest.status.value}"
                )
        status = (
            NodeStatus.FAILED
            if failed
            else (NodeStatus.INCOMPLETE if reasons else NodeStatus.VERIFIED)
        )
        return CheckResult(
            id=obligation.id,
            status=status,
            reasons=tuple(reasons),
            details=details,
        )

    def check_item(self, item_id: str) -> CheckResult:
        item = self.items[item_id]
        direct = tuple(
            self.check_obligation(value.id)
            for value in sorted(self.by_item.get(item_id, []), key=lambda value: value.id)
        )
        child_results = tuple(self.check_item(child.id) for child in self.children.get(item_id, []))
        all_results = (*direct, *child_results)
        reasons: list[str] = []
        if not direct:
            reasons.append("work item owns no obligations")
        if child_results and not any(
            obligation.role is ObligationRole.COMPOSITION
            for obligation in self.by_item.get(item_id, [])
        ):
            reasons.append("non-leaf has no composition obligation")
        failed = any(value.status is NodeStatus.FAILED for value in all_results)
        incomplete = any(value.status is NodeStatus.INCOMPLETE for value in all_results)
        if failed:
            reasons.append("at least one child or obligation failed")
            status = NodeStatus.FAILED
        elif incomplete or reasons:
            reasons.append("at least one child or obligation is incomplete")
            status = NodeStatus.INCOMPLETE
        else:
            status = NodeStatus.VERIFIED
        return CheckResult(
            id=item.id,
            status=status,
            reasons=tuple(dict.fromkeys(reasons)),
            children=all_results,
            details={"kind": item.kind.value, "title": item.title},
        )

    def check_project(self) -> CheckResult:
        roots = tuple(self.check_item(item.id) for item in self.children.get(None, []))
        failed = any(root.status is NodeStatus.FAILED for root in roots)
        incomplete = any(root.status is NodeStatus.INCOMPLETE for root in roots)
        if not roots:
            return CheckResult(
                id=self.store.metadata("project_id") or "project",
                status=NodeStatus.INCOMPLETE,
                reasons=("no active work-item graph",),
            )
        status = (
            NodeStatus.FAILED
            if failed
            else (NodeStatus.INCOMPLETE if incomplete else NodeStatus.VERIFIED)
        )
        return CheckResult(
            id=self.store.metadata("project_id") or "project",
            status=status,
            reasons=() if status is NodeStatus.VERIFIED else ("root verification is not complete",),
            children=roots,
            details={
                "name": self.store.metadata("project_name"),
                "active_plan_hash": self.store.metadata("active_plan_hash"),
            },
        )


def current_subject_digest(store: Store, obligation_id: str) -> str:
    return Evaluator(store).subject_digest(obligation_id)
