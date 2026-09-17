"""Export an immutable graph and direct-SCIP snapshot."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from mkso.evaluation import Evaluator
from mkso.store import Store


def snapshot(store: Store) -> dict[str, Any]:
    evaluator = Evaluator(store)
    return {
        "schema_version": 1,
        "project": {
            "id": store.metadata("project_id"),
            "name": store.metadata("project_name"),
            "plan_hash": store.metadata("active_plan_hash"),
        },
        "work_items": [
            {
                **asdict(item),
                "kind": item.kind.value,
            }
            for item in store.work_items()
        ],
        "obligations": [
            {
                **asdict(obligation),
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
            }
            for obligation in store.obligations()
        ],
        "bindings": [asdict(binding) for binding in store.bindings()],
        "scip": store.scip_snapshot(),
        "evidence": [
            {
                **asdict(evidence),
                "kind": evidence.kind.value,
                "status": evidence.status.value,
            }
            for evidence in store.evidence()
        ],
        "evaluation": evaluator.check_project().to_dict(),
    }
