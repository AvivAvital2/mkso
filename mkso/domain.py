"""Small, dependency-free domain types shared across mkso."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeKind(StrEnum):
    THEME = "theme"
    EPIC = "epic"
    STORY = "story"
    TASK = "task"


NODE_KIND_RANK: dict[NodeKind, int] = {
    NodeKind.THEME: 4,
    NodeKind.EPIC: 3,
    NodeKind.STORY: 2,
    NodeKind.TASK: 1,
}


class ObligationRole(StrEnum):
    BEHAVIOR = "behavior"
    COMPOSITION = "composition"


class EvidenceKind(StrEnum):
    TEST = "test"
    MUTATION = "mutation"
    CONTRACT = "contract"
    STATIC_ANALYSIS = "static_analysis"
    FORMAL_PROOF = "formal_proof"
    COMPOSITION = "composition"


class EvidenceStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class NodeStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True, slots=True)
class CheckerPolicy:
    kind: EvidenceKind
    tool: str
    command: tuple[str, ...]
    inputs: tuple[str, ...]
    artifact_path: str | None = None


@dataclass(frozen=True, slots=True)
class WorkItem:
    id: str
    kind: NodeKind
    title: str
    description: str = ""
    parent_id: str | None = None
    position: int = 0


@dataclass(frozen=True, slots=True)
class Obligation:
    id: str
    work_item_id: str
    title: str
    statement: str
    role: ObligationRole
    required_evidence: tuple[EvidenceKind, ...]
    checker_policies: tuple[CheckerPolicy, ...]
    assumptions: tuple[str, ...] = ()
    guarantees: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PlannedBinding:
    obligation_id: str
    file: str
    qualified_name: str
    signature: str
    rationale: str
    expected_symbol: str
    symbol_id: str | None = None
    indexed_source_hash: str | None = None
    indexed_admission_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    obligation_id: str
    kind: EvidenceKind
    tool: str
    command: tuple[str, ...]
    status: EvidenceStatus
    subject_digest: str
    exit_code: int | None
    artifact_path: str | None
    artifact_sha256: str | None
    stdout: str
    stderr: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CheckResult:
    id: str
    status: NodeStatus
    reasons: tuple[str, ...] = ()
    children: tuple[CheckResult, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "reasons": list(self.reasons),
            "children": [child.to_dict() for child in self.children],
            "details": self.details,
        }
