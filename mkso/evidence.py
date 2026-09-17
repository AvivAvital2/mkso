"""Execute a deterministic checker and record its result as auditable evidence."""

from __future__ import annotations

import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

from mkso.domain import Evidence, EvidenceKind, EvidenceStatus
from mkso.evaluation import current_subject_digest
from mkso.hashing import sha256_file
from mkso.store import Store

_OUTPUT_LIMIT = 200_000


def run_evidence(
    store: Store,
    *,
    obligation_id: str,
    kind: EvidenceKind,
    tool: str,
    command: list[str],
    artifact: Path | None = None,
    timeout_seconds: float = 300.0,
) -> Evidence:
    obligation = store.obligation(obligation_id)
    if not command:
        raise ValueError("checker command must not be empty")
    matching_policies = [
        policy
        for policy in obligation.checker_policies
        if policy.kind is kind and policy.tool == tool and policy.command == tuple(command)
    ]
    if len(matching_policies) != 1:
        raise ValueError(
            "checker invocation is not frozen in the accepted plan for "
            f"{obligation_id}/{kind.value}: tool={tool!r}, command={command!r}"
        )
    policy = matching_policies[0]
    if artifact is None and policy.artifact_path is not None:
        artifact = Path(policy.artifact_path)
    if artifact is not None:
        artifact_resolved = (
            artifact.resolve()
            if artifact.is_absolute()
            else (store.project_root / artifact).resolve()
        )
        try:
            supplied = artifact_resolved.relative_to(store.project_root).as_posix()
        except ValueError as exc:
            raise ValueError("evidence artifact must be inside the project") from exc
        if policy.artifact_path != supplied:
            raise ValueError(
                f"artifact {supplied!r} differs from accepted policy {policy.artifact_path!r}"
            )
    elif policy.artifact_path is not None:
        raise ValueError("accepted checker policy requires an artifact")
    subject_digest = current_subject_digest(store, obligation_id)
    status = EvidenceStatus.ERROR
    exit_code: int | None = None
    stdout = ""
    stderr = ""
    try:
        completed = subprocess.run(
            command,
            cwd=store.project_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        exit_code = completed.returncode
        stdout = completed.stdout[-_OUTPUT_LIMIT:]
        stderr = completed.stderr[-_OUTPUT_LIMIT:]
        status = EvidenceStatus.PASSED if completed.returncode == 0 else EvidenceStatus.FAILED
    except subprocess.TimeoutExpired as exc:
        stderr = f"checker timed out after {timeout_seconds}s: {exc}"
    except OSError as exc:
        stderr = f"checker could not be executed: {exc}"

    artifact_path: str | None = None
    artifact_hash: str | None = None
    if artifact is not None:
        resolved = artifact if artifact.is_absolute() else store.project_root / artifact
        try:
            artifact_path = resolved.resolve().relative_to(store.project_root).as_posix()
        except ValueError as exc:
            raise ValueError("evidence artifact must be inside the project") from exc
        if status is EvidenceStatus.PASSED and not resolved.is_file():
            status = EvidenceStatus.ERROR
            stderr += "\nchecker passed but the declared artifact is missing"
        if resolved.is_file():
            artifact_hash = sha256_file(resolved)

    evidence = Evidence(
        id=f"ev-{uuid.uuid4().hex}",
        obligation_id=obligation_id,
        kind=kind,
        tool=tool,
        command=tuple(command),
        status=status,
        subject_digest=subject_digest,
        exit_code=exit_code,
        artifact_path=artifact_path,
        artifact_sha256=artifact_hash,
        stdout=stdout,
        stderr=stderr,
        created_at=datetime.now(UTC).isoformat(),
    )
    store.add_evidence(evidence)
    return evidence
