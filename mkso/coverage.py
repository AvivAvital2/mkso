"""Exact objective-to-suite-to-run joins against the active SCIP admission.

This module establishes structural provenance only.  It deliberately does not
parse coverage artifacts, decide whether a coverage kind's success rule was
met, or treat a runner-reported result as proof of an obligation.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Any, Protocol

from mkso.hashing import hash_object

_HASH_PREFIX = "sha256:"
_RAW_RESULTS = frozenset({"SATISFIED", "VIOLATED", "INCONCLUSIVE", "ERROR"})


class _CoverageStore(Protocol):
    def metadata(self, key: str) -> str | None: ...

    def scip_freshness_reasons(self) -> list[str]: ...

    def scip_snapshot(self, admission_hash: str) -> dict[str, object] | None: ...


class CoverageJoinError(ValueError):
    """Coverage records cannot be joined exactly to current contract subjects."""


@dataclass(frozen=True, slots=True)
class CoverageSubjectJoin:
    objective_id: str
    objective_hash: str
    obligation_id: str
    requirement_id: str
    coverage_kind: str
    coverage_target: str
    subject_id: str
    source_path: str
    scip_symbol: str
    source_hash: str
    scip_index_hash: str
    tool_id: str
    artifact_format: str
    raw_artifact_hash: str
    trusted_parser_id: str
    trusted_parser_hash: str
    reported_result: str
    measured_fraction: float | None
    reached_values_hash: str | None


@dataclass(frozen=True, slots=True)
class CoverageJoin:
    """A deterministic structural join, not an evidence or proof certificate."""

    scip_admission_hash: str
    scip_index_hash: str
    contract_hash: str
    node_id: str
    channel: str
    suite_hash: str
    suite_assignment_hash: str
    run_hash: str
    entries: tuple[CoverageSubjectJoin, ...]
    join_hash: str


@dataclass(frozen=True, slots=True)
class _ExpectedRequirement:
    objective_id: str
    objective_hash: str
    obligation_id: str
    requirement_id: str
    kind: str
    target: str
    subject_ids: tuple[str, ...]
    targets: dict[str, tuple[str, str]]
    tool_ids: frozenset[str]


def _mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise CoverageJoinError(f"{location} must be a string-keyed object")
    return dict(value)


def _objects(value: object, location: str, *, nonempty: bool = False) -> list[dict[str, Any]]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty" if nonempty else "an"
        raise CoverageJoinError(f"{location} must be {qualifier} array")
    return [_mapping(item, f"{location}[]") for item in value]


def _string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise CoverageJoinError(f"{location} must be a non-empty string")
    return value


def _schema_hash(value: object, location: str) -> str:
    digest = _string(value, location)
    if (
        not digest.startswith(_HASH_PREFIX)
        or len(digest) != len(_HASH_PREFIX) + 64
        or any(character not in "0123456789abcdef" for character in digest[len(_HASH_PREFIX) :])
    ):
        raise CoverageJoinError(f"{location} must be one lowercase sha256 digest")
    return digest


def _stored_hash(value: object, location: str) -> str:
    digest = _string(value, location)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise CoverageJoinError(f"{location} must be one lowercase SHA-256 digest")
    return f"{_HASH_PREFIX}{digest}"


def _strings(
    value: object,
    location: str,
    *,
    nonempty: bool = False,
    sorted_values: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "a non-empty" if nonempty else "an"
        raise CoverageJoinError(f"{location} must be {qualifier} array")
    result = tuple(_string(item, f"{location}[]") for item in value)
    if len(set(result)) != len(result):
        raise CoverageJoinError(f"{location} contains duplicates")
    if sorted_values and result != tuple(sorted(result)):
        raise CoverageJoinError(f"{location} must be sorted")
    return result


def _hashes(value: object, location: str, *, nonempty: bool = False) -> tuple[str, ...]:
    values = _strings(value, location, nonempty=nonempty)
    return tuple(_schema_hash(item, f"{location}[]") for item in values)


def _unique(
    rows: Sequence[Mapping[str, Any]],
    field: str,
    location: str,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for source in rows:
        row = dict(source)
        identity = _string(row.get(field), f"{location}[].{field}")
        if identity in result:
            raise CoverageJoinError(f"{location} contains duplicate {field} {identity}")
        result[identity] = row
    return result


def _active_profiles(
    objective: Mapping[str, Any],
    suite: Mapping[str, Any],
    suite_assignment: Mapping[str, Any],
    channel: str,
) -> frozenset[str]:
    obligation_id = _string(objective.get("obligation_id"), "objective.obligation_id")
    profiles = _objects(
        objective.get("validation_profiles"), "objective.validation_profiles", nonempty=True
    )
    known_kinds: set[str] = set()
    channel_kinds: set[str] = set()
    for profile in profiles:
        kind = _string(profile.get("kind"), "objective.validation_profiles[].kind")
        if kind in known_kinds:
            raise CoverageJoinError(
                f"objective {obligation_id} repeats validation profile kind {kind}"
            )
        known_kinds.add(kind)
        channels = _strings(
            profile.get("channels"),
            "objective.validation_profiles[].channels",
            nonempty=True,
        )
        if channel in channels:
            channel_kinds.add(kind)

    suite_origin = _string(suite.get("suite_origin"), "suite.suite_origin")
    lane = _string(suite.get("lane"), "suite.lane")
    assignment_kind = _string(
        suite_assignment.get("assignment_kind"), "suite_assignment.assignment_kind"
    )
    assignment_channel = _string(suite_assignment.get("channel"), "suite_assignment.channel")
    assignment_lane = _string(suite_assignment.get("suite_lane"), "suite_assignment.suite_lane")
    if assignment_channel != channel:
        raise CoverageJoinError("run channel differs from the suite assignment")
    assignments = _unique(
        _objects(suite.get("strategy_assignments"), "suite.strategy_assignments"),
        "obligation_id",
        "suite.strategy_assignments",
    )

    if channel in {"PRIMARY", "COMPOSITION"}:
        expected_kind = "primary" if channel == "PRIMARY" else "composition"
        if (
            suite_origin != "primary"
            or lane != "PRIMARY"
            or assignment_kind != expected_kind
            or assignment_lane != "PRIMARY"
        ):
            raise CoverageJoinError(f"channel {channel} requires a primary suite")
        if assignments:
            raise CoverageJoinError("a primary suite cannot carry strategy assignments")
        active = frozenset(channel_kinds)
    elif channel in {"A", "B"}:
        if (
            suite_origin != "blind"
            or lane != channel
            or assignment_kind != "blind_fresh"
            or assignment_lane != channel
        ):
            raise CoverageJoinError(f"channel {channel} requires its matching blind-fresh lane")
        assignment = assignments.get(obligation_id)
        if assignment is None:
            raise CoverageJoinError(f"suite has no strategy assignment for {obligation_id}")
        assigned = _string(assignment.get("profile"), "suite.strategy_assignments[].profile")
        if assigned not in channel_kinds:
            raise CoverageJoinError(
                f"suite profile {assigned} is not active for {obligation_id} on channel {channel}"
            )
        active = frozenset({assigned})
    elif channel == "REGRESSION":
        if (
            suite_origin != "blind"
            or lane not in {"A", "B"}
            or assignment_kind != "blind_regression"
            or assignment_lane != lane
        ):
            raise CoverageJoinError("REGRESSION requires a sealed blind-regression lane")
        assignment = assignments.get(obligation_id)
        if assignment is None:
            raise CoverageJoinError(f"suite has no strategy assignment for {obligation_id}")
        assigned = _string(assignment.get("profile"), "suite.strategy_assignments[].profile")
        if assigned not in known_kinds:
            raise CoverageJoinError(
                f"suite regression profile {assigned} is unknown for {obligation_id}"
            )
        active = frozenset({assigned})
    else:
        raise CoverageJoinError(f"unsupported suite-run channel {channel}")

    if not active:
        raise CoverageJoinError(f"objective {obligation_id} has no active profile on {channel}")
    return active


def _current_scip(store: _CoverageStore) -> tuple[str, str, dict[str, dict[str, Any]]]:
    admission_hash = store.metadata("active_scip_admission_hash")
    _stored_hash(admission_hash, "active SCIP admission hash")
    reasons = store.scip_freshness_reasons()
    if reasons:
        raise CoverageJoinError("the active SCIP admission is stale: " + "; ".join(reasons))
    snapshot = store.scip_snapshot(admission_hash)
    if snapshot is None:
        raise CoverageJoinError("the active SCIP admission has no snapshot")

    admission = _mapping(snapshot.get("admission"), "SCIP snapshot admission")
    index = _mapping(snapshot.get("index"), "SCIP snapshot index")
    if admission.get("admission_hash") != admission_hash:
        raise CoverageJoinError("SCIP snapshot admission identity is inconsistent")
    if admission.get("ingestion_hash") != index.get("ingestion_hash"):
        raise CoverageJoinError("SCIP snapshot ingestion identity is inconsistent")
    index_hash = _stored_hash(index.get("index_hash"), "SCIP snapshot index hash")

    documents = _unique(
        _objects(snapshot.get("documents"), "SCIP snapshot documents", nonempty=True),
        "relative_path",
        "SCIP snapshot documents",
    )
    bindings = _unique(
        _objects(snapshot.get("subject_bindings"), "SCIP snapshot subject bindings", nonempty=True),
        "subject_id",
        "SCIP snapshot subject bindings",
    )
    for subject_id, binding in bindings.items():
        if binding.get("admission_hash") != admission_hash:
            raise CoverageJoinError(f"SCIP binding {subject_id} belongs to another admission")
        path = _string(binding.get("document_path"), f"SCIP binding {subject_id}.document_path")
        document = documents.get(path)
        if document is None:
            raise CoverageJoinError(f"SCIP binding {subject_id} has no indexed document")
        source_hash = _stored_hash(
            binding.get("source_hash"), f"SCIP binding {subject_id}.source_hash"
        )
        document_hash = _stored_hash(
            document.get("source_hash"), f"SCIP document {path}.source_hash"
        )
        if source_hash != document_hash:
            raise CoverageJoinError(f"SCIP binding {subject_id} has an inconsistent source hash")
    return admission_hash, index_hash, bindings


def _require_scip_still_current(store: _CoverageStore, admission_hash: str) -> None:
    if store.metadata("active_scip_admission_hash") != admission_hash:
        raise CoverageJoinError("the active SCIP admission changed during the coverage join")
    reasons = store.scip_freshness_reasons()
    if reasons:
        raise CoverageJoinError(
            "the active SCIP admission became stale during the coverage join: " + "; ".join(reasons)
        )


def _expected_requirements(
    objectives: Sequence[Mapping[str, Any]],
    suite: Mapping[str, Any],
    suite_assignment: Mapping[str, Any],
    channel: str,
) -> tuple[dict[str, _ExpectedRequirement], dict[str, str], dict[str, str]]:
    expected: dict[str, _ExpectedRequirement] = {}
    objective_hashes: dict[str, str] = {}
    obligation_ids: dict[str, str] = {}
    all_requirement_ids: set[str] = set()
    for objective in objectives:
        objective_id = _string(objective.get("objective_id"), "objective.objective_id")
        if objective_id in objective_hashes:
            raise CoverageJoinError(f"objectives repeat objective ID {objective_id}")
        objective_hashes[objective_id] = _schema_hash(
            objective.get("objective_hash"), f"objective {objective_id}.objective_hash"
        )
        obligation_id = _string(
            objective.get("obligation_id"), f"objective {objective_id}.obligation_id"
        )
        if obligation_id in obligation_ids:
            raise CoverageJoinError(f"objectives repeat obligation ID {obligation_id}")
        obligation_ids[obligation_id] = objective_id

        targets: dict[str, tuple[str, str]] = {}
        for target in _objects(
            objective.get("target_subjects"),
            f"objective {objective_id}.target_subjects",
            nonempty=True,
        ):
            subject_id = _string(target.get("subject_id"), "target_subjects[].subject_id")
            if subject_id in targets:
                raise CoverageJoinError(f"objective {objective_id} repeats subject {subject_id}")
            targets[subject_id] = (
                _string(target.get("source_path"), f"target {subject_id}.source_path"),
                _string(target.get("scip_selector"), f"target {subject_id}.scip_selector"),
            )

        active_profiles = _active_profiles(objective, suite, suite_assignment, channel)
        tool_ids = frozenset(
            _strings(objective.get("tool_ids"), f"objective {objective_id}.tool_ids")
        )
        requirements = _objects(
            objective.get("coverage_requirements"),
            f"objective {objective_id}.coverage_requirements",
            nonempty=True,
        )
        for requirement in requirements:
            requirement_id = _string(
                requirement.get("id"), f"objective {objective_id}.coverage_requirements[].id"
            )
            if requirement_id in all_requirement_ids:
                raise CoverageJoinError(f"objectives repeat coverage requirement {requirement_id}")
            all_requirement_ids.add(requirement_id)
            applicable = frozenset(
                _strings(
                    requirement.get("applicable_profiles"),
                    f"coverage requirement {requirement_id}.applicable_profiles",
                    nonempty=True,
                )
            )
            if not active_profiles.intersection(applicable):
                continue
            subject_ids = _strings(
                requirement.get("subject_ids"),
                f"coverage requirement {requirement_id}.subject_ids",
                nonempty=True,
                sorted_values=True,
            )
            unknown = set(subject_ids).difference(targets)
            if unknown:
                raise CoverageJoinError(
                    f"coverage requirement {requirement_id} has unknown subjects {sorted(unknown)}"
                )
            expected[requirement_id] = _ExpectedRequirement(
                objective_id=objective_id,
                objective_hash=objective_hashes[objective_id],
                obligation_id=obligation_id,
                requirement_id=requirement_id,
                kind=_string(
                    requirement.get("kind"), f"coverage requirement {requirement_id}.kind"
                ),
                target=_string(
                    requirement.get("target"), f"coverage requirement {requirement_id}.target"
                ),
                subject_ids=subject_ids,
                targets=targets,
                tool_ids=tool_ids,
            )
    if not expected:
        raise CoverageJoinError("the selected objectives have no active coverage requirements")
    return expected, objective_hashes, obligation_ids


def _record_identity(
    objective_records: Sequence[Mapping[str, Any]],
    suite_record: Mapping[str, Any],
    suite_assignment_record: Mapping[str, Any],
    run_record: Mapping[str, Any],
    objective_hashes: Mapping[str, str],
    obligation_ids: Mapping[str, str],
    channel: str,
    index_hash: str,
) -> tuple[str, str, str, str, str]:
    contract_hash = _schema_hash(suite_record.get("contract_hash"), "suite.contract_hash")
    node_id = _string(suite_record.get("node_id"), "suite.node_id")
    for objective in objective_records:
        objective_id = _string(objective.get("objective_id"), "objective.objective_id")
        if (
            _schema_hash(objective.get("contract_hash"), f"objective {objective_id}.contract_hash")
            != contract_hash
        ):
            raise CoverageJoinError(f"objective {objective_id} has a different contract hash")
        if _string(objective.get("node_id"), f"objective {objective_id}.node_id") != node_id:
            raise CoverageJoinError(f"objective {objective_id} belongs to a different node")

    suite_objective_ids = _strings(
        suite_record.get("objective_ids"), "suite.objective_ids", nonempty=True
    )
    if set(suite_objective_ids) != set(objective_hashes):
        raise CoverageJoinError("suite objective IDs do not exactly match the supplied objectives")
    suite_objective_hashes = _hashes(
        suite_record.get("objective_hashes"), "suite.objective_hashes", nonempty=True
    )
    if set(suite_objective_hashes) != set(objective_hashes.values()):
        raise CoverageJoinError(
            "suite objective hashes do not exactly match the supplied objectives"
        )

    if _schema_hash(run_record.get("contract_hash"), "run.contract_hash") != contract_hash:
        raise CoverageJoinError("run contract hash differs from the suite")
    if _string(run_record.get("node_id"), "run.node_id") != node_id:
        raise CoverageJoinError("run node differs from the suite")
    suite_hash = _schema_hash(suite_record.get("suite_hash"), "suite.suite_hash")
    if (
        _schema_hash(
            suite_assignment_record.get("contract_hash"),
            "suite_assignment.contract_hash",
        )
        != contract_hash
        or _string(suite_assignment_record.get("node_id"), "suite_assignment.node_id") != node_id
        or _schema_hash(suite_assignment_record.get("suite_hash"), "suite_assignment.suite_hash")
        != suite_hash
    ):
        raise CoverageJoinError(
            "suite assignment does not bind the exact contract, node, and suite"
        )
    assignment_objective_ids = _strings(
        suite_assignment_record.get("objective_ids"),
        "suite_assignment.objective_ids",
        nonempty=True,
    )
    assignment_objective_hashes = _hashes(
        suite_assignment_record.get("objective_hashes"),
        "suite_assignment.objective_hashes",
        nonempty=True,
    )
    if assignment_objective_ids != suite_objective_ids or (
        assignment_objective_hashes != suite_objective_hashes
    ):
        raise CoverageJoinError("suite assignment changes the suite objective identity")
    suite_assignment_hash = _schema_hash(
        suite_assignment_record.get("suite_assignment_hash"),
        "suite_assignment.suite_assignment_hash",
    )
    if (
        _schema_hash(run_record.get("suite_assignment_hash"), "run.suite_assignment_hash")
        != suite_assignment_hash
    ):
        raise CoverageJoinError("run suite-assignment hash differs")
    if _schema_hash(run_record.get("suite_hash"), "run.suite_hash") != suite_hash:
        raise CoverageJoinError("run suite hash differs from the generated suite")
    run_objective_hashes = _hashes(
        run_record.get("objective_hashes"), "run.objective_hashes", nonempty=True
    )
    if run_objective_hashes != suite_objective_hashes:
        raise CoverageJoinError(
            "run objective hashes are not the suite's exact objective hash list"
        )
    run_obligations = _strings(
        run_record.get("obligation_ids"), "run.obligation_ids", nonempty=True
    )
    if set(run_obligations) != set(obligation_ids):
        raise CoverageJoinError("run obligations do not exactly match the supplied objectives")
    assignments = _unique(
        _objects(suite_record.get("strategy_assignments"), "suite.strategy_assignments"),
        "obligation_id",
        "suite.strategy_assignments",
    )
    if channel in {"A", "B", "REGRESSION"} and set(assignments) != set(obligation_ids):
        raise CoverageJoinError(
            "suite strategy assignments do not exactly match the supplied obligations"
        )
    if _schema_hash(run_record.get("scip_index_hash"), "run.scip_index_hash") != index_hash:
        raise CoverageJoinError("run is bound to a different SCIP index")
    run_hash = _schema_hash(run_record.get("run_hash"), "run.run_hash")
    return contract_hash, node_id, suite_hash, suite_assignment_hash, run_hash


def _validated_suite_bindings(
    suite_record: Mapping[str, Any],
    expected: Mapping[str, _ExpectedRequirement],
) -> dict[str, dict[str, Any]]:
    suite_bindings = _unique(
        _objects(suite_record.get("coverage_bindings"), "suite.coverage_bindings", nonempty=True),
        "requirement_id",
        "suite.coverage_bindings",
    )
    if set(suite_bindings) != set(expected):
        raise CoverageJoinError(
            "suite coverage requirements do not exactly match the active objective requirements"
        )
    for requirement_id, binding in suite_bindings.items():
        requirement = expected[requirement_id]
        bound_subjects = _strings(
            binding.get("subject_ids"),
            f"suite coverage binding {requirement_id}.subject_ids",
            nonempty=True,
            sorted_values=True,
        )
        if bound_subjects != requirement.subject_ids:
            raise CoverageJoinError(
                f"suite coverage binding {requirement_id} changed its frozen subject set"
            )
        tool_id = _string(
            binding.get("tool_id"), f"suite coverage binding {requirement_id}.tool_id"
        )
        if tool_id not in requirement.tool_ids:
            raise CoverageJoinError(
                f"suite coverage binding {requirement_id} uses undeclared tool {tool_id}"
            )
        _string(
            binding.get("artifact_format"),
            f"suite coverage binding {requirement_id}.artifact_format",
        )
        _string(
            binding.get("admission_rule"),
            f"suite coverage binding {requirement_id}.admission_rule",
        )
        _string(
            binding.get("trusted_parser_id"),
            f"suite coverage binding {requirement_id}.trusted_parser_id",
        )
        _schema_hash(
            binding.get("trusted_parser_hash"),
            f"suite coverage binding {requirement_id}.trusted_parser_hash",
        )
    return suite_bindings


def _validated_run_results(
    run_record: Mapping[str, Any],
    expected: Mapping[str, _ExpectedRequirement],
) -> tuple[dict[tuple[str, str], dict[str, Any]], set[tuple[str, str]]]:
    results: dict[tuple[str, str], dict[str, Any]] = {}
    for result in _objects(run_record.get("coverage_results"), "run.coverage_results"):
        requirement_id = _string(result.get("requirement_id"), "coverage result.requirement_id")
        subject_id = _string(result.get("subject_id"), "coverage result.subject_id")
        key = (requirement_id, subject_id)
        if key in results:
            raise CoverageJoinError(
                f"run repeats coverage result for {requirement_id}/{subject_id}"
            )
        results[key] = result

    expected_pairs = {
        (requirement.requirement_id, subject_id)
        for requirement in expected.values()
        for subject_id in requirement.subject_ids
    }
    if set(results) != expected_pairs:
        missing = sorted(expected_pairs.difference(results))
        extra = sorted(set(results).difference(expected_pairs))
        raise CoverageJoinError(
            "run coverage result pairs differ from the frozen pairs; "
            f"missing={missing}, extra={extra}"
        )
    return results, expected_pairs


def _coverage_entry(
    requirement: _ExpectedRequirement,
    subject_id: str,
    suite_binding: Mapping[str, Any],
    result: Mapping[str, Any],
    scip_binding: Mapping[str, Any],
    index_hash: str,
) -> CoverageSubjectJoin:
    requirement_id = requirement.requirement_id
    source_path, scip_symbol = requirement.targets[subject_id]
    if scip_binding.get("document_path") != source_path:
        raise CoverageJoinError(f"subject {subject_id} maps to a different SCIP source path")
    if scip_binding.get("symbol") != scip_symbol:
        raise CoverageJoinError(f"subject {subject_id} maps to a different SCIP symbol")

    current_source_hash = _stored_hash(
        scip_binding.get("source_hash"), f"SCIP binding {subject_id}.source_hash"
    )
    if (
        _schema_hash(result.get("source_hash"), "coverage result.source_hash")
        != current_source_hash
    ):
        raise CoverageJoinError(f"coverage result for {subject_id} has a stale source hash")
    if _schema_hash(result.get("scip_index_hash"), "coverage result.scip_index_hash") != index_hash:
        raise CoverageJoinError(f"coverage result for {subject_id} has a stale SCIP index hash")
    parser_hash = _schema_hash(
        suite_binding.get("trusted_parser_hash"),
        f"suite coverage binding {requirement_id}.trusted_parser_hash",
    )
    if (
        _schema_hash(result.get("trusted_parser_hash"), "coverage result.trusted_parser_hash")
        != parser_hash
    ):
        raise CoverageJoinError(
            f"coverage result for {requirement_id}/{subject_id} used a different parser"
        )
    reported_result = _string(result.get("result"), "coverage result.result")
    if reported_result not in _RAW_RESULTS:
        raise CoverageJoinError(f"coverage result has unsupported status {reported_result}")
    measured_fraction = result.get("measured_fraction")
    if measured_fraction is not None and (
        isinstance(measured_fraction, bool)
        or not isinstance(measured_fraction, (int, float))
        or not 0 <= measured_fraction <= 1
    ):
        raise CoverageJoinError("coverage result.measured_fraction must be between zero and one")
    reached_values_hash = result.get("reached_values_hash")
    if reached_values_hash is not None:
        reached_values_hash = _schema_hash(
            reached_values_hash, "coverage result.reached_values_hash"
        )

    return CoverageSubjectJoin(
        objective_id=requirement.objective_id,
        objective_hash=requirement.objective_hash,
        obligation_id=requirement.obligation_id,
        requirement_id=requirement_id,
        coverage_kind=requirement.kind,
        coverage_target=requirement.target,
        subject_id=subject_id,
        source_path=source_path,
        scip_symbol=scip_symbol,
        source_hash=current_source_hash,
        scip_index_hash=index_hash,
        tool_id=_string(
            suite_binding.get("tool_id"),
            f"suite coverage binding {requirement_id}.tool_id",
        ),
        artifact_format=_string(
            suite_binding.get("artifact_format"),
            f"suite coverage binding {requirement_id}.artifact_format",
        ),
        raw_artifact_hash=_schema_hash(
            result.get("raw_artifact_hash"), "coverage result.raw_artifact_hash"
        ),
        trusted_parser_id=_string(
            suite_binding.get("trusted_parser_id"),
            f"suite coverage binding {requirement_id}.trusted_parser_id",
        ),
        trusted_parser_hash=parser_hash,
        reported_result=reported_result,
        measured_fraction=(None if measured_fraction is None else float(measured_fraction)),
        reached_values_hash=reached_values_hash,
    )


def _joined_entries(
    expected: Mapping[str, _ExpectedRequirement],
    expected_pairs: set[tuple[str, str]],
    suite_bindings: Mapping[str, Mapping[str, Any]],
    results: Mapping[tuple[str, str], Mapping[str, Any]],
    scip_bindings: Mapping[str, Mapping[str, Any]],
    index_hash: str,
) -> tuple[CoverageSubjectJoin, ...]:
    entries: list[CoverageSubjectJoin] = []
    for requirement_id, subject_id in sorted(expected_pairs):
        requirement = expected[requirement_id]
        suite_binding = suite_bindings[requirement_id]
        result = results[(requirement_id, subject_id)]
        scip_binding = scip_bindings.get(subject_id)
        if scip_binding is None:
            raise CoverageJoinError(f"subject {subject_id} has no current SCIP binding")
        entries.append(
            _coverage_entry(
                requirement,
                subject_id,
                suite_binding,
                result,
                scip_binding,
                index_hash,
            )
        )
    return tuple(entries)


def join_coverage_results(
    store: _CoverageStore,
    objectives: Sequence[Mapping[str, Any]],
    suite: Mapping[str, Any],
    suite_assignment: Mapping[str, Any],
    run: Mapping[str, Any],
) -> CoverageJoin:
    """Join raw coverage records to exact current subjects without judging them.

    The caller must separately validate record schemas, signatures, suite code,
    trusted parser execution, coverage-kind semantics, and final evidence effect.
    """
    if not objectives:
        raise CoverageJoinError("coverage join requires at least one objective")
    objective_records = [
        _mapping(objective, f"objectives[{offset}]") for offset, objective in enumerate(objectives)
    ]
    suite_record = _mapping(suite, "suite")
    suite_assignment_record = _mapping(suite_assignment, "suite_assignment")
    run_record = _mapping(run, "run")
    channel = _string(run_record.get("channel"), "run.channel")
    admission_hash, index_hash, scip_bindings = _current_scip(store)
    expected, objective_hashes, obligation_ids = _expected_requirements(
        objective_records, suite_record, suite_assignment_record, channel
    )
    contract_hash, node_id, suite_hash, suite_assignment_hash, run_hash = _record_identity(
        objective_records,
        suite_record,
        suite_assignment_record,
        run_record,
        objective_hashes,
        obligation_ids,
        channel,
        index_hash,
    )
    suite_bindings = _validated_suite_bindings(suite_record, expected)
    results, expected_pairs = _validated_run_results(run_record, expected)
    entries = _joined_entries(
        expected,
        expected_pairs,
        suite_bindings,
        results,
        scip_bindings,
        index_hash,
    )

    _require_scip_still_current(store, admission_hash)
    payload = {
        "scip_admission_hash": admission_hash,
        "scip_index_hash": index_hash,
        "contract_hash": contract_hash,
        "node_id": node_id,
        "channel": channel,
        "suite_hash": suite_hash,
        "run_hash": run_hash,
        "entries": [asdict(entry) for entry in entries],
    }
    return CoverageJoin(
        scip_admission_hash=admission_hash,
        scip_index_hash=index_hash,
        contract_hash=contract_hash,
        node_id=node_id,
        channel=channel,
        suite_hash=suite_hash,
        suite_assignment_hash=suite_assignment_hash,
        run_hash=run_hash,
        entries=entries,
        join_hash=hash_object(payload),
    )
