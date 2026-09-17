"""Derive the structural authority required before a node may be ``PROVED``.

This module is deliberately narrow.  It does not authenticate signatures,
decode SCIP, read storage, issue a certificate, or decide node state.  Its
inputs are the exact projections rederived by those boundaries.  Returning a
``StructuralClosure`` establishes only the structural prerequisite named by
the approved Docker/direct-SCIP amendment; every non-structural proof and
evidence requirement remains independently mandatory.
"""

from __future__ import annotations

from dataclasses import dataclass

CANDIDATE_CODE_REQUIREMENTS = frozenset(
    {
        "current_authoritative_scip_generation",
        "candidate_source_hash_equality",
        "exactly_one_contract_selected_subject_binding",
        "exact_required_and_authorized_observed_relationship_set",
    }
)
SUITE_TARGET_REQUIREMENTS = frozenset(
    {
        "current_authenticated_generated_suite",
        "current_direct_scip_generation_for_suite_workspace",
        "exact_suite_file_and_source_hash_equality",
        "exact_declared_target_and_harness_relationships",
    }
)
RUN_AND_CERTIFICATE_REQUIREMENTS = frozenset(
    {
        "all_run_hashes_resolve_to_authenticated_runner_records",
        "every_run_uses_the_current_candidate_scip_generation",
        "every_applicable_coverage_result_uses_the_same_index_and_source_hash",
        "every_suite_validation_uses_its_current_suite_workspace_scip_generation",
        "certificate_finalizer_rederives_the_complete_transitive_chain",
    }
)
MANAGED_ARTIFACT_REQUIREMENTS = frozenset(
    {
        "current_contract_selected_qualified_adapter_projection",
        "exact_raw_byte_hash_and_projection_binding",
    }
)


class StructuralCompletionError(ValueError):
    """The exact structural prerequisite for proof could not be derived."""

    def __init__(self, reasons: list[str]) -> None:
        self.reasons = tuple(reasons)
        super().__init__("structural completion failed:\n- " + "\n- ".join(self.reasons))


@dataclass(frozen=True, order=True, slots=True)
class SourceFile:
    path: str
    source_hash: str


@dataclass(frozen=True, order=True, slots=True)
class SubjectBinding:
    subject_id: str
    source_path: str
    symbol: str
    source_hash: str


@dataclass(frozen=True, order=True, slots=True)
class SubjectRelationship:
    source_subject_id: str
    kind: str
    target_subject_id: str


@dataclass(frozen=True, slots=True)
class ScipProjection:
    generation_hash: str
    index_hash: str
    files: tuple[SourceFile, ...]
    subject_bindings: tuple[SubjectBinding, ...]
    relationships: tuple[SubjectRelationship, ...]


@dataclass(frozen=True, slots=True)
class CandidateScipEvidence:
    projection: ScipProjection


@dataclass(frozen=True, slots=True)
class SuiteScipEvidence:
    suite_hash: str
    projection: ScipProjection


@dataclass(frozen=True, order=True, slots=True)
class RunBinding:
    run_hash: str
    candidate_generation_hash: str


@dataclass(frozen=True, order=True, slots=True)
class CoverageRequirement:
    coverage_hash: str
    subject_id: str
    source_hash: str


@dataclass(frozen=True, order=True, slots=True)
class CoverageBinding:
    coverage_hash: str
    subject_id: str
    source_hash: str
    candidate_generation_hash: str
    candidate_index_hash: str


@dataclass(frozen=True, order=True, slots=True)
class SuiteValidationBinding:
    validation_hash: str
    suite_hash: str
    suite_generation_hash: str


@dataclass(frozen=True, order=True, slots=True)
class ManagedProjectionRequirement:
    subject_id: str
    adapter_qualification_hash: str
    raw_hash: str
    projection_hash: str


@dataclass(frozen=True, order=True, slots=True)
class ManagedProjectionBinding:
    subject_id: str
    record_hash: str
    adapter_qualification_hash: str
    raw_hash: str
    projection_hash: str


@dataclass(frozen=True, order=True, slots=True)
class StructuralScope:
    framework_freeze_hash: str
    feature_freeze_hash: str
    contract_hash: str
    candidate_manifest_hash: str
    evaluation_id: str
    node_id: str


@dataclass(frozen=True, slots=True)
class AuthenticatedStructuralRecords:
    scope: StructuralScope
    current_candidate_generation_hash: str
    current_suite_generation_hash: str
    candidate_generation_hashes: tuple[str, ...]
    suite_generation_hashes: tuple[str, ...]
    generated_suite_hashes: tuple[str, ...]
    run_hashes: tuple[str, ...]
    coverage_hashes: tuple[str, ...]
    suite_validation_hashes: tuple[str, ...]
    managed_projection_hashes: tuple[str, ...]
    qualified_adapter_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RequiredStructuralProjection:
    scope: StructuralScope
    candidate_files: tuple[SourceFile, ...]
    candidate_subjects: tuple[SubjectBinding, ...]
    candidate_relationships: tuple[SubjectRelationship, ...]
    suite_hash: str
    suite_files: tuple[SourceFile, ...]
    suite_targets: tuple[SubjectBinding, ...]
    suite_relationships: tuple[SubjectRelationship, ...]
    required_run_hashes: tuple[str, ...]
    coverage_requirements: tuple[CoverageRequirement, ...]
    required_suite_validation_hashes: tuple[str, ...]
    managed_requirements: tuple[ManagedProjectionRequirement, ...]


@dataclass(frozen=True, slots=True)
class StructuralCompletionRequest:
    requirements: RequiredStructuralProjection
    candidate: CandidateScipEvidence
    suite: SuiteScipEvidence
    authenticated: AuthenticatedStructuralRecords
    run_bindings: tuple[RunBinding, ...]
    coverage_bindings: tuple[CoverageBinding, ...]
    suite_validation_bindings: tuple[SuiteValidationBinding, ...]
    managed_bindings: tuple[ManagedProjectionBinding, ...]


@dataclass(frozen=True, slots=True)
class StructuralClosure:
    scope: StructuralScope
    candidate_generation_hash: str
    candidate_index_hash: str
    suite_hash: str
    suite_generation_hash: str
    suite_index_hash: str
    run_hashes: tuple[str, ...]
    coverage_hashes: tuple[str, ...]
    suite_validation_hashes: tuple[str, ...]
    managed_projection_hashes: tuple[str, ...]
    transitive_record_hashes: tuple[str, ...]


def _check_ordered_unique(
    values: tuple[object, ...],
    label: str,
    reasons: list[str],
) -> None:
    try:
        ordered = values == tuple(sorted(values))
        unique = len(values) == len(set(values))
    except TypeError:
        reasons.append(f"{label} contains values outside its admitted type")
        return
    if not ordered:
        reasons.append(f"{label} is not canonically ordered")
    if not unique:
        reasons.append(f"{label} contains duplicates")


def _check_unique_attribute(
    values: tuple[object, ...],
    attribute: str,
    label: str,
    reasons: list[str],
) -> None:
    identities = tuple(getattr(value, attribute) for value in values)
    if len(identities) != len(set(identities)):
        reasons.append(f"{label} repeats {attribute}")


def _check_exact(label: str, expected: object, observed: object, reasons: list[str]) -> None:
    if expected != observed:
        reasons.append(f"{label} differs from the exact required projection")


def derive_structural_closure(request: StructuralCompletionRequest) -> StructuralClosure:
    """Return the exact structural closure or fail without a success fallback."""

    if type(request) is not StructuralCompletionRequest:
        raise StructuralCompletionError(["request has the wrong nominal type"])
    if type(request.requirements) is not RequiredStructuralProjection:
        raise StructuralCompletionError(
            ["required structural projection has the wrong nominal type"]
        )
    if type(request.candidate) is not CandidateScipEvidence:
        raise StructuralCompletionError(["candidate SCIP evidence has the wrong nominal type"])
    if type(request.suite) is not SuiteScipEvidence:
        raise StructuralCompletionError(["suite SCIP evidence has the wrong nominal type"])
    if type(request.authenticated) is not AuthenticatedStructuralRecords:
        raise StructuralCompletionError(["authenticated records have the wrong nominal type"])

    reasons: list[str] = []
    requirements = request.requirements
    candidate = request.candidate
    suite = request.suite
    authenticated = request.authenticated

    _check_exact("structural scope", requirements.scope, authenticated.scope, reasons)
    sequences = (
        (requirements.candidate_files, "requirements.candidate_files"),
        (requirements.candidate_subjects, "requirements.candidate_subjects"),
        (requirements.candidate_relationships, "requirements.candidate_relationships"),
        (requirements.suite_files, "requirements.suite_files"),
        (requirements.suite_targets, "requirements.suite_targets"),
        (requirements.suite_relationships, "requirements.suite_relationships"),
        (requirements.required_run_hashes, "requirements.required_run_hashes"),
        (requirements.coverage_requirements, "requirements.coverage_requirements"),
        (
            requirements.required_suite_validation_hashes,
            "requirements.required_suite_validation_hashes",
        ),
        (requirements.managed_requirements, "requirements.managed_requirements"),
        (candidate.projection.files, "candidate.projection.files"),
        (candidate.projection.subject_bindings, "candidate.projection.subject_bindings"),
        (candidate.projection.relationships, "candidate.projection.relationships"),
        (suite.projection.files, "suite.projection.files"),
        (suite.projection.subject_bindings, "suite.projection.subject_bindings"),
        (suite.projection.relationships, "suite.projection.relationships"),
        (authenticated.candidate_generation_hashes, "authenticated.candidate_generations"),
        (authenticated.suite_generation_hashes, "authenticated.suite_generations"),
        (authenticated.generated_suite_hashes, "authenticated.generated_suites"),
        (authenticated.run_hashes, "authenticated.runs"),
        (authenticated.coverage_hashes, "authenticated.coverage"),
        (authenticated.suite_validation_hashes, "authenticated.suite_validations"),
        (authenticated.managed_projection_hashes, "authenticated.managed_projections"),
        (authenticated.qualified_adapter_hashes, "authenticated.qualified_adapters"),
        (request.run_bindings, "run_bindings"),
        (request.coverage_bindings, "coverage_bindings"),
        (request.suite_validation_bindings, "suite_validation_bindings"),
        (request.managed_bindings, "managed_bindings"),
    )
    for values, label in sequences:
        _check_ordered_unique(values, label, reasons)
    for values, attribute, label in (
        (requirements.candidate_files, "path", "requirements.candidate_files"),
        (requirements.candidate_subjects, "subject_id", "requirements.candidate_subjects"),
        (requirements.suite_files, "path", "requirements.suite_files"),
        (requirements.suite_targets, "subject_id", "requirements.suite_targets"),
        (candidate.projection.files, "path", "candidate.projection.files"),
        (
            candidate.projection.subject_bindings,
            "subject_id",
            "candidate.projection.subject_bindings",
        ),
        (suite.projection.files, "path", "suite.projection.files"),
        (
            suite.projection.subject_bindings,
            "subject_id",
            "suite.projection.subject_bindings",
        ),
    ):
        _check_unique_attribute(values, attribute, label, reasons)

    generation_overlap = set(authenticated.candidate_generation_hashes).intersection(
        authenticated.suite_generation_hashes
    )
    if generation_overlap:
        reasons.append("candidate and suite SCIP authority sets overlap")
    if (
        authenticated.current_candidate_generation_hash
        == authenticated.current_suite_generation_hash
    ):
        reasons.append("candidate SCIP cannot substitute for suite SCIP")

    if candidate.projection.generation_hash != authenticated.current_candidate_generation_hash:
        reasons.append("candidate SCIP generation is not current")
    if candidate.projection.generation_hash not in authenticated.candidate_generation_hashes:
        reasons.append("candidate SCIP generation is not authoritative")
    _check_exact(
        "candidate indexed files",
        requirements.candidate_files,
        candidate.projection.files,
        reasons,
    )
    _check_exact(
        "candidate subject bindings",
        requirements.candidate_subjects,
        candidate.projection.subject_bindings,
        reasons,
    )
    _check_exact(
        "candidate relationships",
        requirements.candidate_relationships,
        candidate.projection.relationships,
        reasons,
    )

    _check_exact("generated suite", requirements.suite_hash, suite.suite_hash, reasons)
    if suite.suite_hash not in authenticated.generated_suite_hashes:
        reasons.append("generated suite is not authenticated")
    if suite.projection.generation_hash != authenticated.current_suite_generation_hash:
        reasons.append("suite SCIP generation is not current")
    if suite.projection.generation_hash not in authenticated.suite_generation_hashes:
        reasons.append("suite SCIP generation is not authoritative")
    _check_exact(
        "suite indexed files",
        requirements.suite_files,
        suite.projection.files,
        reasons,
    )
    _check_exact(
        "suite target bindings",
        requirements.suite_targets,
        suite.projection.subject_bindings,
        reasons,
    )
    _check_exact(
        "suite relationships",
        requirements.suite_relationships,
        suite.projection.relationships,
        reasons,
    )

    run_hashes = tuple(binding.run_hash for binding in request.run_bindings)
    _check_exact("run binding set", requirements.required_run_hashes, run_hashes, reasons)
    for binding in request.run_bindings:
        if binding.run_hash not in authenticated.run_hashes:
            reasons.append(f"run {binding.run_hash} is not authenticated")
        if binding.candidate_generation_hash != candidate.projection.generation_hash:
            reasons.append(f"run {binding.run_hash} uses another candidate SCIP generation")

    expected_coverage = tuple(
        (value.coverage_hash, value.subject_id, value.source_hash)
        for value in requirements.coverage_requirements
    )
    observed_coverage = tuple(
        (value.coverage_hash, value.subject_id, value.source_hash)
        for value in request.coverage_bindings
    )
    _check_exact("coverage binding set", expected_coverage, observed_coverage, reasons)
    candidate_subjects = {
        value.subject_id: value for value in candidate.projection.subject_bindings
    }
    for requirement in requirements.coverage_requirements:
        subject = candidate_subjects.get(requirement.subject_id)
        if subject is None or subject.source_hash != requirement.source_hash:
            reasons.append(
                f"coverage requirement {requirement.coverage_hash} does not identify a current "
                "candidate SCIP subject and source"
            )
    for binding in request.coverage_bindings:
        if binding.coverage_hash not in authenticated.coverage_hashes:
            reasons.append(f"coverage result {binding.coverage_hash} is not authenticated")
        if binding.candidate_generation_hash != candidate.projection.generation_hash:
            reasons.append(f"coverage result {binding.coverage_hash} uses another SCIP generation")
        if binding.candidate_index_hash != candidate.projection.index_hash:
            reasons.append(f"coverage result {binding.coverage_hash} uses another SCIP index")

    validation_hashes = tuple(
        binding.validation_hash for binding in request.suite_validation_bindings
    )
    _check_exact(
        "suite validation binding set",
        requirements.required_suite_validation_hashes,
        validation_hashes,
        reasons,
    )
    for binding in request.suite_validation_bindings:
        if binding.validation_hash not in authenticated.suite_validation_hashes:
            reasons.append(f"suite validation {binding.validation_hash} is not authenticated")
        if binding.suite_hash != suite.suite_hash:
            reasons.append(f"suite validation {binding.validation_hash} uses another suite")
        if binding.suite_generation_hash != suite.projection.generation_hash:
            reasons.append(
                f"suite validation {binding.validation_hash} uses another SCIP generation"
            )

    expected_managed = tuple(
        (
            value.subject_id,
            value.adapter_qualification_hash,
            value.raw_hash,
            value.projection_hash,
        )
        for value in requirements.managed_requirements
    )
    observed_managed = tuple(
        (
            value.subject_id,
            value.adapter_qualification_hash,
            value.raw_hash,
            value.projection_hash,
        )
        for value in request.managed_bindings
    )
    _check_exact("managed projection set", expected_managed, observed_managed, reasons)
    for requirement in requirements.managed_requirements:
        if requirement.adapter_qualification_hash not in authenticated.qualified_adapter_hashes:
            reasons.append(
                f"managed subject {requirement.subject_id} has no current qualified adapter"
            )
    for binding in request.managed_bindings:
        if binding.record_hash not in authenticated.managed_projection_hashes:
            reasons.append(f"managed projection {binding.record_hash} is not authenticated")

    if reasons:
        raise StructuralCompletionError(reasons)

    transitive_record_hashes = tuple(
        sorted(
            {
                candidate.projection.generation_hash,
                suite.suite_hash,
                suite.projection.generation_hash,
                *run_hashes,
                *(value.coverage_hash for value in request.coverage_bindings),
                *(value.validation_hash for value in request.suite_validation_bindings),
                *(value.record_hash for value in request.managed_bindings),
            }
        )
    )
    return StructuralClosure(
        scope=requirements.scope,
        candidate_generation_hash=candidate.projection.generation_hash,
        candidate_index_hash=candidate.projection.index_hash,
        suite_hash=suite.suite_hash,
        suite_generation_hash=suite.projection.generation_hash,
        suite_index_hash=suite.projection.index_hash,
        run_hashes=run_hashes,
        coverage_hashes=tuple(value.coverage_hash for value in request.coverage_bindings),
        suite_validation_hashes=validation_hashes,
        managed_projection_hashes=tuple(value.record_hash for value in request.managed_bindings),
        transitive_record_hashes=transitive_record_hashes,
    )
