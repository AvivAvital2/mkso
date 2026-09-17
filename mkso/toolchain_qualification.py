"""Strict A-05 toolchain qualification records.

This is a bootstrap implementation of the human-approved I-06 source design.
The loaders validate retained record bytes and return immutable projections.
They do not authenticate signatures or grant execution authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Literal

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_PROFILE_ID = "a05.python-scip.patch4.regression"
_CLAIM_ID = "a05.python-scip.local-symbol-conformance.gate4"
_CONTAINERFILE_PATH = "verification/fixtures/a05_python/Containerfile.probe"
_OUTPUT_LABELS = frozenset(
    {
        "producer_audit",
        "producer_entrypoint",
        "producer_index",
        "producer_package_lock",
        "producer_production_tree",
    }
)
_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

_SIGNATURE_FIELDS = frozenset({"algorithm", "signer", "namespace", "value"})
_CONTEXT_ENTRY_FIELDS = frozenset({"path", "entry_type", "mode", "size", "content_hash"})
_RUNTIME_IDENTITY_FIELDS = frozenset(
    {
        "build_profile_hash",
        "docker_execution_profile_hash",
        "host_profile_hash",
        "runner_hash",
    }
)
_OUTPUT_REQUIREMENT_FIELDS = frozenset({"label", "container_path"})
_PUBLIC_ARTIFACT_FIELDS = frozenset({"label", "sha256", "size"})
_PROFILE_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "revision",
        "qualification_claim_id",
        "approved_design_hashes",
        "runner_rules_hash",
        "signer_policy_hash",
        "containerfile_path",
        "containerfile_sha256",
        "context_manifest_hash",
        "context_entries",
        "platform",
        "build_target",
        "build_arguments",
        "network_policy",
        "selected_image_closure_hashes",
        "runtime_identity_requirements",
        "timeout_seconds",
        "retry_count",
        "required_output_artifacts",
        "private_output_policy",
        "toolchain_execution_profile_hash",
        "signature",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "schema_version",
        "qualification_claim_id",
        "toolchain_execution_profile_hash",
        "runner_rules_hash",
        "signer_policy_hash",
        "context_manifest_hash",
        "containerfile_sha256",
        "runner_hash",
        "authority_phase",
        "result",
        "public_artifacts",
        "toolchain_qualification_result_hash",
        "signature",
    }
)


class ToolchainQualificationError(ValueError):
    """Raised when retained toolchain qualification bytes fail closed."""


@dataclass(frozen=True, slots=True)
class ToolchainSignature:
    algorithm: Literal["openssh-sshsig-v1"]
    signer: str
    namespace: str
    value: str


@dataclass(frozen=True, slots=True)
class ToolchainContextEntry:
    path: str
    entry_type: Literal["regular_file"]
    mode: Literal["0644", "0755"]
    size: int
    content_hash: str


@dataclass(frozen=True, slots=True)
class ToolchainRuntimeIdentities:
    build_profile_hash: str
    docker_execution_profile_hash: str
    host_profile_hash: str
    runner_hash: str


@dataclass(frozen=True, slots=True)
class ToolchainOutputRequirement:
    label: str
    container_path: str


@dataclass(frozen=True, slots=True)
class ToolchainPublicArtifact:
    label: str
    sha256: str
    size: int


@dataclass(frozen=True, slots=True)
class ToolchainRunKey:
    qualification_claim_id: str
    toolchain_execution_profile_hash: str
    context_manifest_hash: str


@dataclass(frozen=True, slots=True)
class ToolchainExecutionProfile:
    document: bytes
    run_key: ToolchainRunKey
    profile_id: str
    revision: int
    approved_design_hashes: tuple[str, ...]
    runner_rules_hash: str
    signer_policy_hash: str
    containerfile_path: str
    containerfile_sha256: str
    context_entries: tuple[ToolchainContextEntry, ...]
    platform: Literal["linux/amd64"]
    build_target: Literal["qualification"]
    build_arguments: tuple[tuple[str, str], ...]
    network_policy: Literal["build_only_for_pinned_fetches_then_execution_none"]
    selected_image_closure_hashes: tuple[str, ...]
    runtime_identities: ToolchainRuntimeIdentities
    timeout_seconds: Literal[3600]
    retry_count: Literal[0]
    required_output_artifacts: tuple[ToolchainOutputRequirement, ...]
    private_output_policy: Literal["retain_raw_release_aggregate_only"]
    signature: ToolchainSignature


@dataclass(frozen=True, slots=True)
class ToolchainQualificationResult:
    document: bytes
    run_key: ToolchainRunKey
    runner_rules_hash: str
    signer_policy_hash: str
    containerfile_sha256: str
    runner_hash: str
    authority_phase: Literal["BOOTSTRAP", "FRAMEWORK"]
    result_hash: str
    result: Literal["PASSED", "UNVERIFIED"]
    public_artifacts: tuple[ToolchainPublicArtifact, ...]
    signature: ToolchainSignature


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ToolchainQualificationError(message)


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON member {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ToolchainQualificationError(f"non-JSON numeric constant {value}")


def _validate_restricted_value(value: object, location: str = "$") -> None:
    value_type = type(value)
    if value is None or value_type is bool:
        return
    if value_type is int:
        _require(
            -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER,
            f"{location}: integer outside the interoperable range",
        )
        return
    if value_type is str:
        _require(value.isascii(), f"{location}: non-ASCII JSON string")
        return
    if value_type is list:
        for index, item in enumerate(value):
            _validate_restricted_value(item, f"{location}[{index}]")
        return
    if value_type is dict:
        for key, item in value.items():
            _require(type(key) is str and key.isascii(), f"{location}: invalid JSON member name")
            _validate_restricted_value(item, f"{location}.{key}")
        return
    raise ToolchainQualificationError(
        f"{location}: floating-point or unsupported JSON value {value_type.__name__}"
    )


def _load_record(document: bytes, label: str) -> dict[str, Any]:
    _require(type(document) is bytes, f"{label} document must be exact bytes")
    try:
        text = document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolchainQualificationError(f"{label} document is not strict UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_constant,
        )
    except ToolchainQualificationError:
        raise
    except json.JSONDecodeError as exc:
        raise ToolchainQualificationError(f"{label} document is not strict JSON") from exc
    _require(type(value) is dict, f"{label} document must contain an object")
    _validate_restricted_value(value)
    return value


def _require_fields(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    missing = sorted(expected - value.keys())
    extra = sorted(value.keys() - expected)
    _require(not missing and not extra, f"{label} fields are incomplete or extra")


def _string(value: object, label: str, *, nonempty: bool = True) -> str:
    _require(type(value) is str, f"{label} must be a string")
    _require(not nonempty or bool(value), f"{label} must not be empty")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    _require(type(value) is int, f"{label} must be an integer")
    _require(minimum <= value <= _MAX_SAFE_INTEGER, f"{label} is outside its allowed range")
    return value


def _identifier(value: object, label: str) -> str:
    result = _string(value, label)
    _require(_ID_PATTERN.fullmatch(result) is not None, f"{label} is not a valid identifier")
    return result


def _sha256(value: object, label: str) -> str:
    result = _string(value, label)
    _require(_SHA256_PATTERN.fullmatch(result) is not None, f"{label} is not lowercase SHA-256")
    return result


def _relative_path(value: object, label: str) -> str:
    result = _string(value, label)
    parts = result.split("/")
    _require(
        result.isascii()
        and all(" " <= character <= "~" for character in result)
        and not result.startswith("/")
        and not result.endswith("/")
        and "\\" not in result
        and all(part not in {"", ".", ".."} for part in parts),
        f"{label} is not a canonical relative path",
    )
    return result


def _container_path(value: object, label: str) -> str:
    result = _string(value, label)
    parts = result.split("/")[1:]
    _require(
        result.isascii()
        and all(" " <= character <= "~" for character in result)
        and result.startswith("/")
        and result != "/"
        and not result.endswith("/")
        and "\\" not in result
        and all(part not in {"", ".", ".."} for part in parts),
        f"{label} is not a canonical container path",
    )
    return result


def _array(value: object, label: str, *, nonempty: bool = False) -> list[Any]:
    _require(type(value) is list, f"{label} must be an array")
    _require(not nonempty or bool(value), f"{label} must not be empty")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    return value


def _restricted_json_bytes(value: object) -> bytes:
    _validate_restricted_value(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _record_hash(record: dict[str, Any], hash_field: str) -> str:
    projection = {
        key: value for key, value in record.items() if key not in {hash_field, "signature"}
    }
    return _bytes_sha256(_restricted_json_bytes(projection))


def _signature(value: object, label: str, namespace: str) -> ToolchainSignature:
    record = _object(value, label)
    _require_fields(record, _SIGNATURE_FIELDS, label)
    algorithm = _string(record["algorithm"], f"{label}.algorithm")
    _require(algorithm == "openssh-sshsig-v1", f"{label} uses the wrong algorithm")
    signer = _identifier(record["signer"], f"{label}.signer")
    observed_namespace = _string(record["namespace"], f"{label}.namespace")
    _require(observed_namespace == namespace, f"{label} namespace mismatch")
    signature_value = _string(record["value"], f"{label}.value")
    return ToolchainSignature(
        algorithm="openssh-sshsig-v1",
        signer=signer,
        namespace=observed_namespace,
        value=signature_value,
    )


def _hash_array(value: object, label: str) -> tuple[str, ...]:
    values = tuple(
        _sha256(item, f"{label}[{index}]")
        for index, item in enumerate(_array(value, label, nonempty=True))
    )
    _require(len(values) == len(set(values)), f"{label} contains duplicates")
    _require(values == tuple(sorted(values)), f"{label} is not in canonical order")
    return values


def _context_entries(
    value: object,
) -> tuple[tuple[ToolchainContextEntry, ...], list[dict[str, Any]]]:
    raw_entries = _array(value, "context_entries", nonempty=True)
    entries: list[ToolchainContextEntry] = []
    for index, item in enumerate(raw_entries):
        label = f"context_entries[{index}]"
        record = _object(item, label)
        _require_fields(record, _CONTEXT_ENTRY_FIELDS, label)
        entry_type = _string(record["entry_type"], f"{label}.entry_type")
        _require(entry_type == "regular_file", f"{label}.entry_type must be regular_file")
        mode = _string(record["mode"], f"{label}.mode")
        _require(mode in {"0644", "0755"}, f"{label}.mode is not permitted")
        entries.append(
            ToolchainContextEntry(
                path=_relative_path(record["path"], f"{label}.path"),
                entry_type="regular_file",
                mode=mode,
                size=_integer(record["size"], f"{label}.size"),
                content_hash=_sha256(record["content_hash"], f"{label}.content_hash"),
            )
        )
    paths = tuple(entry.path for entry in entries)
    _require(len(paths) == len(set(paths)), "duplicate context path")
    _require(paths == tuple(sorted(paths)), "context entries are not in canonical path order")
    return tuple(entries), raw_entries


def _runtime_identities(value: object) -> ToolchainRuntimeIdentities:
    record = _object(value, "runtime_identity_requirements")
    _require_fields(record, _RUNTIME_IDENTITY_FIELDS, "runtime_identity_requirements")
    return ToolchainRuntimeIdentities(
        build_profile_hash=_sha256(record["build_profile_hash"], "build_profile_hash"),
        docker_execution_profile_hash=_sha256(
            record["docker_execution_profile_hash"], "docker_execution_profile_hash"
        ),
        host_profile_hash=_sha256(record["host_profile_hash"], "host_profile_hash"),
        runner_hash=_sha256(record["runner_hash"], "runner_hash"),
    )


def _output_requirements(value: object) -> tuple[ToolchainOutputRequirement, ...]:
    raw_requirements = _array(value, "required_output_artifacts", nonempty=True)
    requirements: list[ToolchainOutputRequirement] = []
    for index, item in enumerate(raw_requirements):
        label = f"required_output_artifacts[{index}]"
        record = _object(item, label)
        _require_fields(record, _OUTPUT_REQUIREMENT_FIELDS, label)
        requirements.append(
            ToolchainOutputRequirement(
                label=_identifier(record["label"], f"{label}.label"),
                container_path=_container_path(record["container_path"], f"{label}.container_path"),
            )
        )
    labels = tuple(item.label for item in requirements)
    paths = tuple(item.container_path for item in requirements)
    _require(
        len(labels) == len(set(labels)) and set(labels) == _OUTPUT_LABELS,
        "required public output-label set is incomplete or duplicated",
    )
    _require(
        len(paths) == len(set(paths)),
        "required public output selectors reuse a container path",
    )
    return tuple(requirements)


def _public_artifacts(
    value: object, result: Literal["PASSED", "UNVERIFIED"]
) -> tuple[ToolchainPublicArtifact, ...]:
    raw_artifacts = _array(value, "public_artifacts")
    artifacts: list[ToolchainPublicArtifact] = []
    for index, item in enumerate(raw_artifacts):
        label = f"public_artifacts[{index}]"
        record = _object(item, label)
        _require_fields(record, _PUBLIC_ARTIFACT_FIELDS, label)
        artifacts.append(
            ToolchainPublicArtifact(
                label=_identifier(record["label"], f"{label}.label"),
                sha256=_sha256(record["sha256"], f"{label}.sha256"),
                size=_integer(record["size"], f"{label}.size"),
            )
        )
    labels = tuple(item.label for item in artifacts)
    _require(len(labels) == len(set(labels)), "public artifact labels are duplicated")
    if result == "PASSED":
        _require(set(labels) == _OUTPUT_LABELS, "public artifact labels are incomplete or extra")
    else:
        _require(not artifacts, "UNVERIFIED result exposed artifacts")
    return tuple(artifacts)


def load_toolchain_execution_profile(document: bytes) -> ToolchainExecutionProfile:
    """Load one structurally valid A-05 execution profile from retained bytes."""

    record = _load_record(document, "execution profile")
    _require_fields(record, _PROFILE_FIELDS, "execution profile")
    _require(
        record["schema_version"] == "mkso-toolchain-execution-profile/1", "wrong profile schema"
    )
    profile_id = _identifier(record["profile_id"], "profile_id")
    _require(profile_id == _PROFILE_ID, "wrong A-05 profile ID")
    revision = _integer(record["revision"], "revision", minimum=1)
    _require(revision == 1, "wrong A-05 profile revision")
    claim_id = _identifier(record["qualification_claim_id"], "qualification_claim_id")
    _require(claim_id == _CLAIM_ID, "wrong qualification claim")
    approved_design_hashes = _hash_array(record["approved_design_hashes"], "approved_design_hashes")
    runner_rules_hash = _sha256(record["runner_rules_hash"], "runner_rules_hash")
    signer_policy_hash = _sha256(record["signer_policy_hash"], "signer_policy_hash")
    containerfile_path = _relative_path(record["containerfile_path"], "containerfile_path")
    _require(containerfile_path == _CONTAINERFILE_PATH, "wrong Containerfile path")
    containerfile_sha256 = _sha256(record["containerfile_sha256"], "containerfile_sha256")
    context_manifest_hash = _sha256(record["context_manifest_hash"], "context_manifest_hash")
    context_entries, raw_entries = _context_entries(record["context_entries"])
    _require(
        context_manifest_hash == _bytes_sha256(_restricted_json_bytes(raw_entries)),
        "context manifest hash does not rederive",
    )
    container_entries = [entry for entry in context_entries if entry.path == containerfile_path]
    _require(len(container_entries) == 1, "Containerfile context entry is missing or ambiguous")
    _require(
        containerfile_sha256 == container_entries[0].content_hash,
        "Containerfile hash does not bind its context entry",
    )
    _require(record["platform"] == "linux/amd64", "wrong platform")
    _require(record["build_target"] == "qualification", "wrong build target")
    build_arguments = _object(record["build_arguments"], "build_arguments")
    _require(not build_arguments, "caller build arguments are forbidden")
    _require(
        record["network_policy"] == "build_only_for_pinned_fetches_then_execution_none",
        "wrong network policy",
    )
    image_hashes = _hash_array(
        record["selected_image_closure_hashes"], "selected_image_closure_hashes"
    )
    runtime_identities = _runtime_identities(record["runtime_identity_requirements"])
    timeout_seconds = _integer(record["timeout_seconds"], "timeout_seconds")
    _require(timeout_seconds == 3600, "wrong timeout_seconds")
    retry_count = _integer(record["retry_count"], "retry_count")
    _require(retry_count == 0, "wrong retry_count")
    output_requirements = _output_requirements(record["required_output_artifacts"])
    _require(
        record["private_output_policy"] == "retain_raw_release_aggregate_only",
        "wrong private output policy",
    )
    profile_hash = _sha256(
        record["toolchain_execution_profile_hash"], "toolchain_execution_profile_hash"
    )
    _require(
        profile_hash == _record_hash(record, "toolchain_execution_profile_hash"),
        "execution-profile self-hash mismatch",
    )
    signature = _signature(record["signature"], "signature", "mkso.toolchain-execution-profile.v1")
    run_key = ToolchainRunKey(
        qualification_claim_id=claim_id,
        toolchain_execution_profile_hash=profile_hash,
        context_manifest_hash=context_manifest_hash,
    )
    return ToolchainExecutionProfile(
        document=document,
        run_key=run_key,
        profile_id=profile_id,
        revision=revision,
        approved_design_hashes=approved_design_hashes,
        runner_rules_hash=runner_rules_hash,
        signer_policy_hash=signer_policy_hash,
        containerfile_path=containerfile_path,
        containerfile_sha256=containerfile_sha256,
        context_entries=context_entries,
        platform="linux/amd64",
        build_target="qualification",
        build_arguments=(),
        network_policy="build_only_for_pinned_fetches_then_execution_none",
        selected_image_closure_hashes=image_hashes,
        runtime_identities=runtime_identities,
        timeout_seconds=3600,
        retry_count=0,
        required_output_artifacts=output_requirements,
        private_output_policy="retain_raw_release_aggregate_only",
        signature=signature,
    )


def load_toolchain_qualification_result(document: bytes) -> ToolchainQualificationResult:
    """Load one structurally valid A-05 safe result from retained bytes."""

    record = _load_record(document, "qualification result")
    _require_fields(record, _RESULT_FIELDS, "qualification result")
    _require(
        record["schema_version"] == "mkso-toolchain-qualification-result/1",
        "wrong qualification-result schema",
    )
    claim_id = _identifier(record["qualification_claim_id"], "qualification_claim_id")
    _require(claim_id == _CLAIM_ID, "wrong qualification claim")
    profile_hash = _sha256(
        record["toolchain_execution_profile_hash"], "toolchain_execution_profile_hash"
    )
    runner_rules_hash = _sha256(record["runner_rules_hash"], "runner_rules_hash")
    signer_policy_hash = _sha256(record["signer_policy_hash"], "signer_policy_hash")
    context_manifest_hash = _sha256(record["context_manifest_hash"], "context_manifest_hash")
    containerfile_sha256 = _sha256(record["containerfile_sha256"], "containerfile_sha256")
    runner_hash = _sha256(record["runner_hash"], "runner_hash")
    phase = record["authority_phase"]
    _require(phase in {"BOOTSTRAP", "FRAMEWORK"}, "invalid authority phase")
    result = record["result"]
    _require(result in {"PASSED", "UNVERIFIED"}, "invalid qualification result")
    public_artifacts = _public_artifacts(record["public_artifacts"], result)
    result_hash = _sha256(
        record["toolchain_qualification_result_hash"],
        "toolchain_qualification_result_hash",
    )
    _require(
        result_hash == _record_hash(record, "toolchain_qualification_result_hash"),
        "qualification-result self-hash mismatch",
    )
    signature = _signature(
        record["signature"], "signature", "mkso.toolchain-qualification-result.v1"
    )
    run_key = ToolchainRunKey(
        qualification_claim_id=claim_id,
        toolchain_execution_profile_hash=profile_hash,
        context_manifest_hash=context_manifest_hash,
    )
    return ToolchainQualificationResult(
        document=document,
        run_key=run_key,
        runner_rules_hash=runner_rules_hash,
        signer_policy_hash=signer_policy_hash,
        containerfile_sha256=containerfile_sha256,
        runner_hash=runner_hash,
        authority_phase=phase,
        result_hash=result_hash,
        result=result,
        public_artifacts=public_artifacts,
        signature=signature,
    )
