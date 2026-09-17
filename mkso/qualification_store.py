"""Narrow PostgreSQL persistence boundary for A-05 toolchain qualification."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import psycopg
from psycopg import errors, pq

from mkso.toolchain_qualification import (
    ToolchainExecutionProfile,
    ToolchainRunKey,
    load_toolchain_execution_profile,
    load_toolchain_qualification_result,
)

_SERVER_VERSION = 180006
_PSYCOPG_VERSION = "3.3.5"
_PSYCOPG_IMPLEMENTATION = "binary"
_SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_PRIVATE_BLOB_ROLES = (
    "profile",
    "context_file",
    "build_request",
    "stdout",
    "stderr",
    "network_observation",
    "runtime_observation",
    "required_output",
    "raw_output_manifest",
    "adapter_cleanup_observation",
    "cleanup_observation",
    "failure_observation",
    "postgres_event_prefix",
)
_PRIVATE_BLOB_ROLE_ORDER = {
    role: ordinal for ordinal, role in enumerate(_PRIVATE_BLOB_ROLES, start=1)
}
_SINGLETON_BLOB_ROLES = frozenset(
    {
        "profile",
        "stdout",
        "stderr",
        "network_observation",
        "runtime_observation",
        "raw_output_manifest",
        "adapter_cleanup_observation",
        "cleanup_observation",
        "failure_observation",
        "postgres_event_prefix",
    }
)
_RUN_KEY_FIELDS = frozenset(
    {
        "qualification_claim_id",
        "toolchain_execution_profile_hash",
        "context_manifest_hash",
    }
)
_PRIVATE_RUN_FIELDS = frozenset(
    {
        "schema_version",
        "run_key",
        "raw_output_manifest_hash",
        "cleanup_observation_hash",
        "postgres_event_prefix_hash",
        "blobs",
        "raw_run_hash",
    }
)
_PRIVATE_BLOB_FIELDS = frozenset({"role", "logical_name", "sha256", "size"})
_RAW_OUTPUT_FIELDS = frozenset(
    {
        "schema_version",
        "run_key",
        "request_hash",
        "adapter_qualification_hash",
        "observed_controls",
        "exit_code",
        "timed_out",
        "stdout",
        "stderr",
        "network_observation",
        "runtime_observation",
        "outputs",
        "violations",
        "failure_stage",
        "failure_observation",
        "raw_output_manifest_hash",
    }
)
_BLOB_REFERENCE_FIELDS = frozenset({"sha256", "size"})
_RAW_OUTPUT_ENTRY_FIELDS = frozenset({"label", "container_path", "sha256", "size"})
_OBSERVED_CONTROL_FIELDS = frozenset(
    {
        "context_manifest_hash",
        "containerfile_sha256",
        "platform",
        "build_target",
        "build_arguments",
        "network_policy",
        "selected_image_closure_hashes",
        "build_profile_hash",
        "docker_execution_profile_hash",
        "host_profile_hash",
        "runner_hash",
        "timeout_seconds",
        "retry_count",
    }
)
_BUILD_REQUEST_FIELDS = frozenset(
    {
        "toolchain_execution_profile_hash",
        "context_manifest_hash",
        "containerfile_path",
        "containerfile_sha256",
        "platform",
        "build_target",
        "build_arguments",
        "network_policy",
        "selected_image_closure_hashes",
        "runtime_identities",
        "timeout_seconds",
        "retry_count",
        "required_outputs",
        "request_hash",
    }
)
_RUNTIME_IDENTITY_FIELDS = frozenset(
    {
        "build_profile_hash",
        "docker_execution_profile_hash",
        "host_profile_hash",
        "runner_hash",
    }
)
_OUTPUT_REQUIREMENT_FIELDS = frozenset({"label", "container_path"})
_CLEANUP_FIELDS = frozenset(
    {
        "schema_version",
        "adapter_cleanup_observation",
        "runner_context_removed",
        "remaining_runner_paths",
        "cleanup_failures",
        "cleanup_observation_hash",
    }
)
_DATABASE_ROLES = {
    "broker": "mkso_i06_broker",
    "runner": "mkso_i06_runner",
    "private_human": "mkso_i06_private_human",
}
_RUNTIME_DATABASE_ROLES = frozenset(_DATABASE_ROLES.values()) | {"mkso_i06_owner"}


class QualificationStoreError(RuntimeError):
    """Raised when the narrow qualification store fails closed."""


class QualificationStoreSerializationError(QualificationStoreError):
    """Raised for an unretired serialization or deadlock failure."""


@dataclass(frozen=True, slots=True)
class QualificationAdmission:
    run_id: int
    run_key: ToolchainRunKey
    disposition: Literal["ADMITTED", "ACTIVE", "TERMINAL"]
    terminal_document: bytes | None


@dataclass(frozen=True, slots=True)
class QualificationPrivateBlob:
    role: Literal[
        "profile",
        "context_file",
        "build_request",
        "stdout",
        "stderr",
        "network_observation",
        "runtime_observation",
        "required_output",
        "raw_output_manifest",
        "adapter_cleanup_observation",
        "cleanup_observation",
        "failure_observation",
        "postgres_event_prefix",
    ]
    logical_name: str
    content: bytes


@dataclass(frozen=True, slots=True)
class QualificationPrivateRun:
    run_key: ToolchainRunKey
    raw_output_manifest_hash: str
    cleanup_observation_hash: str
    postgres_event_prefix_hash: str
    blobs: tuple[QualificationPrivateBlob, ...]
    manifest_document: bytes
    raw_run_hash: str


@dataclass(frozen=True, slots=True)
class QualificationPrivateRunReceipt:
    run_key: ToolchainRunKey
    raw_run_hash: str
    retained_manifest_hash: str
    postgres_event_prefix_hash: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationStoreError(message)


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate JSON member {key}")
        result[key] = value
    return result


def _reject_numeric_constant(value: str) -> None:
    raise QualificationStoreError(f"non-JSON numeric constant {value}")


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
            _require(type(key) is str and key.isascii(), f"{location}: invalid JSON member")
            _validate_restricted_value(item, f"{location}.{key}")
        return
    raise QualificationStoreError(
        f"{location}: unsupported restricted-JCS value {value_type.__name__}"
    )


def _restricted_json_bytes(value: object) -> bytes:
    _validate_restricted_value(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _load_restricted_object(document: bytes, label: str) -> dict[str, Any]:
    _require(type(document) is bytes and bool(document), f"{label} must be non-empty bytes")
    try:
        source = document.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise QualificationStoreError(f"{label} is not strict UTF-8") from exc
    try:
        value = json.loads(
            source,
            object_pairs_hook=_reject_duplicate_members,
            parse_constant=_reject_numeric_constant,
        )
    except QualificationStoreError:
        raise
    except json.JSONDecodeError as exc:
        raise QualificationStoreError(f"{label} is not strict JSON") from exc
    _require(type(value) is dict, f"{label} must contain one object")
    _validate_restricted_value(value)
    _require(_restricted_json_bytes(value) == document, f"{label} is not canonical")
    return value


def _require_fields(value: dict[str, Any], expected: frozenset[str], label: str) -> None:
    _require(
        value.keys() == expected,
        f"{label} fields are incomplete or extra",
    )


def _object(value: object, label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    return value


def _array(value: object, label: str) -> list[Any]:
    _require(type(value) is list, f"{label} must be an array")
    return value


def _string(value: object, label: str, *, nonempty: bool = True) -> str:
    _require(type(value) is str, f"{label} must be a string")
    _require(value.isascii(), f"{label} must be ASCII")
    _require(not nonempty or bool(value), f"{label} must not be empty")
    return value


def _sha256(value: object, label: str) -> str:
    result = _string(value, label)
    _require(_SHA256_PATTERN.fullmatch(result) is not None, f"{label} must be lowercase SHA-256")
    return result


def _optional_sha256(value: object, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _integer(value: object, label: str, *, minimum: int | None = None) -> int:
    _require(type(value) is int, f"{label} must be an integer")
    _require(
        -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER,
        f"{label} is outside the interoperable range",
    )
    _require(minimum is None or value >= minimum, f"{label} is below its minimum")
    return value


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _record_hash(record: dict[str, Any], omitted_field: str) -> str:
    projection = {key: value for key, value in record.items() if key != omitted_field}
    return _bytes_sha256(_restricted_json_bytes(projection))


def _run_key_record(value: object, label: str) -> ToolchainRunKey:
    record = _object(value, label)
    _require_fields(record, _RUN_KEY_FIELDS, label)
    claim_id = _string(record["qualification_claim_id"], f"{label}.qualification_claim_id")
    _require(_ID_PATTERN.fullmatch(claim_id) is not None, f"{label} has an invalid claim ID")
    return ToolchainRunKey(
        qualification_claim_id=claim_id,
        toolchain_execution_profile_hash=_sha256(
            record["toolchain_execution_profile_hash"],
            f"{label}.toolchain_execution_profile_hash",
        ),
        context_manifest_hash=_sha256(
            record["context_manifest_hash"], f"{label}.context_manifest_hash"
        ),
    )


def _blob_reference(value: object, label: str) -> tuple[str, int]:
    record = _object(value, label)
    _require_fields(record, _BLOB_REFERENCE_FIELDS, label)
    return _sha256(record["sha256"], f"{label}.sha256"), _integer(
        record["size"], f"{label}.size", minimum=0
    )


def _unique_ascii_array(value: object, label: str) -> tuple[str, ...]:
    result = tuple(
        _string(item, f"{label}[{index}]", nonempty=False)
        for index, item in enumerate(_array(value, label))
    )
    _require(len(result) == len(set(result)), f"{label} contains duplicates")
    return result


def _expected_runtime_identities(profile: ToolchainExecutionProfile) -> dict[str, str]:
    identities = profile.runtime_identities
    return {
        "build_profile_hash": identities.build_profile_hash,
        "docker_execution_profile_hash": identities.docker_execution_profile_hash,
        "host_profile_hash": identities.host_profile_hash,
        "runner_hash": identities.runner_hash,
    }


def _validate_runtime_identities(
    value: object,
    profile: ToolchainExecutionProfile,
    label: str,
) -> None:
    record = _object(value, label)
    _require_fields(record, _RUNTIME_IDENTITY_FIELDS, label)
    observed = {
        field: _sha256(record[field], f"{label}.{field}") for field in _RUNTIME_IDENTITY_FIELDS
    }
    _require(observed == _expected_runtime_identities(profile), f"{label} does not match profile")


def _validate_selected_images(
    value: object,
    profile: ToolchainExecutionProfile,
    label: str,
) -> None:
    observed = tuple(
        _sha256(item, f"{label}[{index}]") for index, item in enumerate(_array(value, label))
    )
    _require(
        observed == profile.selected_image_closure_hashes,
        f"{label} does not match profile order",
    )


def _validate_output_requirements(
    value: object,
    profile: ToolchainExecutionProfile,
    label: str,
) -> None:
    raw_outputs = _array(value, label)
    expected = profile.required_output_artifacts
    _require(len(raw_outputs) == len(expected), f"{label} does not match profile")
    for index, (item, requirement) in enumerate(zip(raw_outputs, expected, strict=True)):
        item_label = f"{label}[{index}]"
        record = _object(item, item_label)
        _require_fields(record, _OUTPUT_REQUIREMENT_FIELDS, item_label)
        _require(
            _string(record["label"], f"{item_label}.label") == requirement.label
            and _string(record["container_path"], f"{item_label}.container_path")
            == requirement.container_path,
            f"{item_label} does not match profile",
        )


def _validate_build_request(
    document: bytes,
    profile: ToolchainExecutionProfile,
    expected_hash: str,
) -> None:
    record = _load_restricted_object(document, "build-request document")
    _require_fields(record, _BUILD_REQUEST_FIELDS, "build-request document")
    _require(
        _sha256(
            record["toolchain_execution_profile_hash"],
            "build-request.toolchain_execution_profile_hash",
        )
        == profile.run_key.toolchain_execution_profile_hash,
        "build request has the wrong profile hash",
    )
    _require(
        _sha256(record["context_manifest_hash"], "build-request.context_manifest_hash")
        == profile.run_key.context_manifest_hash,
        "build request has the wrong context hash",
    )
    _require(
        _string(record["containerfile_path"], "build-request.containerfile_path")
        == profile.containerfile_path,
        "build request has the wrong Containerfile path",
    )
    _require(
        _sha256(record["containerfile_sha256"], "build-request.containerfile_sha256")
        == profile.containerfile_sha256,
        "build request has the wrong Containerfile hash",
    )
    _require(record["platform"] == profile.platform, "build request has the wrong platform")
    _require(
        record["build_target"] == profile.build_target,
        "build request has the wrong build target",
    )
    _require(
        type(record["build_arguments"]) is list and not record["build_arguments"],
        "build request has forbidden build arguments",
    )
    _require(
        record["network_policy"] == profile.network_policy,
        "build request has the wrong network policy",
    )
    _validate_selected_images(
        record["selected_image_closure_hashes"],
        profile,
        "build-request.selected_image_closure_hashes",
    )
    _validate_runtime_identities(
        record["runtime_identities"], profile, "build-request.runtime_identities"
    )
    _require(
        _integer(record["timeout_seconds"], "build-request.timeout_seconds", minimum=0)
        == profile.timeout_seconds,
        "build request has the wrong timeout",
    )
    _require(
        _integer(record["retry_count"], "build-request.retry_count", minimum=0)
        == profile.retry_count,
        "build request has the wrong retry count",
    )
    _validate_output_requirements(
        record["required_outputs"], profile, "build-request.required_outputs"
    )
    request_hash = _sha256(record["request_hash"], "build-request.request_hash")
    _require(
        request_hash == _record_hash(record, "request_hash") == expected_hash,
        "build-request hash does not rederive",
    )


def _validate_observed_controls(
    value: object,
    profile: ToolchainExecutionProfile,
) -> None:
    record = _object(value, "raw-output.observed_controls")
    _require_fields(record, _OBSERVED_CONTROL_FIELDS, "raw-output.observed_controls")
    expected_scalars: dict[str, str] = {
        "context_manifest_hash": profile.run_key.context_manifest_hash,
        "containerfile_sha256": profile.containerfile_sha256,
        "platform": profile.platform,
        "build_target": profile.build_target,
        "network_policy": profile.network_policy,
    }
    for field, expected in expected_scalars.items():
        observed = (
            _sha256(record[field], f"raw-output.observed_controls.{field}")
            if field.endswith("hash") or field.endswith("sha256")
            else _string(record[field], f"raw-output.observed_controls.{field}")
        )
        _require(observed == expected, f"observed control {field} does not match profile")
    _require(
        type(record["build_arguments"]) is list and not record["build_arguments"],
        "observed controls contain forbidden build arguments",
    )
    _validate_selected_images(
        record["selected_image_closure_hashes"],
        profile,
        "raw-output.observed_controls.selected_image_closure_hashes",
    )
    expected_identities = _expected_runtime_identities(profile)
    for field, expected in expected_identities.items():
        _require(
            _sha256(record[field], f"raw-output.observed_controls.{field}") == expected,
            f"observed control {field} does not match profile",
        )
    _require(
        _integer(
            record["timeout_seconds"],
            "raw-output.observed_controls.timeout_seconds",
            minimum=0,
        )
        == profile.timeout_seconds,
        "observed timeout does not match profile",
    )
    _require(
        _integer(record["retry_count"], "raw-output.observed_controls.retry_count", minimum=0)
        == profile.retry_count,
        "observed retry count does not match profile",
    )


def _validate_raw_output(
    document: bytes,
    profile: ToolchainExecutionProfile,
    expected_hash: str,
) -> dict[str, Any]:
    record = _load_restricted_object(document, "raw-output manifest")
    _require_fields(record, _RAW_OUTPUT_FIELDS, "raw-output manifest")
    _require(
        record["schema_version"] == "mkso-toolchain-raw-output/1",
        "raw-output manifest has the wrong schema",
    )
    _require(
        _run_key_record(record["run_key"], "raw-output.run_key") == profile.run_key,
        "raw-output manifest has the wrong run key",
    )
    request_hash = _optional_sha256(record["request_hash"], "raw-output.request_hash")
    adapter_hash = _optional_sha256(
        record["adapter_qualification_hash"], "raw-output.adapter_qualification_hash"
    )
    observed_controls = record["observed_controls"]
    if observed_controls is not None:
        _require(request_hash is not None, "observed controls lack a build request")
        _require(adapter_hash is not None, "observed controls lack an adapter identity")
        _validate_observed_controls(observed_controls, profile)
    exit_code = record["exit_code"]
    if exit_code is not None:
        exit_code = _integer(exit_code, "raw-output.exit_code")
    _require(type(record["timed_out"]) is bool, "raw-output.timed_out must be a boolean")
    references = {
        role: _blob_reference(record[role], f"raw-output.{role}")
        for role in (
            "stdout",
            "stderr",
            "network_observation",
            "runtime_observation",
            "failure_observation",
        )
    }

    profile_outputs = {
        requirement.label: (index, requirement.container_path)
        for index, requirement in enumerate(profile.required_output_artifacts)
    }
    output_references: dict[str, tuple[str, int]] = {}
    output_order: list[int] = []
    for index, item in enumerate(_array(record["outputs"], "raw-output.outputs")):
        label = f"raw-output.outputs[{index}]"
        output = _object(item, label)
        _require_fields(output, _RAW_OUTPUT_ENTRY_FIELDS, label)
        output_label = _string(output["label"], f"{label}.label")
        _require(output_label in profile_outputs, f"{label} is not declared by the profile")
        _require(output_label not in output_references, f"{label} duplicates an output label")
        profile_index, expected_path = profile_outputs[output_label]
        _require(
            _string(output["container_path"], f"{label}.container_path") == expected_path,
            f"{label} has the wrong container path",
        )
        output_order.append(profile_index)
        output_references[output_label] = (
            _sha256(output["sha256"], f"{label}.sha256"),
            _integer(output["size"], f"{label}.size", minimum=0),
        )
    _require(output_order == sorted(output_order), "raw-output outputs are not in profile order")

    violations = _unique_ascii_array(record["violations"], "raw-output.violations")
    failure_stage = record["failure_stage"]
    _require(
        failure_stage in {None, "context", "request", "adapter", "output"},
        "raw-output failure stage is invalid",
    )
    raw_output_hash = _sha256(
        record["raw_output_manifest_hash"], "raw-output.raw_output_manifest_hash"
    )
    _require(
        raw_output_hash == _record_hash(record, "raw_output_manifest_hash") == expected_hash,
        "raw-output manifest hash does not rederive",
    )

    if failure_stage is None:
        _require(request_hash is not None, "successful raw output lacks its request")
        _require(adapter_hash is not None, "successful raw output lacks its adapter identity")
        _require(observed_controls is not None, "successful raw output lacks observed controls")
        _require(exit_code == 0, "successful raw output has a nonzero or missing exit code")
        _require(record["timed_out"] is False, "successful raw output reports a timeout")
        _require(not violations, "successful raw output contains violations")
        _require(
            tuple(output_references)
            == tuple(item.label for item in profile.required_output_artifacts),
            "successful raw output is missing required outputs",
        )

    return {
        "request_hash": request_hash,
        "failure_stage": failure_stage,
        "references": references,
        "output_references": output_references,
    }


def _validate_cleanup_observation(
    document: bytes,
    expected_hash: str,
) -> tuple[str, int]:
    record = _load_restricted_object(document, "cleanup-observation document")
    _require_fields(record, _CLEANUP_FIELDS, "cleanup-observation document")
    _require(
        record["schema_version"] == "mkso-toolchain-cleanup-observation/1",
        "cleanup observation has the wrong schema",
    )
    adapter_reference = _blob_reference(
        record["adapter_cleanup_observation"],
        "cleanup-observation.adapter_cleanup_observation",
    )
    _require(
        type(record["runner_context_removed"]) is bool,
        "cleanup-observation.runner_context_removed must be a boolean",
    )
    _unique_ascii_array(
        record["remaining_runner_paths"], "cleanup-observation.remaining_runner_paths"
    )
    _unique_ascii_array(record["cleanup_failures"], "cleanup-observation.cleanup_failures")
    cleanup_hash = _sha256(
        record["cleanup_observation_hash"], "cleanup-observation.cleanup_observation_hash"
    )
    _require(
        cleanup_hash == _record_hash(record, "cleanup_observation_hash") == expected_hash,
        "cleanup-observation hash does not rederive",
    )
    return adapter_reference


def _require_blob_reference(
    blob: QualificationPrivateBlob,
    reference: tuple[str, int],
    label: str,
) -> None:
    _require(
        _bytes_sha256(blob.content) == reference[0] and len(blob.content) == reference[1],
        f"{label} does not match its document reference",
    )


def _validate_private_run(
    private_run: QualificationPrivateRun,
    event_prefix: bytes,
) -> tuple[str, list[str], list[str], list[str], list[int], list[bytes]]:
    manifest = _load_restricted_object(private_run.manifest_document, "private-run manifest")
    _require_fields(manifest, _PRIVATE_RUN_FIELDS, "private-run manifest")
    _require(
        manifest["schema_version"] == "mkso-toolchain-private-run/1",
        "private-run manifest has the wrong schema",
    )
    _require(
        _run_key_record(manifest["run_key"], "private-run.run_key") == private_run.run_key,
        "private-run manifest has the wrong run key",
    )
    manifest_raw_hash = _sha256(
        manifest["raw_output_manifest_hash"], "private-run.raw_output_manifest_hash"
    )
    manifest_cleanup_hash = _sha256(
        manifest["cleanup_observation_hash"], "private-run.cleanup_observation_hash"
    )
    manifest_prefix_hash = _sha256(
        manifest["postgres_event_prefix_hash"], "private-run.postgres_event_prefix_hash"
    )
    _require(
        manifest_raw_hash == private_run.raw_output_manifest_hash
        and manifest_cleanup_hash == private_run.cleanup_observation_hash
        and manifest_prefix_hash == private_run.postgres_event_prefix_hash,
        "private-run manifest commitments do not match the submitted record",
    )
    manifest_raw_run_hash = _sha256(manifest["raw_run_hash"], "private-run.raw_run_hash")
    _require(
        manifest_raw_run_hash == _record_hash(manifest, "raw_run_hash") == private_run.raw_run_hash,
        "private-run self-hash does not rederive",
    )

    raw_manifest_blobs = _array(manifest["blobs"], "private-run.blobs")
    _require(raw_manifest_blobs, "private-run manifest has no blobs")
    _require(
        type(private_run.blobs) is tuple and len(private_run.blobs) == len(raw_manifest_blobs),
        "private-run blob sequence has the wrong type or length",
    )

    roles: list[str] = []
    logical_names: list[str] = []
    hashes: list[str] = []
    sizes: list[int] = []
    contents: list[bytes] = []
    by_role: dict[str, list[QualificationPrivateBlob]] = {role: [] for role in _PRIVATE_BLOB_ROLES}
    previous_order: tuple[int, bytes] | None = None
    seen_pairs: set[tuple[str, str]] = set()
    for index, (blob, raw_entry) in enumerate(
        zip(private_run.blobs, raw_manifest_blobs, strict=True)
    ):
        label = f"private-run.blobs[{index}]"
        _require(type(blob) is QualificationPrivateBlob, f"{label} has the wrong Python type")
        _require(
            type(blob.role) is str and blob.role in _PRIVATE_BLOB_ROLE_ORDER,
            f"{label}.role is invalid",
        )
        logical_name = _string(blob.logical_name, f"{label}.logical_name")
        _require("\x00" not in logical_name, f"{label}.logical_name contains NUL")
        _require(type(blob.content) is bytes, f"{label}.content must be exact bytes")
        pair = (blob.role, logical_name)
        _require(pair not in seen_pairs, f"{label} duplicates a role/name pair")
        seen_pairs.add(pair)
        order = (_PRIVATE_BLOB_ROLE_ORDER[blob.role], logical_name.encode("utf-8"))
        _require(
            previous_order is None or order > previous_order, "private-run blobs are reordered"
        )
        previous_order = order

        entry = _object(raw_entry, label)
        _require_fields(entry, _PRIVATE_BLOB_FIELDS, label)
        entry_role = _string(entry["role"], f"{label}.role")
        entry_name = _string(entry["logical_name"], f"{label}.logical_name")
        entry_hash = _sha256(entry["sha256"], f"{label}.sha256")
        entry_size = _integer(entry["size"], f"{label}.size", minimum=0)
        content_hash = _bytes_sha256(blob.content)
        _require(
            entry_role == blob.role
            and entry_name == logical_name
            and entry_hash == content_hash
            and entry_size == len(blob.content),
            f"{label} metadata does not match its exact blob",
        )
        roles.append(blob.role)
        logical_names.append(logical_name)
        hashes.append(content_hash)
        sizes.append(len(blob.content))
        contents.append(blob.content)
        by_role[blob.role].append(blob)

    for role in _SINGLETON_BLOB_ROLES:
        blobs = by_role[role]
        _require(len(blobs) == 1, f"private run requires exactly one {role} blob")
        _require(blobs[0].logical_name == role, f"{role} blob has the wrong logical name")
    _require(len(by_role["build_request"]) <= 1, "private run has duplicate build requests")
    if by_role["build_request"]:
        _require(
            by_role["build_request"][0].logical_name == "build_request",
            "build-request blob has the wrong logical name",
        )

    profile_blob = by_role["profile"][0]
    profile = load_toolchain_execution_profile(profile_blob.content)
    _require(profile.run_key == private_run.run_key, "profile blob has the wrong run key")

    raw_output_blob = by_role["raw_output_manifest"][0]
    raw_output = _validate_raw_output(
        raw_output_blob.content,
        profile,
        private_run.raw_output_manifest_hash,
    )
    cleanup_blob = by_role["cleanup_observation"][0]
    adapter_cleanup_reference = _validate_cleanup_observation(
        cleanup_blob.content,
        private_run.cleanup_observation_hash,
    )

    _require(
        _bytes_sha256(event_prefix) == private_run.postgres_event_prefix_hash,
        "current PostgreSQL event-prefix hash does not match the private run",
    )
    prefix_blob = by_role["postgres_event_prefix"][0]
    _require(
        prefix_blob.content == event_prefix, "event-prefix blob is not the current exact prefix"
    )

    for role, reference in raw_output["references"].items():
        _require_blob_reference(by_role[role][0], reference, role)
    _require_blob_reference(
        by_role["adapter_cleanup_observation"][0],
        adapter_cleanup_reference,
        "adapter cleanup observation",
    )

    required_output_blobs = {blob.logical_name: blob for blob in by_role["required_output"]}
    _require(
        len(required_output_blobs) == len(by_role["required_output"]),
        "required-output logical names are duplicated",
    )
    output_references = raw_output["output_references"]
    _require(
        required_output_blobs.keys() == output_references.keys(),
        "required-output blobs do not equal the raw-output entries",
    )
    for output_label, reference in output_references.items():
        _require_blob_reference(
            required_output_blobs[output_label], reference, f"required output {output_label}"
        )

    context_blobs = {blob.logical_name: blob for blob in by_role["context_file"]}
    _require(
        len(context_blobs) == len(by_role["context_file"]),
        "context logical names are duplicated",
    )
    profile_context = {entry.path: entry for entry in profile.context_entries}
    _require(
        context_blobs.keys() <= profile_context.keys(),
        "private run contains a context file absent from the profile",
    )

    request_hash = raw_output["request_hash"]
    request_blobs = by_role["build_request"]
    _require(
        (request_hash is None and not request_blobs)
        or (request_hash is not None and len(request_blobs) == 1),
        "build-request presence does not match raw-output request construction",
    )
    if request_hash is not None:
        _validate_build_request(request_blobs[0].content, profile, request_hash)

    if raw_output["failure_stage"] is None:
        _require(
            context_blobs.keys() == profile_context.keys(),
            "successful raw output lacks the complete profile context",
        )
        for path, entry in profile_context.items():
            blob = context_blobs[path]
            _require(
                len(blob.content) == entry.size
                and _bytes_sha256(blob.content) == entry.content_hash,
                f"successful context blob {path} does not match the profile",
            )
        _require(
            by_role["failure_observation"][0].content == b"",
            "successful raw output has a failure observation",
        )
        _require(
            bool(by_role["network_observation"][0].content)
            and bool(by_role["runtime_observation"][0].content),
            "successful raw output lacks execution observations",
        )
        _require(
            all(blob.content for blob in by_role["required_output"]),
            "successful raw output contains an empty required output",
        )

    retained_manifest_hash = _bytes_sha256(private_run.manifest_document)
    return retained_manifest_hash, roles, logical_names, hashes, sizes, contents


def _event_timestamp(value: object, label: str) -> str:
    _require(type(value) is datetime, f"{label} is not a typed timestamp")
    try:
        offset = value.utcoffset()
    except (OverflowError, ValueError) as exc:
        raise QualificationStoreError(f"{label} is outside the supported range") from exc
    _require(offset is not None, f"{label} has no timezone")
    try:
        normalized = value.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise QualificationStoreError(f"{label} cannot be normalized to UTC") from exc
    return normalized.isoformat(timespec="microseconds").removesuffix("+00:00") + "Z"


def _read_private_event_prefix(
    connection: psycopg.Connection[tuple[object, ...]],
    run_key: ToolchainRunKey,
) -> bytes:
    rows = connection.execute(
        "SELECT * FROM mkso_i06.read_toolchain_event_prefix(%s, %s, %s)",
        (
            run_key.qualification_claim_id,
            run_key.toolchain_execution_profile_hash,
            run_key.context_manifest_hash,
        ),
    ).fetchall()
    _require(type(rows) is list and len(rows) == 4, "event-prefix read did not return four rows")
    expected_kinds = ("admission", "start", "raw_output_commitment", "cleanup")
    expected_actors = (
        "mkso_i06_broker",
        "mkso_i06_runner",
        "mkso_i06_runner",
        "mkso_i06_runner",
    )
    run_id: int | None = None
    events: list[dict[str, object]] = []
    for index, row in enumerate(rows, start=1):
        label = f"event-prefix row {index}"
        _require(type(row) is tuple and len(row) == 6, f"{label} has the wrong shape")
        row_run_id, ordinal, event_kind, actor, commitment_hash, recorded_at = row
        observed_run_id = _integer(row_run_id, f"{label}.run_id", minimum=1)
        _require(observed_run_id <= _MAX_SAFE_INTEGER, f"{label}.run_id is too large")
        if run_id is None:
            run_id = observed_run_id
        _require(observed_run_id == run_id, f"{label} has a different run ID")
        _require(_integer(ordinal, f"{label}.ordinal", minimum=1) == index, f"{label} is reordered")
        _require(
            type(event_kind) is str and event_kind == expected_kinds[index - 1],
            f"{label} has the wrong event kind",
        )
        _require(
            type(actor) is str and actor == expected_actors[index - 1],
            f"{label} has the wrong actor",
        )
        commitment = _sha256(commitment_hash, f"{label}.commitment_hash")
        if index <= 2:
            _require(
                commitment == run_key.toolchain_execution_profile_hash,
                f"{label} does not commit to the profile",
            )
        events.append(
            {
                "actor": actor,
                "commitment_hash": commitment,
                "event_kind": event_kind,
                "ordinal": index,
                "recorded_at": _event_timestamp(recorded_at, f"{label}.recorded_at"),
            }
        )
    _require(run_id is not None, "event-prefix read omitted its run ID")
    value = {
        "events": events,
        "run_id": run_id,
        "run_key": {
            "context_manifest_hash": run_key.context_manifest_hash,
            "qualification_claim_id": run_key.qualification_claim_id,
            "toolchain_execution_profile_hash": run_key.toolchain_execution_profile_hash,
        },
        "schema_version": "mkso-toolchain-postgres-event-prefix/1",
    }
    document = _restricted_json_bytes(value)
    _require(
        _load_restricted_object(document, "generated event-prefix document") == value,
        "generated event-prefix document does not rederive",
    )
    return document


class QualificationStore:
    """Role-bound access to the approved I-06 PostgreSQL functions."""

    def __init__(
        self,
        connection: psycopg.Connection[tuple[object, ...]],
        *,
        expected_role: Literal["broker", "runner", "private_human"],
    ) -> None:
        if expected_role not in _DATABASE_ROLES:
            raise QualificationStoreError("unsupported qualification-store role")
        if connection.closed or connection.broken:
            raise QualificationStoreError("qualification-store connection is not usable")
        if connection.info.transaction_status != pq.TransactionStatus.IDLE:
            raise QualificationStoreError("qualification-store connection is not idle")
        if psycopg.__version__ != _PSYCOPG_VERSION:
            raise QualificationStoreError("unexpected Psycopg version")
        if pq.__impl__ != _PSYCOPG_IMPLEMENTATION:
            raise QualificationStoreError("unexpected Psycopg implementation")
        if pq.__build_version__ != _SERVER_VERSION or pq.version() != _SERVER_VERSION:
            raise QualificationStoreError("unexpected libpq build or runtime version")
        if connection.info.server_version != _SERVER_VERSION:
            raise QualificationStoreError("unexpected PostgreSQL server version")

        expected_database_role = _DATABASE_ROLES[expected_role]
        try:
            with connection.transaction():
                row = connection.execute(
                    """
                    SELECT
                        current_user::text,
                        role.rolsuper,
                        role.rolbypassrls,
                        ARRAY(
                            SELECT granted_role.rolname::text
                            FROM pg_catalog.pg_auth_members AS membership
                            JOIN pg_catalog.pg_roles AS granted_role
                              ON granted_role.oid = membership.roleid
                            WHERE membership.member = role.oid
                              AND granted_role.rolname = ANY (%s)
                            ORDER BY granted_role.rolname
                        )
                    FROM pg_catalog.pg_roles AS role
                    WHERE role.rolname = current_user
                    """,
                    (list(sorted(_RUNTIME_DATABASE_ROLES)),),
                ).fetchone()
        except psycopg.Error as exc:
            raise QualificationStoreError("could not verify qualification-store role") from exc
        if connection.info.transaction_status != pq.TransactionStatus.IDLE:
            raise QualificationStoreError("role verification did not leave the connection idle")
        if row is None or len(row) != 4:
            raise QualificationStoreError("qualification-store role is unavailable")
        current_user, is_superuser, bypasses_rls, memberships = row
        if current_user != expected_database_role:
            raise QualificationStoreError(
                "qualification-store current_user is not the expected role"
            )
        if is_superuser is not False or bypasses_rls is not False:
            raise QualificationStoreError("qualification-store role has forbidden authority")
        if memberships not in ([], ()):
            raise QualificationStoreError("qualification-store role membership is not exact")

        self._connection = connection
        self._role = expected_role

    @contextmanager
    def _serializable_operation(self) -> Iterator[None]:
        if self._connection.closed or self._connection.broken:
            raise QualificationStoreError("qualification-store connection is not usable")
        if self._connection.info.transaction_status != pq.TransactionStatus.IDLE:
            raise QualificationStoreError(
                "qualification-store operation requires an idle connection"
            )
        try:
            with self._connection.transaction():
                self._connection.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                yield
        except (errors.SerializationFailure, errors.DeadlockDetected) as exc:
            raise QualificationStoreSerializationError(
                "qualification-store transaction was not retired"
            ) from exc
        except psycopg.Error as exc:
            raise QualificationStoreError("qualification-store operation failed") from exc

    def _require_role(self, *allowed: str) -> None:
        if self._role not in allowed:
            raise QualificationStoreError(
                "qualification-store method is not authorized for this role"
            )

    @staticmethod
    def _require_run_key(run_key: ToolchainRunKey) -> None:
        if type(run_key) is not ToolchainRunKey:
            raise QualificationStoreError("run key has the wrong type")
        if (
            type(run_key.qualification_claim_id) is not str
            or _ID_PATTERN.fullmatch(run_key.qualification_claim_id) is None
        ):
            raise QualificationStoreError("run key has an invalid claim ID")
        if (
            type(run_key.toolchain_execution_profile_hash) is not str
            or type(run_key.context_manifest_hash) is not str
            or _SHA256_PATTERN.fullmatch(run_key.toolchain_execution_profile_hash) is None
            or _SHA256_PATTERN.fullmatch(run_key.context_manifest_hash) is None
        ):
            raise QualificationStoreError("run key has an invalid hash")

    @staticmethod
    def _require_commitment(value: str, label: str) -> None:
        if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
            raise QualificationStoreError(f"{label} must be lowercase SHA-256")

    def private_event_prefix(self, run_key: ToolchainRunKey) -> bytes:
        self._require_role("runner")
        self._require_run_key(run_key)
        with self._serializable_operation():
            return _read_private_event_prefix(self._connection, run_key)

    def retain_private_run(
        self,
        private_run: QualificationPrivateRun,
    ) -> QualificationPrivateRunReceipt:
        self._require_role("runner")
        if type(private_run) is not QualificationPrivateRun:
            raise QualificationStoreError("private run has the wrong type")
        self._require_run_key(private_run.run_key)
        self._require_commitment(private_run.raw_output_manifest_hash, "raw-output manifest hash")
        self._require_commitment(private_run.cleanup_observation_hash, "cleanup-observation hash")
        self._require_commitment(
            private_run.postgres_event_prefix_hash, "PostgreSQL event-prefix hash"
        )
        self._require_commitment(private_run.raw_run_hash, "raw-run hash")
        if type(private_run.manifest_document) is not bytes:
            raise QualificationStoreError("private-run manifest must be exact bytes")

        with self._serializable_operation():
            event_prefix = _read_private_event_prefix(self._connection, private_run.run_key)
            (
                retained_manifest_hash,
                blob_roles,
                blob_logical_names,
                blob_hashes,
                blob_sizes,
                blob_contents,
            ) = _validate_private_run(private_run, event_prefix)
            row = self._connection.execute(
                """
                SELECT raw_run_hash, retained_manifest_hash, postgres_event_prefix_hash
                FROM mkso_i06.retain_toolchain_private_run(
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                )
                """,
                (
                    private_run.run_key.qualification_claim_id,
                    private_run.run_key.toolchain_execution_profile_hash,
                    private_run.run_key.context_manifest_hash,
                    private_run.raw_output_manifest_hash,
                    private_run.cleanup_observation_hash,
                    private_run.postgres_event_prefix_hash,
                    private_run.raw_run_hash,
                    retained_manifest_hash,
                    private_run.manifest_document,
                    blob_roles,
                    blob_logical_names,
                    blob_hashes,
                    blob_sizes,
                    blob_contents,
                ),
            ).fetchone()
            if row is None or type(row) is not tuple or len(row) != 3:
                raise QualificationStoreError("private-run retention returned an invalid receipt")
            returned_raw_hash = _sha256(row[0], "retained receipt raw-run hash")
            returned_manifest_hash = _sha256(row[1], "retained receipt manifest hash")
            returned_prefix_hash = _sha256(row[2], "retained receipt event-prefix hash")
            _require(
                returned_raw_hash == private_run.raw_run_hash
                and returned_manifest_hash == retained_manifest_hash
                and returned_prefix_hash == private_run.postgres_event_prefix_hash,
                "private-run retention returned a different receipt",
            )
            return QualificationPrivateRunReceipt(
                run_key=private_run.run_key,
                raw_run_hash=returned_raw_hash,
                retained_manifest_hash=returned_manifest_hash,
                postgres_event_prefix_hash=returned_prefix_hash,
            )

    def admit(self, profile_document: bytes) -> QualificationAdmission:
        self._require_role("broker")
        with self._serializable_operation():
            profile = load_toolchain_execution_profile(profile_document)
            row = self._connection.execute(
                """
                SELECT run_id, disposition, terminal_document
                FROM mkso_i06.admit_toolchain_run(%s, %s, %s, %s)
                """,
                (
                    profile.document,
                    profile.run_key.toolchain_execution_profile_hash,
                    profile.run_key.qualification_claim_id,
                    profile.run_key.context_manifest_hash,
                ),
            ).fetchone()
            if row is None or len(row) != 3:
                raise QualificationStoreError("admission did not return exactly one result")
            run_id, disposition, terminal_document = row
            if type(run_id) is not int or run_id <= 0:
                raise QualificationStoreError("admission returned an invalid run ID")
            if disposition not in {"ADMITTED", "ACTIVE", "TERMINAL"}:
                raise QualificationStoreError("admission returned an invalid disposition")
            if disposition == "TERMINAL":
                if not isinstance(terminal_document, bytes) or not terminal_document:
                    raise QualificationStoreError(
                        "terminal admission omitted its retained document"
                    )
            elif terminal_document is not None:
                raise QualificationStoreError("nonterminal admission exposed a terminal document")
            return QualificationAdmission(
                run_id=run_id,
                run_key=profile.run_key,
                disposition=disposition,
                terminal_document=terminal_document,
            )

    def mark_started(self, run_key: ToolchainRunKey) -> None:
        self._require_role("runner")
        self._require_run_key(run_key)
        with self._serializable_operation():
            self._connection.execute(
                "SELECT mkso_i06.start_toolchain_run(%s, %s, %s)",
                (
                    run_key.qualification_claim_id,
                    run_key.toolchain_execution_profile_hash,
                    run_key.context_manifest_hash,
                ),
            ).fetchone()

    def commit_raw_output_hash(
        self,
        run_key: ToolchainRunKey,
        raw_output_commitment: str,
    ) -> None:
        self._require_role("runner")
        self._require_run_key(run_key)
        self._require_commitment(raw_output_commitment, "raw-output commitment")
        with self._serializable_operation():
            self._connection.execute(
                "SELECT mkso_i06.commit_raw_output(%s, %s, %s, %s)",
                (
                    run_key.qualification_claim_id,
                    run_key.toolchain_execution_profile_hash,
                    run_key.context_manifest_hash,
                    raw_output_commitment,
                ),
            ).fetchone()

    def commit_cleanup_hash(
        self,
        run_key: ToolchainRunKey,
        cleanup_commitment: str,
    ) -> None:
        self._require_role("runner")
        self._require_run_key(run_key)
        self._require_commitment(cleanup_commitment, "cleanup commitment")
        with self._serializable_operation():
            self._connection.execute(
                "SELECT mkso_i06.commit_cleanup(%s, %s, %s, %s)",
                (
                    run_key.qualification_claim_id,
                    run_key.toolchain_execution_profile_hash,
                    run_key.context_manifest_hash,
                    cleanup_commitment,
                ),
            ).fetchone()

    def commit_terminal(self, result_document: bytes) -> bytes:
        self._require_role("runner")
        with self._serializable_operation():
            result = load_toolchain_qualification_result(result_document)
            signed_document_hash = "sha256:" + hashlib.sha256(result.document).hexdigest()
            row = self._connection.execute(
                """
                SELECT mkso_i06.commit_terminal_result(%s, %s, %s, %s, %s, %s)
                """,
                (
                    result.document,
                    result.result_hash,
                    signed_document_hash,
                    result.run_key.qualification_claim_id,
                    result.run_key.toolchain_execution_profile_hash,
                    result.run_key.context_manifest_hash,
                ),
            ).fetchone()
            if row is None or len(row) != 1 or not isinstance(row[0], bytes):
                raise QualificationStoreError("terminal commitment returned invalid bytes")
            if row[0] != result.document:
                raise QualificationStoreError(
                    "terminal commitment returned different retained bytes"
                )
            return row[0]

    def terminal_for(self, run_key: ToolchainRunKey) -> bytes | None:
        self._require_role("broker", "private_human")
        self._require_run_key(run_key)
        with self._serializable_operation():
            row = self._connection.execute(
                "SELECT mkso_i06.read_toolchain_terminal(%s, %s, %s)",
                (
                    run_key.qualification_claim_id,
                    run_key.toolchain_execution_profile_hash,
                    run_key.context_manifest_hash,
                ),
            ).fetchone()
            if row is None or len(row) != 1:
                raise QualificationStoreError("terminal lookup returned an invalid result")
            if row[0] is None:
                return None
            if not isinstance(row[0], bytes) or not row[0]:
                raise QualificationStoreError("terminal lookup returned invalid bytes")
            return row[0]
