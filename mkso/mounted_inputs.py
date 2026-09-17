"""Bootstrap raw-record derivation for mounted SCIP inputs.

This module closes D-115's caller-created-view gap for the restricted public
bootstrap domain. It rederives record hashes and typed entry views from raw
JSON bytes. It validates signature structure but does not verify a signature,
trust policy, filesystem tree, or dependency construction; those remain
separate authority gates.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from mkso.hashing import BootstrapCanonicalizationError, restricted_record_hash

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNER = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,127}$")
_UUID = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})$"
)
_ENTRY_FIELDS = {"path", "entry_type", "mode", "size", "content_hash"}
_SOURCE_SNAPSHOT_FIELDS = {
    "schema_version",
    "snapshot_id",
    "entries",
    "resolved_dependency_manifest_hash",
    "dependency_root_manifest_hashes",
    "created_at",
    "source_snapshot_hash",
    "signature",
}
_CANDIDATE_MANIFEST_FIELDS = {
    "schema_version",
    "candidate_manifest_id",
    "contract_hash",
    "baseline_source_snapshot_hash",
    "edit_submission_hash",
    "authorized_diff_hash",
    "entries",
    "resolved_dependency_manifest_hash",
    "dependency_root_manifest_hashes",
    "candidate_hash",
    "created_at",
    "candidate_manifest_hash",
    "signature",
}
_DEPENDENCY_ROOT_FIELDS = {
    "schema_version",
    "resolved_dependency_manifest_hash",
    "entries",
    "dependency_root_manifest_hash",
}
_SIGNATURE_FIELDS = {"algorithm", "signer", "namespace", "value"}


class MountedInputError(ValueError):
    """Raised when raw mounted-input records cannot be rederived exactly."""


@dataclass(frozen=True, slots=True)
class DerivedRegularFile:
    relative_path: str
    mode: str
    size: int
    content_hash: str


@dataclass(frozen=True, slots=True)
class DerivedInputManifest:
    manifest_hash: str
    resolved_dependency_manifest_hash: str
    files: tuple[DerivedRegularFile, ...]


@dataclass(frozen=True, slots=True)
class DerivedMountedInputs:
    source_record_kind: str
    source: DerivedInputManifest
    dependencies: tuple[DerivedInputManifest, ...]

    @property
    def manifests(self) -> tuple[DerivedInputManifest, ...]:
        return (self.source, *self.dependencies)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MountedInputError(message)


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"raw record has duplicate JSON member {key!r}")
        result[key] = value
    return result


def _raw_record(payload: object, label: str) -> dict[str, Any]:
    _require(type(payload) is bytes, f"{label} must be exact raw bytes")
    try:
        retained_text = payload.decode("utf-8")
        value = json.loads(retained_text, object_pairs_hook=_reject_duplicate_members)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MountedInputError(f"{label} is not unambiguous UTF-8 JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{label} must contain an object")
    return value


def _hash(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and _HASH.fullmatch(value) is not None,
        f"{label} is not a lowercase SHA-256 digest",
    )
    return value


def _uuid(value: object, label: str) -> None:
    _require(
        isinstance(value, str) and _UUID.fullmatch(value) is not None,
        f"{label} is not a schema-valid UUID string",
    )
    try:
        UUID(value)
    except (ValueError, AttributeError) as exc:
        raise MountedInputError(f"{label} is not a UUID") from exc


def _timestamp(value: object, label: str) -> None:
    _require(
        isinstance(value, str) and _RFC3339.fullmatch(value) is not None,
        f"{label} is not an RFC 3339 timestamp string",
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError as exc:
        raise MountedInputError(f"{label} is not an RFC 3339 timestamp") from exc
    _require(parsed.tzinfo is not None, f"{label} has no timezone")


def _relative_path(value: object, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be non-empty text")
    path = value
    _require("\x00" not in path, f"{label} contains NUL")
    _require(path == unicodedata.normalize("NFC", path), f"{label} is not NFC")
    _require(not path.startswith("/"), f"{label} must be relative")
    _require("\\" not in path, f"{label} contains a backslash")
    segments = path.split("/")
    _require(
        all(segment not in {"", ".", ".."} for segment in segments),
        f"{label} contains an unsafe segment",
    )
    _require(PurePosixPath(path).as_posix() == path, f"{label} is not normalized POSIX")
    return path


def _entries(value: object, label: str) -> tuple[DerivedRegularFile, ...]:
    _require(isinstance(value, list) and bool(value), f"{label} must be a non-empty array")
    files: list[DerivedRegularFile] = []
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        _require(isinstance(item, dict), f"{item_label} must be an object")
        _require(set(item) == _ENTRY_FIELDS, f"{item_label} fields are not exact")
        path = _relative_path(item["path"], f"{item_label}.path")
        _require(item["entry_type"] == "regular_file", f"{item_label} is not a regular file")
        _require(item["mode"] in {"0644", "0755"}, f"{item_label}.mode is forbidden")
        size = item["size"]
        _require(
            isinstance(size, int) and not isinstance(size, bool) and size >= 0,
            f"{item_label}.size is invalid",
        )
        files.append(
            DerivedRegularFile(
                relative_path=path,
                mode=item["mode"],
                size=size,
                content_hash=_hash(item["content_hash"], f"{item_label}.content_hash"),
            )
        )
    paths = [item.relative_path for item in files]
    _require(
        paths == sorted(paths, key=lambda item: item.encode("utf-8")),
        f"{label} is not in UTF-8 path order",
    )
    _require(len(paths) == len(set(paths)), f"{label} contains a duplicate path")
    return tuple(files)


def _root_hashes(value: object, label: str) -> tuple[str, ...]:
    _require(isinstance(value, list), f"{label} must be an array")
    hashes = tuple(_hash(item, f"{label}[{index}]") for index, item in enumerate(value))
    _require(hashes == tuple(sorted(hashes)), f"{label} is not in digest order")
    _require(len(hashes) == len(set(hashes)), f"{label} contains a duplicate digest")
    return hashes


def _signature(value: object, namespace: str, label: str) -> None:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(set(value) == _SIGNATURE_FIELDS, f"{label} fields are not exact")
    _require(value["algorithm"] == "openssh-sshsig-v1", f"{label}.algorithm is invalid")
    _require(
        isinstance(value["signer"], str) and _SIGNER.fullmatch(value["signer"]) is not None,
        f"{label}.signer is invalid",
    )
    _require(value["namespace"] == namespace, f"{label}.namespace is invalid")
    _require(isinstance(value["value"], str) and bool(value["value"]), f"{label}.value is empty")


def derive_bootstrap_source_record_hash(record: Mapping[str, Any]) -> str:
    """Rederive a restricted source-snapshot or candidate-manifest self-hash."""

    version = record.get("schema_version")
    if version == "mkso-source-snapshot/1":
        omitted = {"source_snapshot_hash", "signature"}
    elif version == "mkso-candidate-manifest/1":
        omitted = {"candidate_manifest_hash", "signature"}
    else:
        raise MountedInputError("source record has an unsupported schema version")
    try:
        return restricted_record_hash(record, omitted_fields=omitted)
    except BootstrapCanonicalizationError as exc:
        raise MountedInputError(f"source record exceeds the bootstrap JCS subset: {exc}") from exc


def derive_bootstrap_dependency_root_manifest_hash(record: Mapping[str, Any]) -> str:
    """Rederive a restricted dependency-root-manifest self-hash."""

    try:
        return restricted_record_hash(
            record,
            omitted_fields={"dependency_root_manifest_hash"},
        )
    except BootstrapCanonicalizationError as exc:
        raise MountedInputError(
            f"dependency-root record exceeds the bootstrap JCS subset: {exc}"
        ) from exc


def _source_record(record: dict[str, Any]) -> tuple[str, DerivedInputManifest, tuple[str, ...]]:
    version = record.get("schema_version")
    if version == "mkso-source-snapshot/1":
        fields = _SOURCE_SNAPSHOT_FIELDS
        identifier = "snapshot_id"
        self_hash_field = "source_snapshot_hash"
        namespace = "mkso.source-snapshot.v1"
        extra_hash_fields: tuple[str, ...] = ()
        kind = "source_snapshot"
    elif version == "mkso-candidate-manifest/1":
        fields = _CANDIDATE_MANIFEST_FIELDS
        identifier = "candidate_manifest_id"
        self_hash_field = "candidate_manifest_hash"
        namespace = "mkso.candidate-manifest.v1"
        extra_hash_fields = (
            "contract_hash",
            "baseline_source_snapshot_hash",
            "edit_submission_hash",
            "authorized_diff_hash",
            "candidate_hash",
        )
        kind = "candidate_manifest"
    else:
        raise MountedInputError("source record has an unsupported schema version")

    _require(set(record) == fields, "source record fields are not exact")
    for field in extra_hash_fields:
        _hash(record[field], field)
    _uuid(record[identifier], identifier)
    _timestamp(record["created_at"], "created_at")
    dependency_hash = _hash(
        record["resolved_dependency_manifest_hash"],
        "resolved_dependency_manifest_hash",
    )
    roots = _root_hashes(record["dependency_root_manifest_hashes"], "dependency roots")
    files = _entries(record["entries"], "source entries")
    _signature(record["signature"], namespace, "source signature")
    observed_hash = derive_bootstrap_source_record_hash(record)
    _require(record[self_hash_field] == observed_hash, "source record self-hash mismatch")
    return (
        kind,
        DerivedInputManifest(observed_hash, dependency_hash, files),
        roots,
    )


def _dependency_record(record: dict[str, Any]) -> DerivedInputManifest:
    _require(set(record) == _DEPENDENCY_ROOT_FIELDS, "dependency-root fields are not exact")
    _require(
        record.get("schema_version") == "mkso-dependency-root-manifest/1",
        "dependency root has the wrong schema version",
    )
    dependency_hash = _hash(
        record["resolved_dependency_manifest_hash"],
        "dependency root resolved_dependency_manifest_hash",
    )
    files = _entries(record["entries"], "dependency-root entries")
    observed_hash = derive_bootstrap_dependency_root_manifest_hash(record)
    _require(
        record["dependency_root_manifest_hash"] == observed_hash,
        "dependency-root self-hash mismatch",
    )
    return DerivedInputManifest(observed_hash, dependency_hash, files)


def derive_bootstrap_mounted_inputs(
    source_record_bytes: bytes,
    dependency_root_record_bytes: Sequence[bytes],
) -> DerivedMountedInputs:
    """Derive D-115 input views from raw records under an authentication premise.

    The caller must still verify the source-record signature and trust policy in
    the authoritative transaction. This function never treats signature shape
    or a successful self-hash comparison as authentication.
    """

    _require(
        isinstance(dependency_root_record_bytes, Sequence)
        and not isinstance(dependency_root_record_bytes, (str, bytes, bytearray)),
        "dependency-root records must be a sequence of raw byte strings",
    )
    source_raw = _raw_record(source_record_bytes, "source record")
    kind, source, declared_roots = _source_record(source_raw)
    dependencies = tuple(
        _dependency_record(_raw_record(payload, f"dependency-root record[{index}]"))
        for index, payload in enumerate(dependency_root_record_bytes)
    )
    observed_roots = tuple(item.manifest_hash for item in dependencies)
    _require(
        observed_roots == declared_roots,
        "retained dependency-root records differ from the signed source record",
    )
    _require(
        all(
            item.resolved_dependency_manifest_hash == source.resolved_dependency_manifest_hash
            for item in dependencies
        ),
        "dependency root resolved-manifest hash differs from the source record",
    )
    return DerivedMountedInputs(kind, source, dependencies)
