"""Fail-closed public-bootstrap validation for static Docker profiles.

These records describe logical mounts and an exact Docker execution request.
Validation does not grant authority: the profile must later be an exact member
of the verified human-signed framework freeze and bind qualified image, host,
security, resource, and adapter profiles.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from mkso.hashing import BootstrapCanonicalizationError, restricted_record_hash
from mkso.python_scip_environment import (
    PYTHON_SCIP_ENTRYPOINT,
    PYTHON_SCIP_HOSTNAME,
    PythonScipEnvironmentError,
    validate_environment_pairs,
)

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


class DockerProfileError(ValueError):
    """Raised when a static Docker profile is ambiguous or unsafe by shape."""


@dataclass(frozen=True, slots=True)
class DockerMount:
    role: str
    container_path: str
    access: str
    source_manifest_hash: str | None
    options: tuple[str, ...]
    size_bytes: int | None


@dataclass(frozen=True, slots=True)
class DockerExecutionProfile:
    adapter_qualification_hash: str
    host_profile_hash: str
    image_closure_hash: str
    entrypoint: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    container_hostname: str
    tty: bool
    mounts: tuple[DockerMount, ...]
    network_mode: str
    security_profile_hash: str
    resource_profile_hash: str
    timeout_milliseconds: int
    profile_hash: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DockerProfileError(message)


def _hash(value: object, label: str, *, nullable: bool = False) -> str | None:
    if value is None:
        _require(nullable, f"{label} cannot be null")
        return None
    _require(
        isinstance(value, str) and _HASH.fullmatch(value) is not None,
        f"{label} is not a lowercase SHA-256 digest",
    )
    return value


def _required_hash(value: object, label: str) -> str:
    result = _hash(value, label)
    _require(result is not None, f"{label} cannot be null")
    return result


def _ascii(value: object, label: str, *, empty_allowed: bool = False) -> str:
    _require(isinstance(value, str), f"{label} must be a string")
    _require(value.isascii(), f"{label} must be ASCII in the bootstrap profile")
    _require("\x00" not in value, f"{label} contains NUL")
    _require(empty_allowed or bool(value), f"{label} cannot be empty")
    return value


def _container_path(value: object, label: str) -> str:
    path = _ascii(value, label)
    _require(path.startswith("/"), f"{label} must be absolute")
    _require(path != "/", f"{label} cannot be the container root")
    _require("//" not in path, f"{label} contains an empty path segment")
    _require(
        all(segment not in {".", ".."} for segment in path.split("/")),
        f"{label} contains a dot path segment",
    )
    _require(PurePosixPath(path).as_posix() == path, f"{label} is not normalized POSIX")
    return path


def derive_bootstrap_profile_hash(record: Mapping[str, Any]) -> str:
    """Derive the review-only self-hash, excluding only its own value."""

    try:
        return restricted_record_hash(record, omitted_fields={"profile_hash"})
    except BootstrapCanonicalizationError as exc:
        raise DockerProfileError(str(exc)) from exc


def _mount(value: object, index: int) -> DockerMount:
    label = f"mounts[{index}]"
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(
        set(value)
        == {"role", "container_path", "access", "source_manifest_hash", "options", "size_bytes"},
        f"{label} fields are not exact",
    )
    role = value["role"]
    _require(
        isinstance(role, str) and role in {"source", "dependency", "output", "tmpfs"},
        f"{label} role is invalid",
    )
    path = _container_path(value["container_path"], f"{label}.container_path")
    access = value["access"]
    _require(
        isinstance(access, str) and access in {"read_only", "read_write"},
        f"{label} access is invalid",
    )
    source_hash = _hash(
        value["source_manifest_hash"],
        f"{label}.source_manifest_hash",
        nullable=True,
    )
    options = value["options"]
    _require(isinstance(options, list), f"{label}.options must be an array")
    _require(not options, f"{label}.options must be empty in the V1 bootstrap profile")
    size = value["size_bytes"]
    _require(
        size is None or (isinstance(size, int) and not isinstance(size, bool) and size > 0),
        f"{label}.size_bytes is invalid",
    )

    if role in {"source", "dependency"}:
        _require(access == "read_only", f"{label} input mount is not read-only")
        _require(source_hash is not None, f"{label} input manifest is missing")
        _require(size is None, f"{label} input mount has an ambient size override")
    elif role == "output":
        _require(access == "read_write", f"{label} output mount is not writable")
        _require(source_hash is None, f"{label} output has a caller-supplied source")
        _require(size is None, f"{label} output size belongs to the resource profile")
    else:
        _require(access == "read_write", f"{label} tmpfs is not writable")
        _require(source_hash is None, f"{label} tmpfs has a caller-supplied source")
        _require(size is not None, f"{label} tmpfs has no exact size")

    return DockerMount(
        role=role,
        container_path=path,
        access=access,
        source_manifest_hash=source_hash,
        options=(),
        size_bytes=size,
    )


def validate_docker_execution_profile(record: Mapping[str, Any]) -> DockerExecutionProfile:
    """Validate one exact static Docker profile without granting authority."""

    required = {
        "schema_version",
        "adapter_qualification_hash",
        "host_profile_hash",
        "image_closure_hash",
        "entrypoint",
        "environment",
        "container_hostname",
        "tty",
        "mounts",
        "network_mode",
        "security_profile_hash",
        "resource_profile_hash",
        "timeout_milliseconds",
        "profile_hash",
    }
    _require(set(record) == required, "Docker execution profile fields are not exact")
    _require(
        record["schema_version"] == "mkso-docker-execution-profile/1",
        "wrong Docker execution profile schema version",
    )

    adapter_hash = _required_hash(
        record["adapter_qualification_hash"], "adapter qualification hash"
    )
    host_hash = _required_hash(record["host_profile_hash"], "host profile hash")
    image_hash = _required_hash(record["image_closure_hash"], "image closure hash")
    security_hash = _required_hash(record["security_profile_hash"], "security profile hash")
    resource_hash = _required_hash(record["resource_profile_hash"], "resource profile hash")

    entrypoint_value = record["entrypoint"]
    _require(
        entrypoint_value == list(PYTHON_SCIP_ENTRYPOINT),
        "entrypoint is not the exact Python SCIP entrypoint",
    )
    entrypoint = PYTHON_SCIP_ENTRYPOINT

    try:
        environment = validate_environment_pairs(record["environment"], "profile environment")
    except PythonScipEnvironmentError as exc:
        raise DockerProfileError(str(exc)) from exc

    hostname = record["container_hostname"]
    _require(hostname == PYTHON_SCIP_HOSTNAME, "container hostname is not the D-113 hostname")
    _require(record["tty"] is False, "Docker profile must not allocate a TTY")

    mount_values = record["mounts"]
    _require(isinstance(mount_values, list), "mounts must be an array")
    mounts = tuple(_mount(value, index) for index, value in enumerate(mount_values))
    roles = Counter(mount.role for mount in mounts)
    _require(roles["source"] == 1, "profile must contain exactly one source mount")
    _require(roles["output"] == 1, "profile must contain exactly one output mount")
    _require(roles["tmpfs"] == 1, "profile must contain exactly one tmpfs mount")
    paths = [mount.container_path for mount in mounts]
    _require(len(paths) == len(set(paths)), "mount container paths are not unique")
    normalized_paths = [PurePosixPath(path) for path in paths]
    for index, path in enumerate(normalized_paths):
        for other in normalized_paths[index + 1 :]:
            _require(
                path not in other.parents and other not in path.parents,
                "mount container paths overlap",
            )
    entrypoint_path = PurePosixPath(entrypoint[0])
    for path in normalized_paths:
        _require(
            path != entrypoint_path
            and path not in entrypoint_path.parents
            and entrypoint_path not in path.parents,
            "mount container path overlaps the entrypoint",
        )

    _require(record["network_mode"] == "none", "Docker network mode is not none")
    timeout = record["timeout_milliseconds"]
    _require(
        isinstance(timeout, int) and not isinstance(timeout, bool) and timeout > 0,
        "timeout_milliseconds must be a positive integer",
    )

    profile_hash = derive_bootstrap_profile_hash(record)
    _require(record["profile_hash"] == profile_hash, "Docker profile self-hash mismatch")
    return DockerExecutionProfile(
        adapter_qualification_hash=adapter_hash,
        host_profile_hash=host_hash,
        image_closure_hash=image_hash,
        entrypoint=entrypoint,
        environment=environment,
        container_hostname=hostname,
        tty=False,
        mounts=mounts,
        network_mode="none",
        security_profile_hash=security_hash,
        resource_profile_hash=resource_hash,
        timeout_milliseconds=timeout,
        profile_hash=profile_hash,
    )
