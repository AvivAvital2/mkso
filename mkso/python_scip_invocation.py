"""Fail-closed static joins for the V1 Python SCIP Docker invocation.

This module validates a freeze-selected invocation record and derives its
regular-file manifest views from retained raw D-115 records. Its caller must
still authenticate the source-record signature and freeze inputs. This module
does not create a Docker request, inspect a container, observe a process, or
grant SCIP evidence authority.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from mkso.docker_profile import (
    DockerExecutionProfile,
    DockerMount,
    DockerProfileError,
    validate_docker_execution_profile,
)
from mkso.hashing import BootstrapCanonicalizationError, restricted_record_hash
from mkso.mounted_inputs import (
    DerivedInputManifest,
    DerivedRegularFile,
    MountedInputError,
    derive_bootstrap_mounted_inputs,
)

PYTHON_SCIP_CONFIG_PATH = "/workspace/scip-pyrightconfig.json"
PYTHON_SCIP_CONFIG_RELATIVE_PATH = "scip-pyrightconfig.json"
PYTHON_SCIP_SOURCE_ROOT = "/workspace"

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUIRED_OPTIONS = (
    "--cwd",
    "--output",
    "--environment",
    "--project-name",
    "--project-version",
)


class PythonScipInvocationError(ValueError):
    """Raised when an invocation record does not rederive from sealed inputs."""


@dataclass(frozen=True, slots=True)
class PythonScipInputBinding:
    container_path: str
    mount_role: str
    mount_container_path: str
    mount_manifest_hash: str
    relative_path: str
    size: int
    content_hash: str
    argument_index: int | None


@dataclass(frozen=True, slots=True)
class PythonScipInvocation:
    docker_profile_hash: str
    project_name: str
    project_version: str
    arguments: tuple[str, ...]
    config_input: PythonScipInputBinding
    environment_input: PythonScipInputBinding
    expected_documents: tuple[str, ...]
    invocation_hash: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PythonScipInvocationError(message)


def _hash(value: object, label: str) -> str:
    _require(
        isinstance(value, str) and _HASH.fullmatch(value) is not None,
        f"{label} is not a lowercase SHA-256 digest",
    )
    return value


def _text(value: object, label: str) -> str:
    _require(isinstance(value, str) and bool(value), f"{label} must be non-empty text")
    _require("\x00" not in value, f"{label} contains NUL")
    return value


def _relative_path(value: object, label: str) -> str:
    path = _text(value, label)
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


def _container_path(value: object, label: str) -> str:
    path = _text(value, label)
    _require(path.isascii(), f"{label} must be ASCII")
    _require(path.startswith("/") and path != "/", f"{label} must be absolute and non-root")
    _require("\\" not in path, f"{label} contains a backslash")
    _require("//" not in path, f"{label} contains an empty segment")
    _require(
        all(segment not in {".", ".."} for segment in path.split("/")),
        f"{label} contains a dot segment",
    )
    _require(PurePosixPath(path).as_posix() == path, f"{label} is not normalized POSIX")
    return path


def _is_strictly_beneath(path: str, root: str) -> bool:
    return PurePosixPath(root) in PurePosixPath(path).parents


def _manifest_index(
    manifests: Sequence[DerivedInputManifest],
) -> dict[str, dict[str, DerivedRegularFile]]:
    result: dict[str, dict[str, DerivedRegularFile]] = {}
    for manifest_index, manifest in enumerate(manifests):
        _require(
            isinstance(manifest, DerivedInputManifest),
            f"manifests[{manifest_index}] is not a raw-record-derived manifest view",
        )
        manifest_hash = _hash(manifest.manifest_hash, f"manifests[{manifest_index}].manifest_hash")
        for file_index, file in enumerate(manifest.files):
            _require(
                isinstance(file, DerivedRegularFile),
                f"manifest {manifest_hash} files[{file_index}] is not a regular-file view",
            )
        _require(manifest_hash not in result, "duplicate sealed input manifest hash")
        paths = [file.relative_path for file in manifest.files]
        _require(paths, f"manifest {manifest_hash} has no regular files")
        _require(
            paths == sorted(paths, key=lambda item: item.encode("utf-8")),
            f"manifest {manifest_hash} files are not in UTF-8 path order",
        )
        _require(len(paths) == len(set(paths)), f"manifest {manifest_hash} has duplicate paths")
        files: dict[str, DerivedRegularFile] = {}
        for file_index, file in enumerate(manifest.files):
            path = _relative_path(
                file.relative_path, f"manifest {manifest_hash} files[{file_index}].relative_path"
            )
            _require(
                isinstance(file.size, int) and not isinstance(file.size, bool) and file.size >= 0,
                f"manifest {manifest_hash} file {path} has invalid size",
            )
            _hash(file.content_hash, f"manifest {manifest_hash} file {path} content_hash")
            files[path] = file
        result[manifest_hash] = files
    return result


def _binding(value: object, label: str) -> PythonScipInputBinding:
    _require(isinstance(value, dict), f"{label} must be an object")
    fields = {
        "container_path",
        "mount_role",
        "mount_container_path",
        "mount_manifest_hash",
        "relative_path",
        "size",
        "content_hash",
        "argument_index",
    }
    _require(set(value) == fields, f"{label} fields are not exact")
    role = value["mount_role"]
    _require(role in {"source", "dependency"}, f"{label}.mount_role is invalid")
    size = value["size"]
    _require(
        isinstance(size, int) and not isinstance(size, bool) and size >= 0,
        f"{label}.size is invalid",
    )
    argument_index = value["argument_index"]
    _require(
        argument_index is None
        or (
            isinstance(argument_index, int)
            and not isinstance(argument_index, bool)
            and argument_index >= 0
        ),
        f"{label}.argument_index is invalid",
    )
    return PythonScipInputBinding(
        container_path=_container_path(value["container_path"], f"{label}.container_path"),
        mount_role=role,
        mount_container_path=_container_path(
            value["mount_container_path"], f"{label}.mount_container_path"
        ),
        mount_manifest_hash=_hash(value["mount_manifest_hash"], f"{label}.mount_manifest_hash"),
        relative_path=_relative_path(value["relative_path"], f"{label}.relative_path"),
        size=size,
        content_hash=_hash(value["content_hash"], f"{label}.content_hash"),
        argument_index=argument_index,
    )


def _mount_index(profile: DockerExecutionProfile) -> dict[tuple[str, str], DockerMount]:
    result: dict[tuple[str, str], DockerMount] = {}
    for index, mount in enumerate(profile.mounts):
        _require(isinstance(mount, DockerMount), f"Docker mount[{index}] is not a typed mount")
        key = (mount.role, mount.container_path)
        _require(key not in result, "Docker profile has duplicate role/path mounts")
        result[key] = mount
    return result


def _revalidate_docker_profile(profile: DockerExecutionProfile) -> DockerExecutionProfile:
    """Rederive a typed profile so its constructor is not an authority boundary."""

    _require(
        isinstance(profile, DockerExecutionProfile),
        "Docker profile is not a typed view",
    )
    _require(isinstance(profile.mounts, tuple), "Docker profile mounts are not a tuple")
    for index, mount in enumerate(profile.mounts):
        _require(isinstance(mount, DockerMount), f"Docker mount[{index}] is not a typed mount")
    record = {
        "schema_version": "mkso-docker-execution-profile/1",
        "adapter_qualification_hash": profile.adapter_qualification_hash,
        "host_profile_hash": profile.host_profile_hash,
        "image_closure_hash": profile.image_closure_hash,
        "entrypoint": list(profile.entrypoint),
        "environment": [list(pair) for pair in profile.environment],
        "container_hostname": profile.container_hostname,
        "tty": profile.tty,
        "mounts": [
            {
                "role": mount.role,
                "container_path": mount.container_path,
                "access": mount.access,
                "source_manifest_hash": mount.source_manifest_hash,
                "options": list(mount.options),
                "size_bytes": mount.size_bytes,
            }
            for mount in profile.mounts
        ],
        "network_mode": profile.network_mode,
        "security_profile_hash": profile.security_profile_hash,
        "resource_profile_hash": profile.resource_profile_hash,
        "timeout_milliseconds": profile.timeout_milliseconds,
        "profile_hash": profile.profile_hash,
    }
    try:
        observed = validate_docker_execution_profile(record)
    except (DockerProfileError, TypeError) as exc:
        raise PythonScipInvocationError(f"Docker profile revalidation failed: {exc}") from exc
    _require(observed == profile, "Docker profile typed view does not equal its rederivation")
    return observed


def _join_binding(
    binding: PythonScipInputBinding,
    *,
    label: str,
    mounts: Mapping[tuple[str, str], DockerMount],
    manifests: Mapping[str, Mapping[str, DerivedRegularFile]],
) -> None:
    key = (binding.mount_role, binding.mount_container_path)
    _require(key in mounts, f"{label} owning mount is absent from Docker profile")
    mount = mounts[key]
    _require(mount.access == "read_only", f"{label} owning mount is writable")
    _require(
        mount.source_manifest_hash == binding.mount_manifest_hash,
        f"{label} manifest hash differs from Docker mount",
    )
    _require(
        _is_strictly_beneath(binding.container_path, binding.mount_container_path),
        f"{label} is not strictly beneath its owning mount",
    )
    expected_container_path = f"{binding.mount_container_path}/{binding.relative_path}"
    _require(
        binding.container_path == expected_container_path,
        f"{label} container and relative paths disagree",
    )
    _require(
        binding.mount_manifest_hash in manifests,
        f"{label} retained manifest view is absent",
    )
    files = manifests[binding.mount_manifest_hash]
    _require(binding.relative_path in files, f"{label} file is absent from its manifest")
    file = files[binding.relative_path]
    _require(file.size == binding.size, f"{label} size differs from manifest")
    _require(file.content_hash == binding.content_hash, f"{label} hash differs from manifest")


def derive_bootstrap_invocation_hash(record: Mapping[str, Any]) -> str:
    """Derive the review-only record self-hash over the audited JSON subset."""

    try:
        return restricted_record_hash(record, omitted_fields={"invocation_hash"})
    except BootstrapCanonicalizationError as exc:
        raise PythonScipInvocationError(str(exc)) from exc


def _option_value(arguments: tuple[str, ...], option: str) -> tuple[int, str]:
    _require(
        not any(value.startswith(f"{option}=") for value in arguments),
        f"{option} equals-form bypass is forbidden",
    )
    indexes = [index for index, value in enumerate(arguments) if value == option]
    _require(len(indexes) == 1, f"{option} must occur exactly once")
    option_index = indexes[0]
    _require(option_index + 1 < len(arguments), f"{option} has no following value token")
    return option_index + 1, arguments[option_index + 1]


def validate_python_scip_invocation(
    record: Mapping[str, Any],
    *,
    docker_profile: DockerExecutionProfile,
    source_record_bytes: bytes,
    dependency_root_record_bytes: Sequence[bytes],
    selected_project_name: str,
    selected_project_version: str,
    frozen_arguments: Sequence[str],
    frozen_expected_documents: Sequence[str],
) -> PythonScipInvocation:
    """Validate one static D-114 invocation through raw D-115 input records."""

    _require(isinstance(record, Mapping), "Python SCIP invocation must be a mapping")
    docker_profile = _revalidate_docker_profile(docker_profile)
    fields = {
        "schema_version",
        "docker_profile_hash",
        "project_name",
        "project_version",
        "arguments",
        "config_input",
        "environment_input",
        "expected_documents",
        "invocation_hash",
    }
    _require(set(record) == fields, "Python SCIP invocation fields are not exact")
    _require(
        record["schema_version"] == "mkso-python-scip-invocation/1",
        "wrong Python SCIP invocation schema version",
    )
    invocation_hash = derive_bootstrap_invocation_hash(record)
    _require(record["invocation_hash"] == invocation_hash, "invocation self-hash mismatch")
    profile_hash = _hash(record["docker_profile_hash"], "docker_profile_hash")
    _require(profile_hash == docker_profile.profile_hash, "Docker profile hash join failed")
    project_name = _text(record["project_name"], "project_name")
    project_version = _text(record["project_version"], "project_version")
    _require(
        project_name == _text(selected_project_name, "selected_project_name"),
        "project name differs from the selected contract/profile identity",
    )
    _require(
        project_version == _text(selected_project_version, "selected_project_version"),
        "project version differs from the selected contract/profile identity",
    )

    arguments_value = record["arguments"]
    _require(isinstance(arguments_value, list), "arguments must be an array")
    arguments = tuple(
        _text(value, f"arguments[{index}]") for index, value in enumerate(arguments_value)
    )
    _require(
        isinstance(frozen_arguments, Sequence)
        and not isinstance(frozen_arguments, (str, bytes, bytearray)),
        "frozen_arguments must be a sequence of tokens",
    )
    frozen_argument_vector = tuple(
        _text(value, f"frozen_arguments[{index}]") for index, value in enumerate(frozen_arguments)
    )
    _require(
        arguments == frozen_argument_vector,
        "invocation arguments differ from the freeze-selected vector",
    )
    _require(arguments and arguments[0] == "index", "first argument must be the index command")

    config = _binding(record["config_input"], "config_input")
    environment = _binding(record["environment_input"], "environment_input")
    _require(
        config
        == PythonScipInputBinding(
            container_path=PYTHON_SCIP_CONFIG_PATH,
            mount_role="source",
            mount_container_path=PYTHON_SCIP_SOURCE_ROOT,
            mount_manifest_hash=config.mount_manifest_hash,
            relative_path=PYTHON_SCIP_CONFIG_RELATIVE_PATH,
            size=config.size,
            content_hash=config.content_hash,
            argument_index=None,
        ),
        "config input is not the exact D-114 source binding",
    )
    _require(environment.argument_index is not None, "environment input has no argument index")

    mounts = _mount_index(docker_profile)
    source_key = ("source", PYTHON_SCIP_SOURCE_ROOT)
    _require(source_key in mounts, "Docker source mount is not /workspace")
    try:
        mounted_inputs = derive_bootstrap_mounted_inputs(
            source_record_bytes,
            dependency_root_record_bytes,
        )
    except MountedInputError as exc:
        raise PythonScipInvocationError(f"mounted-input derivation failed: {exc}") from exc
    manifest_index = _manifest_index(mounted_inputs.manifests)
    mounted_input_hashes = {
        mount.source_manifest_hash
        for mount in docker_profile.mounts
        if mount.role in {"source", "dependency"}
    }
    _require(
        None not in mounted_input_hashes and set(manifest_index) == mounted_input_hashes,
        "raw-record-derived manifest views differ from Docker input mounts",
    )
    _require(
        mounts[source_key].source_manifest_hash == mounted_inputs.source.manifest_hash,
        "source mount does not resolve to the retained source record",
    )
    dependency_mount_hashes = tuple(
        mount.source_manifest_hash for mount in docker_profile.mounts if mount.role == "dependency"
    )
    _require(
        dependency_mount_hashes
        == tuple(manifest.manifest_hash for manifest in mounted_inputs.dependencies),
        "dependency mounts differ from the signed ordered root set",
    )
    _join_binding(config, label="config input", mounts=mounts, manifests=manifest_index)
    _join_binding(environment, label="environment input", mounts=mounts, manifests=manifest_index)

    cwd_index, cwd = _option_value(arguments, "--cwd")
    _require(cwd == PYTHON_SCIP_SOURCE_ROOT, "--cwd does not select /workspace")
    output_mounts = [mount for mount in docker_profile.mounts if mount.role == "output"]
    _require(len(output_mounts) == 1, "Docker profile does not have one output mount")
    output_index, output = _option_value(arguments, "--output")
    _require(output == output_mounts[0].container_path, "--output differs from output mount")
    environment_index, environment_path = _option_value(arguments, "--environment")
    _require(
        environment_index == environment.argument_index,
        "environment argument index differs from input binding",
    )
    _require(
        environment_path == environment.container_path,
        "--environment differs from input binding",
    )
    name_index, name = _option_value(arguments, "--project-name")
    _require(name == project_name, "--project-name differs from frozen identity")
    version_index, version = _option_value(arguments, "--project-version")
    _require(version == project_version, "--project-version differs from frozen identity")
    bound_indexes = {
        cwd_index,
        output_index,
        environment_index,
        name_index,
        version_index,
    }
    _require(len(bound_indexes) == len(_REQUIRED_OPTIONS), "required option values overlap")

    documents_value = record["expected_documents"]
    _require(isinstance(documents_value, list), "expected_documents must be an array")
    documents = tuple(
        _relative_path(value, f"expected_documents[{index}]")
        for index, value in enumerate(documents_value)
    )
    _require(documents, "expected document set is empty")
    _require(
        documents == tuple(sorted(documents, key=lambda item: item.encode("utf-8"))),
        "expected documents are not in UTF-8 path order",
    )
    _require(len(documents) == len(set(documents)), "expected documents contain duplicates")
    _require(
        isinstance(frozen_expected_documents, Sequence)
        and not isinstance(frozen_expected_documents, (str, bytes, bytearray)),
        "frozen_expected_documents must be a sequence of paths",
    )
    frozen_documents = tuple(
        _relative_path(value, f"frozen_expected_documents[{index}]")
        for index, value in enumerate(frozen_expected_documents)
    )
    _require(frozen_documents, "frozen expected document set is empty")
    _require(
        frozen_documents == tuple(sorted(frozen_documents, key=lambda item: item.encode("utf-8"))),
        "frozen expected documents are not in UTF-8 path order",
    )
    _require(
        len(frozen_documents) == len(set(frozen_documents)),
        "frozen expected documents contain duplicates",
    )
    _require(
        documents == frozen_documents,
        "invocation documents differ from the frozen contract/profile set",
    )
    source_manifest_hash = mounts[source_key].source_manifest_hash
    _require(
        source_manifest_hash is not None and source_manifest_hash in manifest_index,
        "raw-record-derived source manifest view is absent",
    )
    source_files = manifest_index[source_manifest_hash]
    _require(
        set(documents) <= set(source_files),
        "expected document is absent from the sealed source manifest",
    )

    return PythonScipInvocation(
        docker_profile_hash=profile_hash,
        project_name=project_name,
        project_version=project_version,
        arguments=arguments,
        config_input=config,
        environment_input=environment,
        expected_documents=documents,
        invocation_hash=invocation_hash,
    )
