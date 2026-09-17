"""Fail-closed container-image closure validation.

This module validates the content-addressed image graph selected by the frozen
Docker design.  Its compact JSON self-hash is bootstrap-only until mkso's
separately approved RFC 8785 component is admitted.  The accepted record domain
is deliberately restricted to ASCII strings, integers, booleans, null, arrays,
and objects, for which the emitted bytes match the required JCS representation.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from mkso.hashing import (
    BootstrapCanonicalizationError,
    restricted_record_hash,
    sha256_digest,
)

OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_INDEX = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFERENCE = re.compile(
    r"^(?P<repository>"
    r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::(?P<port>[0-9]{1,5}))?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+"
    r")@(?P<digest>sha256:[0-9a-f]{64})$"
)


class ContainerImageClosureError(ValueError):
    """Raised when an image record or retained blob closure is not exact."""


@dataclass(frozen=True, slots=True)
class ContainerDescriptor:
    media_type: str
    digest: str
    size: int


@dataclass(frozen=True, slots=True)
class ContainerImageClosure:
    canonical_reference: str
    platform_os: str
    platform_architecture: str
    manifest: ContainerDescriptor
    config: ContainerDescriptor
    layers: tuple[ContainerDescriptor, ...]
    artifact_set_hash: str
    closure_hash: str


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContainerImageClosureError(message)


def _sha256(value: bytes) -> str:
    return sha256_digest(value)


def derive_bootstrap_closure_hash(record: Mapping[str, Any]) -> str:
    """Derive the review-only self-hash, excluding only its own value."""

    try:
        return restricted_record_hash(record, omitted_fields={"closure_hash"})
    except BootstrapCanonicalizationError as exc:
        raise ContainerImageClosureError(str(exc)) from exc


def _descriptor(value: object, label: str) -> ContainerDescriptor:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(
        set(value) == {"media_type", "digest", "size"},
        f"{label} descriptor fields are not exact",
    )
    media_type = value["media_type"]
    digest = value["digest"]
    size = value["size"]
    _require(isinstance(media_type, str) and media_type, f"{label} media type is invalid")
    _require(
        isinstance(digest, str) and _HASH.fullmatch(digest) is not None,
        f"{label} digest is invalid",
    )
    _require(
        isinstance(size, int) and not isinstance(size, bool) and size > 0,
        f"{label} size is invalid",
    )
    return ContainerDescriptor(media_type=media_type, digest=digest, size=size)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContainerImageClosureError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> object:
    raise ContainerImageClosureError(f"non-JSON numeric constant {value!r}")


def _json_object(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_non_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerImageClosureError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    _require(isinstance(value, dict), f"{label} must contain one JSON object")
    return value


def _manifest_descriptor(value: object, label: str) -> ContainerDescriptor:
    _require(isinstance(value, dict), f"{label} must be an object")
    _require(
        set(value) == {"mediaType", "digest", "size"},
        f"{label} manifest descriptor fields are not exact",
    )
    return _descriptor(
        {
            "media_type": value["mediaType"],
            "digest": value["digest"],
            "size": value["size"],
        },
        label,
    )


def _verify_blob(descriptor: ContainerDescriptor, blob: bytes, label: str) -> None:
    _require(len(blob) == descriptor.size, f"{label} blob size mismatch")
    _require(_sha256(blob) == descriptor.digest, f"{label} blob digest mismatch")


def _uncompressed_layer_digest(media_type: str, blob: bytes) -> str:
    if media_type in {OCI_LAYER, DOCKER_LAYER}:
        return _sha256(blob)
    _require(
        media_type in {OCI_LAYER_GZIP, DOCKER_LAYER_GZIP},
        f"unsupported V1 layer media type {media_type!r}",
    )
    digest = hashlib.sha256()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob), mode="rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except (EOFError, OSError) as exc:
        raise ContainerImageClosureError(f"invalid gzip image layer: {exc}") from exc
    return f"sha256:{digest.hexdigest()}"


def _validate_record_shape(record: Mapping[str, Any]) -> None:
    required = {
        "schema_version",
        "canonical_reference",
        "platform",
        "manifest",
        "config",
        "layers",
        "source_index_manifest",
        "artifact_set_hash",
        "build_profile_hash",
        "closure_hash",
    }
    _require(set(record) == required, "container image record fields are not exact")
    _require(record["schema_version"] == "mkso-container-image-closure/1", "wrong schema version")
    platform = record["platform"]
    _require(isinstance(platform, dict), "platform must be an object")
    _require(set(platform) == {"os", "architecture"}, "platform fields are not exact")
    _require(platform == {"os": "linux", "architecture": "amd64"}, "unsupported V1 platform")
    for field in ("artifact_set_hash", "build_profile_hash", "closure_hash"):
        value = record[field]
        _require(isinstance(value, str) and _HASH.fullmatch(value) is not None, f"invalid {field}")


def validate_container_image_closure(
    record: Mapping[str, Any], blobs: Mapping[str, bytes]
) -> ContainerImageClosure:
    """Validate one exact selected-platform image and its retained raw blobs."""

    _validate_record_shape(record)
    canonical_reference = record["canonical_reference"]
    _require(isinstance(canonical_reference, str), "canonical reference must be a string")
    reference_match = _REFERENCE.fullmatch(canonical_reference)
    _require(reference_match is not None, "image reference is not repository@sha256")
    port = reference_match.group("port")
    if port is not None:
        _require(
            str(int(port)) == port and 1 <= int(port) <= 65535,
            "registry port is not canonical or in range",
        )

    manifest = _descriptor(record["manifest"], "manifest")
    config = _descriptor(record["config"], "config")
    layer_values = record["layers"]
    _require(isinstance(layer_values, list) and layer_values, "layer list is empty or invalid")
    layers = tuple(
        _descriptor(value, f"layers[{index}]") for index, value in enumerate(layer_values)
    )
    source_value = record["source_index_manifest"]
    source_index = None if source_value is None else _descriptor(source_value, "source index")

    _require(
        reference_match.group("digest") == manifest.digest,
        "reference digest is not the manifest digest",
    )
    _require(
        manifest.media_type in {OCI_MANIFEST, DOCKER_MANIFEST}, "unsupported manifest media type"
    )
    if manifest.media_type == OCI_MANIFEST:
        _require(config.media_type == OCI_CONFIG, "OCI manifest has a non-OCI config")
        layer_media_types = {OCI_LAYER, OCI_LAYER_GZIP}
    else:
        _require(config.media_type == DOCKER_CONFIG, "Docker manifest has a non-Docker config")
        layer_media_types = {DOCKER_LAYER, DOCKER_LAYER_GZIP}
    _require(
        all(layer.media_type in layer_media_types for layer in layers),
        "layer media-type family mismatch",
    )
    if source_index is not None:
        _require(
            source_index.media_type in {OCI_INDEX, DOCKER_INDEX}, "invalid source index media type"
        )
        _require(
            source_index.digest != manifest.digest, "source index cannot equal selected manifest"
        )

    expected_blob_digests = {manifest.digest, config.digest, *(layer.digest for layer in layers)}
    _require(set(blobs) == expected_blob_digests, "retained image blob set is not exact")
    for digest, raw in blobs.items():
        _require(_HASH.fullmatch(digest) is not None, "retained blob key is not a SHA-256 digest")
        _require(isinstance(raw, bytes), f"retained blob {digest} is not bytes")

    _verify_blob(manifest, blobs[manifest.digest], "manifest")
    _verify_blob(config, blobs[config.digest], "config")
    for index, layer in enumerate(layers):
        _verify_blob(layer, blobs[layer.digest], f"layer {index}")

    manifest_value = _json_object(blobs[manifest.digest], "image manifest")
    _require(
        set(manifest_value) == {"schemaVersion", "mediaType", "config", "layers"},
        "image manifest fields are not exact",
    )
    _require(manifest_value["schemaVersion"] == 2, "image manifest schemaVersion is not 2")
    _require(
        manifest_value["mediaType"] == manifest.media_type,
        "manifest media type differs from its record",
    )
    _require(
        _manifest_descriptor(manifest_value["config"], "manifest config") == config,
        "manifest config descriptor mismatch",
    )
    raw_layers = manifest_value["layers"]
    _require(isinstance(raw_layers, list), "manifest layers must be an array")
    manifest_layers = tuple(
        _manifest_descriptor(value, f"manifest layers[{index}]")
        for index, value in enumerate(raw_layers)
    )
    _require(manifest_layers == layers, "manifest layer descriptors differ in value or order")

    config_value = _json_object(blobs[config.digest], "image config")
    _require(config_value.get("os") == "linux", "image config OS is not linux")
    _require(config_value.get("architecture") == "amd64", "image config architecture is not amd64")
    rootfs = config_value.get("rootfs")
    _require(isinstance(rootfs, dict), "image config rootfs is missing")
    _require(set(rootfs) == {"type", "diff_ids"}, "image config rootfs fields are not exact")
    _require(rootfs["type"] == "layers", "image config rootfs type is not layers")
    diff_ids = rootfs["diff_ids"]
    _require(isinstance(diff_ids, list), "image config diff_ids must be an array")
    _require(
        all(isinstance(value, str) and _HASH.fullmatch(value) is not None for value in diff_ids),
        "image config contains an invalid diff_id",
    )
    observed_diff_ids = [
        _uncompressed_layer_digest(layer.media_type, blobs[layer.digest]) for layer in layers
    ]
    _require(diff_ids == observed_diff_ids, "image config diff_ids do not match ordered layers")

    closure_hash = derive_bootstrap_closure_hash(record)
    _require(record["closure_hash"] == closure_hash, "container image closure self-hash mismatch")
    platform = record["platform"]
    return ContainerImageClosure(
        canonical_reference=canonical_reference,
        platform_os=platform["os"],
        platform_architecture=platform["architecture"],
        manifest=manifest,
        config=config,
        layers=layers,
        artifact_set_hash=record["artifact_set_hash"],
        closure_hash=closure_hash,
    )
