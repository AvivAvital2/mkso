"""Direct, hash-bound decoding of standard SCIP protobuf indexes.

The checked-in review surface is the upstream ``scip.proto`` schema.  mkso
uses a frozen ``protoc`` only to compile that trusted schema into an in-memory
descriptor; candidate ``.scip`` bytes are decoded directly by the pinned
Python Protobuf runtime.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from google.protobuf import __version__ as protobuf_runtime_version
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError, Message

from mkso.hashing import sha256_file

SCIP_SCHEMA_PATH = Path(__file__).parent / "_schema" / "scip.proto"
SCIP_SCHEMA_SHA256 = "04cb20f2b8be73f6c0376b5b3e84c3ae20ebaff0ad3d23ba2d16f866b395ed7d"
SCIP_SCHEMA_RELEASE = "v0.9.0"


@dataclass(frozen=True, slots=True)
class ScipCodecIdentity:
    schema_release: str
    schema_sha256: str
    protoc_path: str
    protoc_sha256: str
    protoc_version: str
    protobuf_runtime_version: str


class ScipCodecError(ValueError):
    """The decoder cannot establish a trusted standard-SCIP interpretation."""


class ScipDecoder:
    """Decode SCIP with an exact schema, schema compiler, and runtime identity."""

    def __init__(
        self,
        *,
        protoc_path: Path,
        expected_protoc_sha256: str,
        expected_protobuf_runtime_version: str,
    ) -> None:
        executable = protoc_path.resolve()
        if not executable.is_file():
            raise ScipCodecError(f"protoc executable does not exist: {executable}")
        actual_protoc_hash = sha256_file(executable)
        if actual_protoc_hash != expected_protoc_sha256:
            raise ScipCodecError(
                "protoc digest mismatch: "
                f"expected {expected_protoc_sha256}, got {actual_protoc_hash}"
            )
        if protobuf_runtime_version != expected_protobuf_runtime_version:
            raise ScipCodecError(
                "Protobuf runtime version mismatch: "
                f"expected {expected_protobuf_runtime_version}, "
                f"got {protobuf_runtime_version}"
            )
        actual_schema_hash = sha256_file(SCIP_SCHEMA_PATH)
        if actual_schema_hash != SCIP_SCHEMA_SHA256:
            raise ScipCodecError(
                f"SCIP schema digest mismatch: expected {SCIP_SCHEMA_SHA256}, "
                f"got {actual_schema_hash}"
            )

        version = self._protoc_version(executable)
        index_class = self._compile_index_class(executable)
        self.identity = ScipCodecIdentity(
            schema_release=SCIP_SCHEMA_RELEASE,
            schema_sha256=actual_schema_hash,
            protoc_path=str(executable),
            protoc_sha256=actual_protoc_hash,
            protoc_version=version,
            protobuf_runtime_version=protobuf_runtime_version,
        )
        self._index_class = index_class

    @staticmethod
    def _protoc_version(executable: Path) -> str:
        try:
            result = subprocess.run(
                [str(executable), "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScipCodecError(f"unable to identify protoc: {exc}") from exc
        version = result.stdout.strip()
        if not version or result.stderr:
            raise ScipCodecError(
                "protoc identity command must emit one non-empty stdout value and no stderr"
            )
        return version

    @staticmethod
    def _compile_index_class(executable: Path) -> type[Message]:
        with tempfile.TemporaryDirectory(prefix="mkso-scip-schema-") as directory:
            descriptor_path = Path(directory) / "scip.desc"
            try:
                result = subprocess.run(
                    [
                        str(executable),
                        f"--proto_path={SCIP_SCHEMA_PATH.parent}",
                        f"--descriptor_set_out={descriptor_path}",
                        SCIP_SCHEMA_PATH.name,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                raise ScipCodecError(f"unable to compile the SCIP schema: {exc}") from exc
            if result.stdout or result.stderr:
                raise ScipCodecError("protoc schema compilation emitted unexpected output")
            try:
                descriptor_bytes = descriptor_path.read_bytes()
            except OSError as exc:
                raise ScipCodecError(f"protoc did not produce a descriptor: {exc}") from exc

        descriptor_set = descriptor_pb2.FileDescriptorSet()
        try:
            descriptor_set.ParseFromString(descriptor_bytes)
        except DecodeError as exc:
            raise ScipCodecError(f"protoc produced an invalid descriptor set: {exc}") from exc
        if [item.name for item in descriptor_set.file] != [SCIP_SCHEMA_PATH.name]:
            raise ScipCodecError("compiled descriptor set does not contain exactly scip.proto")
        pool = descriptor_pool.DescriptorPool()
        try:
            pool.Add(descriptor_set.file[0])
            descriptor = pool.FindMessageTypeByName("scip.Index")
        except (KeyError, TypeError) as exc:
            raise ScipCodecError("compiled schema does not define scip.Index") from exc
        return message_factory.GetMessageClass(descriptor)

    def decode_bytes(self, payload: bytes) -> Message:
        if not payload:
            raise ScipCodecError("SCIP index is empty")
        index = self._index_class()
        try:
            consumed = index.ParseFromString(payload)
        except DecodeError as exc:
            raise ScipCodecError(f"invalid SCIP protobuf: {exc}") from exc
        if consumed != len(payload):
            raise ScipCodecError(f"SCIP decoder consumed {consumed} of {len(payload)} bytes")
        known_only = self._index_class()
        known_only.CopyFrom(index)
        known_only.DiscardUnknownFields()
        if index.SerializeToString(deterministic=True) != known_only.SerializeToString(
            deterministic=True
        ):
            raise ScipCodecError(
                f"SCIP index contains fields unknown to the frozen {SCIP_SCHEMA_RELEASE} schema"
            )
        return index


def field(message: Message, name: str) -> Any:
    """Typed boundary helper for dynamic Protobuf messages."""
    try:
        return getattr(message, name)
    except AttributeError as exc:
        raise ScipCodecError(f"SCIP schema is missing required field {name!r}") from exc
