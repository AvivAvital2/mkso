"""Bootstrap-only deterministic JSON hashing helpers.

This module is deliberately *not* an RFC 8785 implementation. Sorted compact
``json.dumps`` output is suitable only where the caller has independently
restricted values to the ASCII/integer subset for which the bytes are known to
match JCS. Authoritative record hashing must use the separately qualified JCS
component required by the frozen design.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any


class BootstrapCanonicalizationError(ValueError):
    """Raised when a value exceeds the audited bootstrap JCS subset."""


def canonical_json(value: Any) -> str:
    """Return stable bootstrap JSON; never treat this function as general JCS."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_digest(value: bytes) -> str:
    """Return a lowercase SHA-256 digest with its algorithm prefix."""

    return f"sha256:{sha256_bytes(value)}"


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_object(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _require_restricted_bootstrap_value(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, str):
        if not value.isascii():
            raise BootstrapCanonicalizationError(f"{path}: non-ASCII bootstrap record value")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_restricted_bootstrap_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise BootstrapCanonicalizationError(f"{path}: invalid object key")
            _require_restricted_bootstrap_value(item, f"{path}.{key}")
        return
    raise BootstrapCanonicalizationError(
        f"{path}: unsupported bootstrap record value {type(value).__name__}"
    )


def restricted_bootstrap_json(value: object) -> bytes:
    """Return JCS-equivalent bytes only for the audited ASCII/integer subset."""

    _require_restricted_bootstrap_value(value)
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def restricted_record_hash(record: Mapping[str, Any], *, omitted_fields: Collection[str]) -> str:
    """Hash one restricted record projection with an explicit omission set."""

    projection = {key: value for key, value in record.items() if key not in omitted_fields}
    return sha256_digest(restricted_bootstrap_json(projection))
