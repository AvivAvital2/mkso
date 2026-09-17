"""Exact public-bootstrap environment policy for the V1 Python SCIP adapter.

This module is adapter-specific by design.  It must not turn the generic
container-image or Docker-profile machinery into a Python-only abstraction.
Its checks implement the static and cross-view parts of D-113, but they confer
no authority without the signed framework freeze, qualified runtime image,
Docker adapter, and Linux host observation required by the frozen design.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from mkso.hashing import restricted_bootstrap_json, sha256_digest

PYTHON_SCIP_HOSTNAME: Final = "mkso-scip-python"
PYTHON_SCIP_ENTRYPOINT: Final = ("/usr/local/bin/mkso-scip-python",)
PYTHON_SCIP_ENVIRONMENT: Final = (
    ("HOME", "/nonexistent"),
    ("HOSTNAME", PYTHON_SCIP_HOSTNAME),
    ("LC_ALL", "C.UTF-8"),
    ("PATH", ""),
    ("TMPDIR", "/tmp"),
    ("TZ", "UTC"),
)
PYTHON_SCIP_DOCKER_ENVIRONMENT: Final = tuple(
    f"{name}={value}" for name, value in PYTHON_SCIP_ENVIRONMENT
)
PYTHON_SCIP_ENVIRONMENT_VIEW_LABELS: Final = (
    "image_config",
    "create_request",
    "inspect",
    "host_observed_process",
)


class PythonScipEnvironmentError(ValueError):
    """Raised when a Python SCIP environment view differs from D-113."""


def environment_pairs_json() -> list[list[str]]:
    """Return a fresh JSON representation of the exact D-113 environment."""

    return [list(pair) for pair in PYTHON_SCIP_ENVIRONMENT]


def docker_environment_json() -> list[str]:
    """Return a fresh Docker/OCI config representation of the environment."""

    return list(PYTHON_SCIP_DOCKER_ENVIRONMENT)


def derive_bootstrap_environment_hash() -> str:
    """Hash the restricted D-113 pair representation for public bootstrap use."""

    return sha256_digest(restricted_bootstrap_json(environment_pairs_json()))


def validate_environment_pairs(value: object, label: str) -> tuple[tuple[str, str], ...]:
    """Require one JSON pair array to equal the complete canonical environment."""

    expected = environment_pairs_json()
    if value != expected:
        raise PythonScipEnvironmentError(f"{label} is not the exact D-113 environment")
    return PYTHON_SCIP_ENVIRONMENT


def validate_docker_environment(value: object, label: str) -> tuple[str, ...]:
    """Require one Docker/OCI ``NAME=value`` array to equal D-113 exactly."""

    expected = docker_environment_json()
    if value != expected:
        raise PythonScipEnvironmentError(f"{label} is not the exact D-113 environment")
    return PYTHON_SCIP_DOCKER_ENVIRONMENT


def validate_observed_process_environment(value: object) -> tuple[tuple[str, str], ...]:
    """Parse and validate raw Linux ``/proc/<pid>/environ``-style bytes."""

    if not isinstance(value, bytes) or not value or not value.endswith(b"\0"):
        raise PythonScipEnvironmentError(
            "host-observed process environment must be non-empty NUL-terminated bytes"
        )
    raw_entries = value[:-1].split(b"\0")
    if any(not entry for entry in raw_entries):
        raise PythonScipEnvironmentError("host-observed process environment has an empty entry")

    pairs: list[tuple[str, str]] = []
    for entry in raw_entries:
        try:
            text = entry.decode("ascii")
        except UnicodeDecodeError as exc:
            raise PythonScipEnvironmentError(
                "host-observed process environment is not ASCII"
            ) from exc
        name, separator, setting = text.partition("=")
        if not separator or not name:
            raise PythonScipEnvironmentError(
                "host-observed process environment has an invalid entry"
            )
        pairs.append((name, setting))

    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise PythonScipEnvironmentError(
            "host-observed process environment contains a duplicate name"
        )
    canonical = tuple(sorted(pairs, key=lambda pair: pair[0].encode("ascii")))
    if canonical != PYTHON_SCIP_ENVIRONMENT:
        raise PythonScipEnvironmentError(
            "host-observed process environment is not the exact D-113 environment"
        )
    return canonical


def validate_environment_views(views: Mapping[str, object]) -> None:
    """Require every named Docker/OCI environment view to equal D-113.

    Production callers will supply retained image-config, create-request,
    inspect, and independently host-observed process views.  This function
    validates only their exact values; it does not authenticate their origins.
    """

    if set(views) != set(PYTHON_SCIP_ENVIRONMENT_VIEW_LABELS):
        raise PythonScipEnvironmentError("environment view set is missing or extra")
    for label in PYTHON_SCIP_ENVIRONMENT_VIEW_LABELS[:-1]:
        validate_docker_environment(views[label], label)
    validate_observed_process_environment(views["host_observed_process"])
