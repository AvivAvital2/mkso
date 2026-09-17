"""Bootstrap enforcement for deterministic reason-bound authorized deltas.

The accepted values are deliberately restricted to the ASCII/integer subset
handled by mkso.hashing. This module cannot authorize production use until
mkso admits the separately qualified general RFC 8785 component, signature
verifier, and Linux patch broker required by the frozen design.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from mkso.hashing import (
    BootstrapCanonicalizationError,
    restricted_bootstrap_json,
    restricted_record_hash,
    sha256_digest,
)

_RECORD_FIELDS = {
    "schema_version",
    "contract_hash",
    "baseline_source_snapshot_hash",
    "edit_submission_hash",
    "result_entry_set_hash",
    "slot_result_bindings",
    "authorized_diff_hash",
}


class AuthorizedDiffError(ValueError):
    """Raised when an authorized-diff value cannot be rederived exactly."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AuthorizedDiffError(message)


def _index_unique(
    values: Sequence[Mapping[str, Any]], key: str, label: str
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for value in values:
        identity = value.get(key)
        _require(isinstance(identity, str) and identity, f"{label} has no {key}")
        _require(identity not in result, f"duplicate {label} {identity}")
        result[identity] = value
    return result


def result_entry_set_hash(entries: Sequence[Mapping[str, Any]]) -> str:
    """Hash one already ordered complete candidate-entry array."""

    paths = [entry.get("path") for entry in entries]
    _require(all(isinstance(path, str) and path for path in paths), "result entry has no path")
    _require(len(paths) == len(set(paths)), "duplicate result entry path")
    _require(
        paths == sorted(paths, key=lambda path: path.encode("utf-8")),
        "result entries are not in UTF-8 path order",
    )
    try:
        return sha256_digest(restricted_bootstrap_json(list(entries)))
    except BootstrapCanonicalizationError as exc:
        raise AuthorizedDiffError(f"result entries exceed bootstrap JCS subset: {exc}") from exc


def derive_authorized_diff(
    *,
    contract_hash: str,
    baseline_source_snapshot_hash: str,
    edit_submission_hash: str,
    frozen_slots: Sequence[Mapping[str, Any]],
    operations: Sequence[Mapping[str, Any]],
    result_entries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Derive the sole bootstrap record from admitted broker inputs."""

    slots = _index_unique(frozen_slots, "id", "frozen slot")
    operation_ids = [operation.get("slot_id") for operation in operations]
    _require(operation_ids, "authorized diff has no active operation")
    _require(
        all(isinstance(slot_id, str) and slot_id for slot_id in operation_ids),
        "operation has no slot ID",
    )
    _require(len(operation_ids) == len(set(operation_ids)), "duplicate active slot operation")
    _require(set(operation_ids) <= set(slots), "active operation has no frozen slot")

    entry_index = _index_unique(result_entries, "path", "result entry")
    entry_set_hash = result_entry_set_hash(result_entries)
    bindings: list[dict[str, Any]] = []
    for operation in sorted(operations, key=lambda item: item["slot_id"].encode("utf-8")):
        slot = slots[operation["slot_id"]]
        path = slot.get("path")
        _require(isinstance(path, str) and path in entry_index, "slot result entry is absent")
        result = entry_index[path]
        bindings.append(
            {
                "slot_id": slot["id"],
                "obligation_id": slot["obligation_id"],
                "task_id": slot["task_id"],
                "subject_id": slot["subject_id"],
                "change_category": slot["change_category"],
                "replacement_blob_hash": operation["replacement_blob_hash"],
                "replacement_size": operation["replacement_size"],
                "path": path,
                "result_mode": result["mode"],
                "result_size": result["size"],
                "result_content_hash": result["content_hash"],
            }
        )

    record = {
        "schema_version": "mkso-authorized-diff/1",
        "contract_hash": contract_hash,
        "baseline_source_snapshot_hash": baseline_source_snapshot_hash,
        "edit_submission_hash": edit_submission_hash,
        "result_entry_set_hash": entry_set_hash,
        "slot_result_bindings": bindings,
    }
    try:
        record["authorized_diff_hash"] = restricted_record_hash(
            record, omitted_fields={"authorized_diff_hash"}
        )
    except BootstrapCanonicalizationError as exc:
        raise AuthorizedDiffError(f"authorized diff exceeds bootstrap JCS subset: {exc}") from exc
    return record


def validate_authorized_diff(
    value: Mapping[str, Any],
    *,
    contract_hash: str,
    baseline_source_snapshot_hash: str,
    edit_submission_hash: str,
    frozen_slots: Sequence[Mapping[str, Any]],
    operations: Sequence[Mapping[str, Any]],
    result_entries: Sequence[Mapping[str, Any]],
) -> None:
    """Reject every stored value that differs from deterministic rederivation."""

    _require(set(value) == _RECORD_FIELDS, "authorized diff has missing or extra fields")
    expected = derive_authorized_diff(
        contract_hash=contract_hash,
        baseline_source_snapshot_hash=baseline_source_snapshot_hash,
        edit_submission_hash=edit_submission_hash,
        frozen_slots=frozen_slots,
        operations=operations,
        result_entries=result_entries,
    )
    _require(dict(value) == expected, "authorized diff differs from its rederived value")


def validate_contract_join(
    value: Mapping[str, Any],
    *,
    admitted_contract_hash: str,
    contract: Mapping[str, Any],
) -> None:
    """Join stored audit fields to a separately admitted frozen contract."""

    _require(value.get("contract_hash") == admitted_contract_hash, "contract hash join failed")
    slots_value = contract.get("edit_slots")
    obligations_value = contract.get("obligations")
    _require(isinstance(slots_value, list), "contract has no edit-slot array")
    _require(isinstance(obligations_value, list), "contract has no obligation array")
    slots = _index_unique(slots_value, "id", "contract slot")
    obligations = _index_unique(obligations_value, "id", "contract obligation")
    bindings = value.get("slot_result_bindings")
    _require(isinstance(bindings, list), "authorized diff has no binding array")
    for binding in bindings:
        slot_id = binding.get("slot_id")
        _require(isinstance(slot_id, str) and slot_id in slots, "binding has no contract slot")
        slot = slots[slot_id]
        for field in (
            "obligation_id",
            "task_id",
            "subject_id",
            "change_category",
            "path",
        ):
            _require(
                binding.get(field) == slot.get(field), f"binding {field} differs from contract"
            )
        obligation_id = slot.get("obligation_id")
        _require(
            isinstance(obligation_id, str) and obligation_id in obligations,
            "slot has no contract obligation",
        )
        obligation = obligations[obligation_id]
        _require(obligation.get("role") != "composition", "slot obligation is composition")
        _require(
            obligation.get("work_item_id") == slot.get("task_id"),
            "slot obligation is owned by another work item",
        )
        subject_ids = obligation.get("subject_ids")
        _require(
            isinstance(subject_ids, list) and slot.get("subject_id") in subject_ids,
            "slot subject is absent from its obligation",
        )


def validate_candidate_manifest_join(value: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    """Join an admitted record to an independently authenticated manifest."""

    _require(manifest.get("contract_hash") == value.get("contract_hash"), "contract join failed")
    _require(
        manifest.get("baseline_source_snapshot_hash") == value.get("baseline_source_snapshot_hash"),
        "baseline join failed",
    )
    _require(
        manifest.get("edit_submission_hash") == value.get("edit_submission_hash"),
        "edit-submission join failed",
    )
    _require(
        manifest.get("authorized_diff_hash") == value.get("authorized_diff_hash"),
        "authorized-diff join failed",
    )
    entries = manifest.get("entries")
    _require(isinstance(entries, list), "candidate manifest has no entry array")
    _require(
        result_entry_set_hash(entries) == value.get("result_entry_set_hash"),
        "result-entry-set join failed",
    )


def validate_evaluation_join(
    value: Mapping[str, Any],
    manifest: Mapping[str, Any],
    evaluation: Mapping[str, Any],
) -> None:
    """Join an admitted evaluation after its separate full validation."""

    validate_candidate_manifest_join(value, manifest)
    _require(
        evaluation.get("contract_hash") == manifest.get("contract_hash"), "contract join failed"
    )
    _require(
        evaluation.get("candidate_hash") == manifest.get("candidate_hash"),
        "candidate join failed",
    )
    _require(
        evaluation.get("candidate_manifest_hash") == manifest.get("candidate_manifest_hash"),
        "candidate-manifest join failed",
    )
    primary = evaluation.get("primary")
    _require(isinstance(primary, Mapping), "evaluation has no primary record")
    _require(
        primary.get("authorized_diff_hash") == value.get("authorized_diff_hash"),
        "evaluation authorized-diff join failed",
    )
