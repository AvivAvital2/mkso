"""Exact structural comparison of two admitted standard-SCIP snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mkso.hashing import canonical_json

if TYPE_CHECKING:
    from mkso.store import Store


@dataclass(frozen=True, slots=True)
class ScipAdmissionDiff:
    before_admission_hash: str
    after_admission_hash: str
    index_bytes_changed: bool
    changed_contract_fields: tuple[str, ...]
    changed_generation_fields: tuple[str, ...]
    changed_input_paths: tuple[str, ...]
    changed_document_paths: tuple[str, ...]
    changed_symbol_keys: tuple[str, ...]
    changed_relationship_source_keys: tuple[str, ...]
    changed_occurrence_document_paths: tuple[str, ...]
    changed_subject_ids: tuple[str, ...]
    changed_contract_relationship_source_ids: tuple[str, ...]
    changed_source_index_policy_fields: tuple[str, ...]

    @property
    def is_empty(self) -> bool:
        return not (
            self.index_bytes_changed
            or self.changed_contract_fields
            or self.changed_generation_fields
            or self.changed_input_paths
            or self.changed_document_paths
            or self.changed_symbol_keys
            or self.changed_relationship_source_keys
            or self.changed_occurrence_document_paths
            or self.changed_subject_ids
            or self.changed_contract_relationship_source_ids
            or self.changed_source_index_policy_fields
        )


def _mapping(value: object, location: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{location} must be a string-keyed object")
    return dict(value)


def _rows(snapshot: Mapping[str, object], section: str) -> list[dict[str, Any]]:
    value = snapshot.get(section)
    if not isinstance(value, list):
        raise ValueError(f"SCIP snapshot {section} must be an array")
    return [_mapping(row, f"SCIP snapshot {section}[]") for row in value]


def _keyed_rows(
    snapshot: Mapping[str, object],
    section: str,
    key: str,
    *,
    excluded: frozenset[str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in _rows(snapshot, section):
        identity = row.get(key)
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"SCIP snapshot {section} row has no non-empty {key}")
        if identity in result:
            raise ValueError(f"SCIP snapshot {section} contains duplicate {key} {identity!r}")
        result[identity] = canonical_json(
            {name: value for name, value in row.items() if name not in excluded}
        )
    return result


def _grouped_rows(
    snapshot: Mapping[str, object],
    section: str,
    key: str,
    *,
    excluded: frozenset[str],
) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for row in _rows(snapshot, section):
        identity = row.get(key)
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"SCIP snapshot {section} row has no non-empty {key}")
        grouped.setdefault(identity, []).append(
            canonical_json({name: value for name, value in row.items() if name not in excluded})
        )
    return {identity: tuple(sorted(values)) for identity, values in grouped.items()}


def _changed_keys(before: Mapping[str, object], after: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        sorted(key for key in set(before) | set(after) if before.get(key) != after.get(key))
    )


def _input_manifest(index: Mapping[str, object]) -> dict[str, str]:
    manifest = index.get("input_manifest")
    if not isinstance(manifest, list):
        raise ValueError("SCIP snapshot index input_manifest must be an array")
    result: dict[str, str] = {}
    for value in manifest:
        if (
            not isinstance(value, list)
            or len(value) != 2
            or not all(isinstance(item, str) and item for item in value)
        ):
            raise ValueError("SCIP snapshot index input_manifest contains an invalid entry")
        path, digest = value
        if path in result:
            raise ValueError(f"SCIP snapshot index input_manifest duplicates {path!r}")
        result[path] = digest
    return result


def _changed_fields(
    before: Mapping[str, object],
    after: Mapping[str, object],
    fields: frozenset[str],
) -> tuple[str, ...]:
    return tuple(sorted(field for field in fields if before.get(field) != after.get(field)))


def compare_scip_admissions(
    store: Store,
    before_admission_hash: str,
    after_admission_hash: str,
) -> ScipAdmissionDiff:
    """Report exact stored differences without inferring behavioral impact."""
    before = store.scip_snapshot(before_admission_hash)
    after = store.scip_snapshot(after_admission_hash)
    if before is None or after is None:  # explicit hashes cannot select the implicit empty state
        raise ValueError("both SCIP admissions must exist")

    before_admission = _mapping(before.get("admission"), "SCIP snapshot admission")
    after_admission = _mapping(after.get("admission"), "SCIP snapshot admission")
    before_index = _mapping(before.get("index"), "SCIP snapshot index")
    after_index = _mapping(after.get("index"), "SCIP snapshot index")
    before_source_policy = _mapping(
        before.get("source_index_policy"),
        "SCIP snapshot source_index_policy",
    )
    after_source_policy = _mapping(
        after.get("source_index_policy"),
        "SCIP snapshot source_index_policy",
    )

    before_hash = before_admission.get("admission_hash")
    after_hash = after_admission.get("admission_hash")
    if before_hash != before_admission_hash or after_hash != after_admission_hash:
        raise ValueError("SCIP snapshot admission identity does not match its lookup hash")

    contract_fields = (frozenset(before_admission) | frozenset(after_admission)) - frozenset(
        {"admission_hash", "ingestion_hash"}
    )
    generation_fields = (frozenset(before_index) | frozenset(after_index)) - frozenset(
        {"ingestion_hash", "index_hash", "raw_index_size", "input_manifest"}
    )

    before_inputs = _input_manifest(before_index)
    after_inputs = _input_manifest(after_index)
    documents_before = _keyed_rows(
        before,
        "documents",
        "relative_path",
        excluded=frozenset({"ingestion_hash"}),
    )
    documents_after = _keyed_rows(
        after,
        "documents",
        "relative_path",
        excluded=frozenset({"ingestion_hash"}),
    )
    symbols_before = _keyed_rows(
        before,
        "symbols",
        "symbol_key",
        excluded=frozenset({"ingestion_hash"}),
    )
    symbols_after = _keyed_rows(
        after,
        "symbols",
        "symbol_key",
        excluded=frozenset({"ingestion_hash"}),
    )
    relationships_before = _grouped_rows(
        before,
        "relationships",
        "source_symbol_key",
        excluded=frozenset({"ingestion_hash", "ordinal"}),
    )
    relationships_after = _grouped_rows(
        after,
        "relationships",
        "source_symbol_key",
        excluded=frozenset({"ingestion_hash", "ordinal"}),
    )
    occurrences_before = _grouped_rows(
        before,
        "occurrences",
        "document_path",
        excluded=frozenset({"ingestion_hash", "ordinal"}),
    )
    occurrences_after = _grouped_rows(
        after,
        "occurrences",
        "document_path",
        excluded=frozenset({"ingestion_hash", "ordinal"}),
    )
    subjects_before = _keyed_rows(
        before,
        "subject_bindings",
        "subject_id",
        excluded=frozenset({"admission_hash"}),
    )
    subjects_after = _keyed_rows(
        after,
        "subject_bindings",
        "subject_id",
        excluded=frozenset({"admission_hash"}),
    )
    contract_relationships_before = _grouped_rows(
        before,
        "contract_relationships",
        "source_subject_id",
        excluded=frozenset({"admission_hash"}),
    )
    contract_relationships_after = _grouped_rows(
        after,
        "contract_relationships",
        "source_subject_id",
        excluded=frozenset({"admission_hash"}),
    )

    return ScipAdmissionDiff(
        before_admission_hash=before_admission_hash,
        after_admission_hash=after_admission_hash,
        index_bytes_changed=before_index.get("index_hash") != after_index.get("index_hash"),
        changed_contract_fields=_changed_fields(
            before_admission,
            after_admission,
            contract_fields,
        ),
        changed_generation_fields=_changed_fields(
            before_index,
            after_index,
            generation_fields,
        ),
        changed_input_paths=_changed_keys(before_inputs, after_inputs),
        changed_document_paths=_changed_keys(documents_before, documents_after),
        changed_symbol_keys=_changed_keys(symbols_before, symbols_after),
        changed_relationship_source_keys=_changed_keys(
            relationships_before,
            relationships_after,
        ),
        changed_occurrence_document_paths=_changed_keys(
            occurrences_before,
            occurrences_after,
        ),
        changed_subject_ids=_changed_keys(subjects_before, subjects_after),
        changed_contract_relationship_source_ids=_changed_keys(
            contract_relationships_before,
            contract_relationships_after,
        ),
        changed_source_index_policy_fields=_changed_keys(
            before_source_policy,
            after_source_policy,
        ),
    )
