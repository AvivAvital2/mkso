"""SQLite persistence for the active graph and append-only evidence history."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from mkso.domain import (
    CheckerPolicy,
    Evidence,
    EvidenceKind,
    EvidenceStatus,
    NodeKind,
    Obligation,
    ObligationRole,
    PlannedBinding,
    WorkItem,
)
from mkso.hashing import sha256_bytes, sha256_file
from mkso.scip import (
    ScipExpectation,
    ScipIndexerInvocation,
    load_scip_bytes,
    run_scip_indexer,
    scip_admission_hash,
    scip_ingestion_hash,
    verify_contract_subjects,
)
from mkso.scip_codec import ScipDecoder

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plan_revisions (
    plan_hash TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    manifest_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS work_items (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    parent_id TEXT REFERENCES work_items(id) ON DELETE CASCADE,
    position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS obligations (
    id TEXT PRIMARY KEY,
    work_item_id TEXT NOT NULL REFERENCES work_items(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    statement TEXT NOT NULL,
    role TEXT NOT NULL,
    required_evidence_json TEXT NOT NULL,
    checker_policies_json TEXT NOT NULL,
    assumptions_json TEXT NOT NULL,
    guarantees_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS planned_bindings (
    obligation_id TEXT NOT NULL REFERENCES obligations(id) ON DELETE CASCADE,
    file TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    signature TEXT NOT NULL,
    rationale TEXT NOT NULL,
    expected_symbol TEXT NOT NULL,
    symbol_id TEXT,
    indexed_source_hash TEXT,
    indexed_admission_hash TEXT,
    PRIMARY KEY (obligation_id, file, qualified_name)
);

CREATE TABLE IF NOT EXISTS scip_indexes (
    ingestion_hash TEXT PRIMARY KEY,
    index_hash TEXT NOT NULL,
    raw_index BLOB NOT NULL,
    schema_release TEXT NOT NULL,
    schema_sha256 TEXT NOT NULL,
    protoc_path TEXT NOT NULL,
    protoc_sha256 TEXT NOT NULL,
    protoc_version TEXT NOT NULL,
    protobuf_runtime_version TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_arguments_json TEXT NOT NULL,
    project_root_uri TEXT NOT NULL,
    text_document_encoding INTEGER NOT NULL,
    indexer_executable_path TEXT NOT NULL,
    indexer_executable_sha256 TEXT NOT NULL,
    indexer_arguments_json TEXT NOT NULL,
    indexer_environment_hash TEXT NOT NULL,
    input_manifest_json TEXT NOT NULL,
    indexed_files_json TEXT NOT NULL,
    indexer_stdin_hash TEXT,
    indexer_stdout_hash TEXT NOT NULL,
    indexer_stderr_hash TEXT NOT NULL,
    indexer_exit_code INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scip_documents (
    ingestion_hash TEXT NOT NULL REFERENCES scip_indexes(ingestion_hash) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    language TEXT NOT NULL,
    position_encoding INTEGER NOT NULL,
    source_hash TEXT NOT NULL,
    PRIMARY KEY (ingestion_hash, relative_path)
);

CREATE TABLE IF NOT EXISTS scip_symbols (
    ingestion_hash TEXT NOT NULL REFERENCES scip_indexes(ingestion_hash) ON DELETE CASCADE,
    symbol_key TEXT NOT NULL,
    symbol TEXT NOT NULL,
    document_path TEXT,
    external INTEGER NOT NULL CHECK (external IN (0, 1)),
    kind INTEGER NOT NULL,
    display_name TEXT NOT NULL,
    signature_language TEXT NOT NULL,
    signature_text TEXT NOT NULL,
    enclosing_symbol TEXT NOT NULL,
    PRIMARY KEY (ingestion_hash, symbol_key)
);

CREATE TABLE IF NOT EXISTS scip_relationships (
    ingestion_hash TEXT NOT NULL REFERENCES scip_indexes(ingestion_hash) ON DELETE CASCADE,
    source_symbol_key TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    target_symbol_key TEXT NOT NULL,
    is_reference INTEGER NOT NULL CHECK (is_reference IN (0, 1)),
    is_implementation INTEGER NOT NULL CHECK (is_implementation IN (0, 1)),
    is_type_definition INTEGER NOT NULL CHECK (is_type_definition IN (0, 1)),
    is_definition INTEGER NOT NULL CHECK (is_definition IN (0, 1)),
    PRIMARY KEY (ingestion_hash, source_symbol_key, ordinal)
);

CREATE TABLE IF NOT EXISTS scip_occurrences (
    ingestion_hash TEXT NOT NULL REFERENCES scip_indexes(ingestion_hash) ON DELETE CASCADE,
    document_path TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    symbol_key TEXT NOT NULL,
    symbol_roles INTEGER NOT NULL,
    start_line INTEGER NOT NULL,
    start_character INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    end_character INTEGER NOT NULL,
    enclosing_start_line INTEGER,
    enclosing_start_character INTEGER,
    enclosing_end_line INTEGER,
    enclosing_end_character INTEGER,
    PRIMARY KEY (ingestion_hash, document_path, ordinal)
);

CREATE TABLE IF NOT EXISTS scip_admissions (
    admission_hash TEXT PRIMARY KEY,
    ingestion_hash TEXT NOT NULL REFERENCES scip_indexes(ingestion_hash),
    contract_path TEXT NOT NULL,
    contract_sha256 TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scip_contract_index_policies (
    admission_hash TEXT PRIMARY KEY REFERENCES scip_admissions(admission_hash) ON DELETE CASCADE,
    policy_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scip_subject_bindings (
    admission_hash TEXT NOT NULL REFERENCES scip_admissions(admission_hash) ON DELETE CASCADE,
    subject_id TEXT NOT NULL,
    symbol TEXT NOT NULL,
    document_path TEXT NOT NULL,
    definition_start_line INTEGER NOT NULL,
    definition_start_character INTEGER NOT NULL,
    definition_end_line INTEGER NOT NULL,
    definition_end_character INTEGER NOT NULL,
    enclosing_start_line INTEGER,
    enclosing_start_character INTEGER,
    enclosing_end_line INTEGER,
    enclosing_end_character INTEGER,
    source_hash TEXT NOT NULL,
    PRIMARY KEY (admission_hash, subject_id)
);

CREATE TABLE IF NOT EXISTS scip_contract_relationships (
    admission_hash TEXT NOT NULL,
    source_subject_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    target_subject_id TEXT NOT NULL,
    required INTEGER NOT NULL CHECK (required IN (0, 1)),
    PRIMARY KEY (admission_hash, source_subject_id, kind, target_subject_id),
    FOREIGN KEY (admission_hash, source_subject_id)
        REFERENCES scip_subject_bindings(admission_hash, subject_id) ON DELETE CASCADE,
    FOREIGN KEY (admission_hash, target_subject_id)
        REFERENCES scip_subject_bindings(admission_hash, subject_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_scip_definitions
ON scip_occurrences(ingestion_hash, document_path, symbol, symbol_roles);

-- Evidence is intentionally not foreign-keyed to obligations.  Re-applying an
-- accepted plan replaces the active graph, while historical evidence remains
-- available for audit.  Its subject digest prevents accidental reuse.
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    obligation_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    tool TEXT NOT NULL,
    command_json TEXT NOT NULL,
    status TEXT NOT NULL,
    subject_digest TEXT NOT NULL,
    exit_code INTEGER,
    artifact_path TEXT,
    artifact_sha256 TEXT,
    stdout TEXT NOT NULL,
    stderr TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_lookup
ON evidence(obligation_id, kind, created_at DESC);
"""


def _input_file_error(project_root: Path, relative_path: str, expected_hash: str) -> str | None:
    parts = relative_path.split("/")
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or any(part in {"", ".", ".."} for part in parts)
        or PurePosixPath(relative_path).as_posix() != relative_path
    ):
        return f"SCIP generation input path is not canonical: {relative_path}"
    if len(expected_hash) != 64 or any(value not in "0123456789abcdef" for value in expected_hash):
        return f"SCIP generation input hash is invalid: {relative_path}"
    path = project_root / relative_path
    cursor = project_root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink():
            return f"SCIP generation input is a symbolic link: {relative_path}"
    if not path.is_file() or sha256_file(path) != expected_hash:
        return f"SCIP generation input is stale: {relative_path}"
    return None


@dataclass(frozen=True, slots=True)
class ScipAdmissionReceipt:
    admission_hash: str
    resolved_bindings: int
    document_count: int
    symbol_count: int
    occurrence_count: int
    subject_count: int


class Store:
    def __init__(self, database: Path, project_root: Path | None = None) -> None:
        self.database = database.resolve()
        self.project_root = (project_root or database.parent.parent).resolve()

    @classmethod
    def initialize(cls, project_root: Path) -> Store:
        root = project_root.resolve()
        state_dir = root / ".mkso"
        state_dir.mkdir(parents=True, exist_ok=True)
        store = cls(state_dir / "project.db", root)
        with store.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('project_root', ?)",
                (str(root),),
            )
        return store

    @classmethod
    def discover(cls, start: Path) -> Store:
        cursor = start.resolve()
        for candidate in (cursor, *cursor.parents):
            database = candidate / ".mkso" / "project.db"
            if database.is_file():
                return cls(database, candidate)
        raise FileNotFoundError("no .mkso/project.db found; run `mkso init` first")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.database)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def metadata(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def replace_plan(
        self,
        *,
        plan_hash: str,
        applied_at: str,
        manifest_json: str,
        work_items: Iterable[WorkItem],
        obligations: Iterable[Obligation],
        bindings: Iterable[PlannedBinding],
    ) -> None:
        items = list(work_items)
        obligations_list = list(obligations)
        bindings_list = list(bindings)
        by_id = {item.id: item for item in items}

        def depth(item: WorkItem) -> int:
            seen: set[str] = set()
            current = item
            value = 0
            while current.parent_id is not None:
                if current.id in seen:
                    raise ValueError(f"cycle while ordering work item {item.id}")
                seen.add(current.id)
                value += 1
                current = by_id[current.parent_id]
            return value

        with self.connect() as conn:
            conn.execute("DELETE FROM work_items")
            for item in sorted(items, key=lambda value: (depth(value), value.position, value.id)):
                conn.execute(
                    "INSERT INTO work_items(id, kind, title, description, parent_id, position) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        item.id,
                        item.kind.value,
                        item.title,
                        item.description,
                        item.parent_id,
                        item.position,
                    ),
                )
            conn.executemany(
                "INSERT INTO obligations(id, work_item_id, title, statement, role, "
                "required_evidence_json, checker_policies_json, assumptions_json, "
                "guarantees_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        obligation.id,
                        obligation.work_item_id,
                        obligation.title,
                        obligation.statement,
                        obligation.role.value,
                        json.dumps([kind.value for kind in obligation.required_evidence]),
                        json.dumps(
                            [
                                {
                                    "kind": policy.kind.value,
                                    "tool": policy.tool,
                                    "command": list(policy.command),
                                    "inputs": list(policy.inputs),
                                    "artifact_path": policy.artifact_path,
                                }
                                for policy in obligation.checker_policies
                            ]
                        ),
                        json.dumps(list(obligation.assumptions)),
                        json.dumps(list(obligation.guarantees)),
                    )
                    for obligation in obligations_list
                ],
            )
            conn.executemany(
                "INSERT INTO planned_bindings(obligation_id, file, qualified_name, "
                "signature, rationale, expected_symbol, symbol_id, indexed_source_hash, "
                "indexed_admission_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        binding.obligation_id,
                        binding.file,
                        binding.qualified_name,
                        binding.signature,
                        binding.rationale,
                        binding.expected_symbol,
                        binding.symbol_id,
                        binding.indexed_source_hash,
                        binding.indexed_admission_hash,
                    )
                    for binding in bindings_list
                ],
            )
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) VALUES('active_plan_hash', ?)",
                (plan_hash,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO plan_revisions(plan_hash, applied_at, manifest_json) "
                "VALUES(?, ?, ?)",
                (plan_hash, applied_at, manifest_json),
            )

    def work_items(self) -> list[WorkItem]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM work_items ORDER BY position, id").fetchall()
        return [
            WorkItem(
                id=row["id"],
                kind=NodeKind(row["kind"]),
                title=row["title"],
                description=row["description"],
                parent_id=row["parent_id"],
                position=row["position"],
            )
            for row in rows
        ]

    def obligations(self, work_item_id: str | None = None) -> list[Obligation]:
        query = "SELECT * FROM obligations"
        params: tuple[str, ...] = ()
        if work_item_id is not None:
            query += " WHERE work_item_id = ?"
            params = (work_item_id,)
        query += " ORDER BY id"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            Obligation(
                id=row["id"],
                work_item_id=row["work_item_id"],
                title=row["title"],
                statement=row["statement"],
                role=ObligationRole(row["role"]),
                required_evidence=tuple(
                    EvidenceKind(value) for value in json.loads(row["required_evidence_json"])
                ),
                checker_policies=tuple(
                    CheckerPolicy(
                        kind=EvidenceKind(value["kind"]),
                        tool=value["tool"],
                        command=tuple(value["command"]),
                        inputs=tuple(value["inputs"]),
                        artifact_path=value.get("artifact_path"),
                    )
                    for value in json.loads(row["checker_policies_json"])
                ),
                assumptions=tuple(json.loads(row["assumptions_json"])),
                guarantees=tuple(json.loads(row["guarantees_json"])),
            )
            for row in rows
        ]

    def obligation(self, obligation_id: str) -> Obligation:
        matches = [value for value in self.obligations() if value.id == obligation_id]
        if not matches:
            raise KeyError(f"unknown obligation: {obligation_id}")
        return matches[0]

    def bindings(self, obligation_id: str | None = None) -> list[PlannedBinding]:
        query = "SELECT * FROM planned_bindings"
        params: tuple[str, ...] = ()
        if obligation_id is not None:
            query += " WHERE obligation_id = ?"
            params = (obligation_id,)
        query += " ORDER BY obligation_id, file, qualified_name"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            PlannedBinding(
                obligation_id=row["obligation_id"],
                file=row["file"],
                qualified_name=row["qualified_name"],
                signature=row["signature"],
                rationale=row["rationale"],
                expected_symbol=row["expected_symbol"],
                symbol_id=row["symbol_id"],
                indexed_source_hash=row["indexed_source_hash"],
                indexed_admission_hash=row["indexed_admission_hash"],
            )
            for row in rows
        ]

    def admit_scip_index(
        self,
        decoder: ScipDecoder,
        expectation: ScipExpectation,
        invocation: ScipIndexerInvocation,
        contract_path: Path,
        *,
        stdin_payload: bytes | None = None,
    ) -> ScipAdmissionReceipt:
        """Own the indexer run, re-decode its bytes, bind, and atomically persist SCIP."""
        _, generation, raw_index = run_scip_indexer(
            decoder,
            self.project_root,
            expectation,
            invocation,
            stdin_payload=stdin_payload,
        )
        if sha256_bytes(raw_index) != generation.index_hash or generation.exit_code != 0:
            raise ValueError("SCIP generation attestation does not admit this index")
        index = load_scip_bytes(decoder, raw_index, self.project_root, expectation)
        contract = verify_contract_subjects(
            index,
            contract_path,
            project_root=self.project_root,
        )
        if len(contract.contract_sha256) != 64 or any(
            value not in "0123456789abcdef" for value in contract.contract_sha256
        ):
            raise ValueError("contract_sha256 must be one lowercase SHA-256 digest")
        contract_error = _input_file_error(
            self.project_root,
            contract.contract_path,
            contract.contract_sha256,
        )
        if contract_error is not None:
            raise ValueError(contract_error.replace("SCIP generation input", "SCIP contract"))
        if not generation.input_manifest:
            raise ValueError("SCIP generation input manifest is empty")
        if tuple(sorted(generation.input_manifest)) != generation.input_manifest:
            raise ValueError("SCIP generation input manifest is not sorted")
        input_paths = [path for path, _ in generation.input_manifest]
        if len(set(input_paths)) != len(input_paths):
            raise ValueError("SCIP generation input manifest contains duplicate paths")
        if not generation.indexed_files or tuple(sorted(set(generation.indexed_files))) != (
            generation.indexed_files
        ):
            raise ValueError("SCIP generation indexed files must be non-empty, unique, and sorted")
        input_hashes = dict(generation.input_manifest)
        if not set(generation.indexed_files).issubset(input_hashes):
            raise ValueError("every indexed document must be present in the input manifest")
        policy = contract.source_index_policy
        if generation.indexed_files != policy.indexed_paths:
            raise ValueError("SCIP indexed files differ from the frozen contract scope")
        if tuple(input_paths) != policy.input_paths:
            raise ValueError("SCIP indexer inputs differ from the frozen contract scope")
        for relative_path, expected_hash in generation.input_manifest:
            error = _input_file_error(self.project_root, relative_path, expected_hash)
            if error is not None:
                raise ValueError(error)
        indexed_documents = tuple(
            sorted((document.relative_path, document.source_hash) for document in index.documents)
        )
        expected_documents = tuple(
            (relative_path, input_hashes[relative_path])
            for relative_path in generation.indexed_files
        )
        if indexed_documents != expected_documents:
            raise ValueError("SCIP documents do not match the attested indexed source bytes")
        subject_bindings = contract.subject_bindings
        if not subject_bindings:
            raise ValueError("SCIP admission has no contract subject bindings")
        if tuple(sorted(subject_bindings, key=lambda value: value.subject_id)) != subject_bindings:
            raise ValueError("SCIP subject bindings must be unique and sorted by subject ID")
        if len({binding.subject_id for binding in subject_bindings}) != len(subject_bindings):
            raise ValueError("SCIP subject bindings contain duplicate subject IDs")
        subject_relationships = contract.subject_relationships
        relationship_keys = [
            (
                relationship.source_subject_id,
                relationship.kind,
                relationship.target_subject_id,
            )
            for relationship in subject_relationships
        ]
        if relationship_keys != sorted(set(relationship_keys)):
            raise ValueError("SCIP contract relationships must be unique and sorted")
        subject_ids = {binding.subject_id for binding in subject_bindings}
        if any(
            relationship.source_subject_id not in subject_ids
            or relationship.target_subject_id not in subject_ids
            for relationship in subject_relationships
        ):
            raise ValueError("SCIP contract relationship refers to an unbound subject")
        documents_by_path = {document.relative_path: document for document in index.documents}
        for binding in subject_bindings:
            document = documents_by_path.get(binding.document_path)
            definitions = [
                occurrence
                for occurrence in index.occurrences
                if occurrence.document_path == binding.document_path
                and occurrence.symbol == binding.symbol
                and occurrence.is_definition
            ]
            if (
                document is None
                or document.source_hash != binding.source_hash
                or len(definitions) != 1
                or definitions[0].source_range != binding.definition_range
                or definitions[0].enclosing_range != binding.enclosing_range
            ):
                raise ValueError(
                    f"SCIP subject binding is not admitted by the index: {binding.subject_id}"
                )
        identity = index.codec_identity
        ingestion_hash = scip_ingestion_hash(index, generation)
        admission_hash = scip_admission_hash(ingestion_hash, contract)
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT raw_index FROM scip_indexes WHERE ingestion_hash = ?",
                (ingestion_hash,),
            ).fetchone()
            if existing is not None and bytes(existing["raw_index"]) != raw_index:
                raise ValueError("SCIP ingestion hash collision or inconsistent raw index")
            if existing is None:
                conn.execute(
                    "INSERT INTO scip_indexes(ingestion_hash, index_hash, raw_index, "
                    "schema_release, schema_sha256, protoc_path, protoc_sha256, "
                    "protoc_version, protobuf_runtime_version, tool_name, tool_version, "
                    "tool_arguments_json, project_root_uri, text_document_encoding, "
                    "indexer_executable_path, indexer_executable_sha256, "
                    "indexer_arguments_json, indexer_environment_hash, input_manifest_json, "
                    "indexed_files_json, indexer_stdin_hash, indexer_stdout_hash, "
                    "indexer_stderr_hash, indexer_exit_code) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?)",
                    (
                        ingestion_hash,
                        index.index_hash,
                        raw_index,
                        identity.schema_release,
                        identity.schema_sha256,
                        identity.protoc_path,
                        identity.protoc_sha256,
                        identity.protoc_version,
                        identity.protobuf_runtime_version,
                        index.tool_name,
                        index.tool_version,
                        json.dumps(list(index.tool_arguments)),
                        index.project_root_uri,
                        index.text_document_encoding,
                        generation.executable_path,
                        generation.executable_sha256,
                        json.dumps(list(generation.arguments)),
                        generation.environment_hash,
                        json.dumps([list(value) for value in generation.input_manifest]),
                        json.dumps(list(generation.indexed_files)),
                        generation.stdin_hash,
                        generation.stdout_hash,
                        generation.stderr_hash,
                        generation.exit_code,
                    ),
                )
                conn.executemany(
                    "INSERT INTO scip_documents(ingestion_hash, relative_path, language, "
                    "position_encoding, source_hash) VALUES(?, ?, ?, ?, ?)",
                    [
                        (
                            ingestion_hash,
                            document.relative_path,
                            document.language,
                            document.position_encoding,
                            document.source_hash,
                        )
                        for document in index.documents
                    ],
                )
                conn.executemany(
                    "INSERT INTO scip_symbols(ingestion_hash, symbol_key, symbol, "
                    "document_path, external, kind, display_name, signature_language, "
                    "signature_text, enclosing_symbol) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            ingestion_hash,
                            symbol.symbol_key,
                            symbol.symbol,
                            symbol.document_path,
                            int(symbol.external),
                            symbol.kind,
                            symbol.display_name,
                            symbol.signature_language,
                            symbol.signature_text,
                            symbol.enclosing_symbol,
                        )
                        for symbol in index.symbols
                    ],
                )
                conn.executemany(
                    "INSERT INTO scip_relationships(ingestion_hash, source_symbol_key, "
                    "ordinal, target_symbol_key, is_reference, is_implementation, "
                    "is_type_definition, is_definition) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            ingestion_hash,
                            symbol.symbol_key,
                            ordinal,
                            relationship.target_symbol_key,
                            int(relationship.is_reference),
                            int(relationship.is_implementation),
                            int(relationship.is_type_definition),
                            int(relationship.is_definition),
                        )
                        for symbol in index.symbols
                        for ordinal, relationship in enumerate(symbol.relationships)
                    ],
                )
                conn.executemany(
                    "INSERT INTO scip_occurrences(ingestion_hash, document_path, ordinal, "
                    "symbol, symbol_key, symbol_roles, start_line, start_character, end_line, "
                    "end_character, enclosing_start_line, enclosing_start_character, "
                    "enclosing_end_line, enclosing_end_character) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [
                        (
                            ingestion_hash,
                            occurrence.document_path,
                            occurrence.ordinal,
                            occurrence.symbol,
                            occurrence.symbol_key,
                            occurrence.symbol_roles,
                            occurrence.source_range.start.line,
                            occurrence.source_range.start.character,
                            occurrence.source_range.end.line,
                            occurrence.source_range.end.character,
                            None
                            if occurrence.enclosing_range is None
                            else occurrence.enclosing_range.start.line,
                            None
                            if occurrence.enclosing_range is None
                            else occurrence.enclosing_range.start.character,
                            None
                            if occurrence.enclosing_range is None
                            else occurrence.enclosing_range.end.line,
                            None
                            if occurrence.enclosing_range is None
                            else occurrence.enclosing_range.end.character,
                        )
                        for occurrence in index.occurrences
                    ],
                )
            conn.execute(
                "INSERT OR IGNORE INTO scip_admissions(admission_hash, ingestion_hash, "
                "contract_path, contract_sha256) VALUES(?, ?, ?, ?)",
                (
                    admission_hash,
                    ingestion_hash,
                    contract.contract_path,
                    contract.contract_sha256,
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO scip_contract_index_policies(admission_hash, policy_json) "
                "VALUES(?, ?)",
                (
                    admission_hash,
                    json.dumps(asdict(policy), sort_keys=True, separators=(",", ":")),
                ),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO scip_subject_bindings(admission_hash, subject_id, "
                "symbol, document_path, definition_start_line, definition_start_character, "
                "definition_end_line, definition_end_character, enclosing_start_line, "
                "enclosing_start_character, enclosing_end_line, enclosing_end_character, "
                "source_hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        admission_hash,
                        binding.subject_id,
                        binding.symbol,
                        binding.document_path,
                        binding.definition_range.start.line,
                        binding.definition_range.start.character,
                        binding.definition_range.end.line,
                        binding.definition_range.end.character,
                        None
                        if binding.enclosing_range is None
                        else binding.enclosing_range.start.line,
                        None
                        if binding.enclosing_range is None
                        else binding.enclosing_range.start.character,
                        None
                        if binding.enclosing_range is None
                        else binding.enclosing_range.end.line,
                        None
                        if binding.enclosing_range is None
                        else binding.enclosing_range.end.character,
                        binding.source_hash,
                    )
                    for binding in subject_bindings
                ],
            )
            conn.executemany(
                "INSERT OR IGNORE INTO scip_contract_relationships(admission_hash, "
                "source_subject_id, kind, target_subject_id, required) VALUES(?, ?, ?, ?, ?)",
                [
                    (
                        admission_hash,
                        relationship.source_subject_id,
                        relationship.kind,
                        relationship.target_subject_id,
                        int(relationship.required),
                    )
                    for relationship in subject_relationships
                ],
            )
            conn.execute(
                "UPDATE planned_bindings SET symbol_id = NULL, indexed_source_hash = NULL, "
                "indexed_admission_hash = NULL"
            )
            resolved = 0
            errors: list[str] = []
            authorized_subjects = {
                (binding.document_path, binding.symbol) for binding in subject_bindings
            }
            bindings = conn.execute(
                "SELECT * FROM planned_bindings ORDER BY obligation_id, file, qualified_name"
            ).fetchall()
            for binding in bindings:
                if (binding["file"], binding["expected_symbol"]) not in authorized_subjects:
                    errors.append(
                        f"{binding['obligation_id']}: planned binding is not an exact "
                        f"contract subject: {binding['file']}:{binding['expected_symbol']}"
                    )
                    continue
                candidates = conn.execute(
                    "SELECT o.symbol, d.source_hash FROM scip_occurrences o "
                    "JOIN scip_documents d ON d.ingestion_hash = o.ingestion_hash "
                    "AND d.relative_path = o.document_path "
                    "JOIN scip_symbols s ON s.ingestion_hash = o.ingestion_hash "
                    "AND s.symbol_key = o.symbol_key AND s.document_path = o.document_path "
                    "WHERE o.ingestion_hash = ? AND o.document_path = ? AND o.symbol = ? "
                    "AND (o.symbol_roles & 1) = 1",
                    (ingestion_hash, binding["file"], binding["expected_symbol"]),
                ).fetchall()
                if len(candidates) != 1:
                    errors.append(
                        f"{binding['obligation_id']}: expected one direct SCIP definition for "
                        f"{binding['file']}:{binding['expected_symbol']}, "
                        f"found {len(candidates)}"
                    )
                    continue
                candidate = candidates[0]
                conn.execute(
                    "UPDATE planned_bindings SET symbol_id = ?, indexed_source_hash = ?, "
                    "indexed_admission_hash = ? WHERE obligation_id = ? AND file = ? "
                    "AND qualified_name = ?",
                    (
                        candidate["symbol"],
                        candidate["source_hash"],
                        admission_hash,
                        binding["obligation_id"],
                        binding["file"],
                        binding["qualified_name"],
                    ),
                )
                resolved += 1
            if errors:
                raise ValueError("SCIP admission rejected: " + "; ".join(errors))
            conn.execute(
                "INSERT OR REPLACE INTO metadata(key, value) "
                "VALUES('active_scip_admission_hash', ?)",
                (admission_hash,),
            )
        return ScipAdmissionReceipt(
            admission_hash=admission_hash,
            resolved_bindings=resolved,
            document_count=len(index.documents),
            symbol_count=len(index.symbols),
            occurrence_count=len(index.occurrences),
            subject_count=len(subject_bindings),
        )

    def scip_snapshot(self, admission_hash: str | None = None) -> dict[str, object] | None:
        if admission_hash is None:
            admission_hash = self.metadata("active_scip_admission_hash")
        if admission_hash is None:
            return None
        with self.connect() as conn:
            admission = conn.execute(
                "SELECT * FROM scip_admissions WHERE admission_hash = ?", (admission_hash,)
            ).fetchone()
            if admission is None:
                raise ValueError(f"SCIP admission metadata is missing: {admission_hash}")
            ingestion_hash = str(admission["ingestion_hash"])
            index = conn.execute(
                "SELECT * FROM scip_indexes WHERE ingestion_hash = ?", (ingestion_hash,)
            ).fetchone()
            if index is None:
                raise ValueError(f"SCIP ingestion metadata is missing: {ingestion_hash}")
            documents = conn.execute(
                "SELECT * FROM scip_documents WHERE ingestion_hash = ? ORDER BY relative_path",
                (ingestion_hash,),
            ).fetchall()
            symbols = conn.execute(
                "SELECT * FROM scip_symbols WHERE ingestion_hash = ? "
                "ORDER BY external, document_path, symbol_key",
                (ingestion_hash,),
            ).fetchall()
            relationships = conn.execute(
                "SELECT * FROM scip_relationships WHERE ingestion_hash = ? "
                "ORDER BY source_symbol_key, ordinal",
                (ingestion_hash,),
            ).fetchall()
            occurrences = conn.execute(
                "SELECT * FROM scip_occurrences WHERE ingestion_hash = ? "
                "ORDER BY document_path, ordinal",
                (ingestion_hash,),
            ).fetchall()
            subject_bindings = conn.execute(
                "SELECT * FROM scip_subject_bindings WHERE admission_hash = ? ORDER BY subject_id",
                (admission_hash,),
            ).fetchall()
            source_index_policy = conn.execute(
                "SELECT policy_json FROM scip_contract_index_policies WHERE admission_hash = ?",
                (admission_hash,),
            ).fetchone()
            if source_index_policy is None:
                raise ValueError(f"SCIP contract index policy is missing: {admission_hash}")
            contract_relationships = conn.execute(
                "SELECT * FROM scip_contract_relationships WHERE admission_hash = ? "
                "ORDER BY source_subject_id, kind, target_subject_id",
                (admission_hash,),
            ).fetchall()
        index_value = dict(index)
        raw_index = index_value.pop("raw_index")
        index_value["raw_index_size"] = len(raw_index)
        index_value["tool_arguments"] = json.loads(index_value.pop("tool_arguments_json"))
        index_value["indexer_arguments"] = json.loads(index_value.pop("indexer_arguments_json"))
        index_value["input_manifest"] = json.loads(index_value.pop("input_manifest_json"))
        index_value["indexed_files"] = json.loads(index_value.pop("indexed_files_json"))
        return {
            "admission": dict(admission),
            "index": index_value,
            "documents": [dict(row) for row in documents],
            "symbols": [dict(row) for row in symbols],
            "relationships": [dict(row) for row in relationships],
            "occurrences": [dict(row) for row in occurrences],
            "subject_bindings": [dict(row) for row in subject_bindings],
            "contract_relationships": [dict(row) for row in contract_relationships],
            "source_index_policy": json.loads(source_index_policy["policy_json"]),
        }

    def scip_freshness_reasons(self) -> list[str]:
        admission_hash = self.metadata("active_scip_admission_hash")
        if admission_hash is None:
            return ["no active SCIP admission"]
        with self.connect() as conn:
            row = conn.execute(
                "SELECT a.contract_path, a.contract_sha256, i.input_manifest_json "
                "FROM scip_admissions a "
                "JOIN scip_indexes i ON i.ingestion_hash = a.ingestion_hash "
                "WHERE a.admission_hash = ?",
                (admission_hash,),
            ).fetchone()
        if row is None:
            return ["active SCIP admission records are missing"]
        contract_error = _input_file_error(
            self.project_root,
            row["contract_path"],
            row["contract_sha256"],
        )
        reasons: list[str] = []
        if contract_error is not None:
            reasons.append(contract_error.replace("SCIP generation input", "SCIP contract"))
        try:
            manifest = json.loads(row["input_manifest_json"])
        except json.JSONDecodeError:
            return [*reasons, "active SCIP input manifest is invalid JSON"]
        if not isinstance(manifest, list):
            return [*reasons, "active SCIP input manifest is not an array"]
        for value in manifest:
            if (
                not isinstance(value, list)
                or len(value) != 2
                or not all(isinstance(item, str) for item in value)
            ):
                reasons.append("active SCIP input manifest contains an invalid entry")
                continue
            error = _input_file_error(self.project_root, value[0], value[1])
            if error is not None:
                reasons.append(error)
        return reasons

    def add_evidence(self, evidence: Evidence) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO evidence(id, obligation_id, kind, tool, command_json, status, "
                "subject_digest, exit_code, artifact_path, artifact_sha256, stdout, stderr, "
                "created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence.id,
                    evidence.obligation_id,
                    evidence.kind.value,
                    evidence.tool,
                    json.dumps(list(evidence.command)),
                    evidence.status.value,
                    evidence.subject_digest,
                    evidence.exit_code,
                    evidence.artifact_path,
                    evidence.artifact_sha256,
                    evidence.stdout,
                    evidence.stderr,
                    evidence.created_at,
                ),
            )

    def evidence(self, obligation_id: str | None = None) -> list[Evidence]:
        query = "SELECT * FROM evidence"
        params: tuple[str, ...] = ()
        if obligation_id is not None:
            query += " WHERE obligation_id = ?"
            params = (obligation_id,)
        query += " ORDER BY created_at DESC, id DESC"
        with self.connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            Evidence(
                id=row["id"],
                obligation_id=row["obligation_id"],
                kind=EvidenceKind(row["kind"]),
                tool=row["tool"],
                command=tuple(json.loads(row["command_json"])),
                status=EvidenceStatus(row["status"]),
                subject_digest=row["subject_digest"],
                exit_code=row["exit_code"],
                artifact_path=row["artifact_path"],
                artifact_sha256=row["artifact_sha256"],
                stdout=row["stdout"],
                stderr=row["stderr"],
                created_at=row["created_at"],
            )
            for row in rows
        ]
