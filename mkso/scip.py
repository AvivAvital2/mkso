"""Fail-closed structural validation for standard SCIP indexes."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from google.protobuf.message import Message

from mkso.hashing import hash_object, sha256_bytes, sha256_file
from mkso.scip_codec import ScipCodecIdentity, ScipDecoder, field

DEFINITION_ROLE = 0x01
KNOWN_SYMBOL_ROLES = 0x7F
UTF8 = 1
SUPPORTED_POSITION_ENCODINGS = {1, 2, 3}


@dataclass(frozen=True, order=True, slots=True)
class SourcePosition:
    line: int
    character: int


@dataclass(frozen=True, slots=True)
class SourceRange:
    start: SourcePosition
    end: SourcePosition

    def contains(self, other: SourceRange) -> bool:
        return self.start <= other.start and other.end <= self.end


@dataclass(frozen=True, slots=True)
class ScipExpectation:
    tool_name: str
    tool_version: str
    tool_arguments: tuple[str, ...]
    project_root_uri: str


@dataclass(frozen=True, slots=True)
class ScipDocument:
    relative_path: str
    language: str
    position_encoding: int
    source_hash: str


@dataclass(frozen=True, slots=True)
class ScipOccurrence:
    document_path: str
    ordinal: int
    symbol: str
    symbol_key: str
    symbol_roles: int
    source_range: SourceRange
    enclosing_range: SourceRange | None

    @property
    def is_definition(self) -> bool:
        return bool(self.symbol_roles & DEFINITION_ROLE)


@dataclass(frozen=True, slots=True)
class ScipRelationship:
    source_symbol_key: str
    target_symbol_key: str
    is_reference: bool
    is_implementation: bool
    is_type_definition: bool
    is_definition: bool


@dataclass(frozen=True, slots=True)
class ScipSymbol:
    symbol_key: str
    symbol: str
    document_path: str | None
    external: bool
    kind: int
    display_name: str
    signature_language: str
    signature_text: str
    enclosing_symbol: str
    relationships: tuple[ScipRelationship, ...]


@dataclass(frozen=True, slots=True)
class ScipIndex:
    index_hash: str
    codec_identity: ScipCodecIdentity
    tool_name: str
    tool_version: str
    tool_arguments: tuple[str, ...]
    project_root_uri: str
    text_document_encoding: int
    documents: tuple[ScipDocument, ...]
    symbols: tuple[ScipSymbol, ...]
    occurrences: tuple[ScipOccurrence, ...]

    @property
    def interpretation_hash(self) -> str:
        return hash_object(
            {
                "index_hash": self.index_hash,
                "codec_identity": asdict(self.codec_identity),
                "producer": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "arguments": list(self.tool_arguments),
                    "project_root_uri": self.project_root_uri,
                    "text_document_encoding": self.text_document_encoding,
                },
            }
        )


@dataclass(frozen=True, slots=True)
class ScipIndexerInvocation:
    executable_path: Path
    executable_sha256: str
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    input_files: tuple[str, ...]
    indexed_files: tuple[str, ...]
    timeout_seconds: float


@dataclass(frozen=True, slots=True)
class ScipGenerationAttestation:
    executable_path: str
    executable_sha256: str
    arguments: tuple[str, ...]
    environment_hash: str
    input_manifest: tuple[tuple[str, str], ...]
    indexed_files: tuple[str, ...]
    stdin_hash: str | None
    index_hash: str
    stdout_hash: str
    stderr_hash: str
    exit_code: int


def scip_ingestion_hash(index: ScipIndex, generation: ScipGenerationAttestation) -> str:
    return hash_object(
        {
            "interpretation_hash": index.interpretation_hash,
            "generation": asdict(generation),
        }
    )


@dataclass(frozen=True, slots=True)
class SubjectBinding:
    subject_id: str
    symbol: str
    document_path: str
    definition_range: SourceRange
    enclosing_range: SourceRange | None
    source_hash: str


@dataclass(frozen=True, slots=True)
class ContractSubjectRelationship:
    source_subject_id: str
    kind: str
    target_subject_id: str
    required: bool


@dataclass(frozen=True, slots=True)
class ContractSourceIndexPolicy:
    tool_requirement_id: str
    mode: str
    indexed_paths: tuple[str, ...]
    input_paths: tuple[str, ...]
    language_ids: tuple[tuple[str, str], ...]
    inter_subject_relationship_policy: str
    unmappable_structure_effect: str


@dataclass(frozen=True, slots=True)
class ContractScipAdmission:
    contract_path: str
    contract_sha256: str
    subject_bindings: tuple[SubjectBinding, ...]
    subject_relationships: tuple[ContractSubjectRelationship, ...]
    source_index_policy: ContractSourceIndexPolicy


def scip_admission_hash(
    ingestion_hash: str,
    contract: ContractScipAdmission,
) -> str:
    return hash_object(
        {
            "ingestion_hash": ingestion_hash,
            "contract_path": contract.contract_path,
            "contract_sha256": contract.contract_sha256,
            "subject_bindings": [asdict(binding) for binding in contract.subject_bindings],
            "subject_relationships": [
                asdict(relationship) for relationship in contract.subject_relationships
            ],
            "source_index_policy": asdict(contract.source_index_policy),
        }
    )


class ScipValidationError(ValueError):
    """One or more required structural facts could not be established."""

    def __init__(self, errors: list[str] | tuple[str, ...]) -> None:
        self.errors = tuple(errors)
        super().__init__("SCIP validation failed:\n- " + "\n- ".join(self.errors))


def _symbol_key(symbol: str, document_path: str | None) -> str:
    if symbol.startswith("local "):
        if document_path is None:
            raise ScipValidationError([f"external symbol cannot be local: {symbol}"])
        return f"{document_path}\x00{symbol}"
    return symbol


def _canonical_document_path(value: str) -> str:
    parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if path.as_posix() != value:
        raise ValueError("must be a canonical relative POSIX path")
    return value


def _source_lines(text: str) -> list[str]:
    pieces = text.splitlines(keepends=True)
    if not pieces:
        return [""]
    lines = [piece.rstrip("\r\n") for piece in pieces]
    if pieces[-1].endswith(("\n", "\r")):
        lines.append("")
    return lines


def _valid_character_offsets(line: str, encoding: int) -> set[int]:
    offsets = {0}
    current = 0
    for character in line:
        if encoding == 1:
            current += len(character.encode("utf-8"))
        elif encoding == 2:
            current += len(character.encode("utf-16-le")) // 2
        elif encoding == 3:
            current += 1
        else:  # guarded by document validation
            return set()
        offsets.add(current)
    return offsets


def _range_from_values(values: tuple[int, ...], location: str) -> SourceRange:
    if len(values) == 3:
        start_line, start_character, end_character = values
        end_line = start_line
    elif len(values) == 4:
        start_line, start_character, end_line, end_character = values
    else:
        raise ValueError(f"{location} must have exactly three or four integers")
    if min(values) < 0:
        raise ValueError(f"{location} cannot contain negative values")
    result = SourceRange(
        start=SourcePosition(start_line, start_character),
        end=SourcePosition(end_line, end_character),
    )
    if result.end < result.start:
        raise ValueError(f"{location} end precedes its start")
    return result


def _typed_range(message: Message, group: str, location: str) -> SourceRange | None:
    selected = message.WhichOneof(group)
    if selected is None:
        return None
    value = field(message, selected)
    if selected.startswith("single_line"):
        values = (
            int(field(value, "line")),
            int(field(value, "start_character")),
            int(field(value, "end_character")),
        )
    else:
        values = (
            int(field(value, "start_line")),
            int(field(value, "start_character")),
            int(field(value, "end_line")),
            int(field(value, "end_character")),
        )
    return _range_from_values(values, location)


def _occurrence_range(message: Message, *, enclosing: bool, location: str) -> SourceRange | None:
    group = "typed_enclosing_range" if enclosing else "typed_range"
    legacy_name = "enclosing_range" if enclosing else "range"
    typed = _typed_range(message, group, location)
    legacy_values = tuple(int(value) for value in field(message, legacy_name))
    legacy = _range_from_values(legacy_values, location) if legacy_values else None
    if typed is not None and legacy is not None and typed != legacy:
        raise ValueError(f"{location} typed and deprecated encodings disagree")
    return typed or legacy


def _validate_range_bounds(
    source_range: SourceRange,
    *,
    lines: list[str],
    encoding: int,
    location: str,
) -> None:
    for label, position in (("start", source_range.start), ("end", source_range.end)):
        if position.line >= len(lines):
            raise ValueError(f"{location} {label} line is outside the current source")
        if position.character not in _valid_character_offsets(lines[position.line], encoding):
            raise ValueError(f"{location} {label} character is not a valid code-unit boundary")


def _read_source(source_root: Path, relative_path: str) -> tuple[str, str]:
    root = source_root.resolve()
    path = root.joinpath(*relative_path.split("/"))
    cursor = root
    for part in relative_path.split("/"):
        cursor = cursor / part
        if cursor.is_symlink():
            raise ValueError("document path contains a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("document does not resolve to a file inside the source root") from exc
    if not resolved.is_file():
        raise ValueError("document is not a regular file")
    try:
        payload = resolved.read_bytes()
        text = payload.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"document is not readable UTF-8 source: {exc}") from exc
    return text, sha256_bytes(payload)


def _relationship(
    message: Message,
    *,
    source_key: str,
    document_path: str | None,
    location: str,
) -> ScipRelationship:
    target = str(field(message, "symbol"))
    flags = (
        bool(field(message, "is_reference")),
        bool(field(message, "is_implementation")),
        bool(field(message, "is_type_definition")),
        bool(field(message, "is_definition")),
    )
    if not target:
        raise ValueError(f"{location}.symbol is empty")
    if not any(flags):
        raise ValueError(f"{location} has no relationship role")
    return ScipRelationship(
        source_symbol_key=source_key,
        target_symbol_key=_symbol_key(target, document_path),
        is_reference=flags[0],
        is_implementation=flags[1],
        is_type_definition=flags[2],
        is_definition=flags[3],
    )


def _validate_scip_message(
    decoder: ScipDecoder,
    index: Message,
    index_hash: str,
    source_root: Path,
    expectation: ScipExpectation,
) -> ScipIndex:
    """Validate one directly decoded standard-SCIP message."""
    errors: list[str] = []
    if not index.HasField("metadata"):
        raise ScipValidationError(["metadata is absent"])
    metadata = field(index, "metadata")
    tool_info = field(metadata, "tool_info")
    actual_tool = (
        str(field(tool_info, "name")),
        str(field(tool_info, "version")),
        tuple(str(value) for value in field(tool_info, "arguments")),
    )
    expected_tool = (
        expectation.tool_name,
        expectation.tool_version,
        expectation.tool_arguments,
    )
    if actual_tool != expected_tool:
        errors.append(f"producer identity differs: expected {expected_tool!r}, got {actual_tool!r}")
    project_root_uri = str(field(metadata, "project_root"))
    if project_root_uri != expectation.project_root_uri:
        errors.append(
            f"metadata.project_root differs: expected {expectation.project_root_uri!r}, "
            f"got {project_root_uri!r}"
        )
    text_encoding = int(field(metadata, "text_document_encoding"))
    if text_encoding != UTF8:
        errors.append("v1 requires metadata.text_document_encoding=UTF8")

    raw_documents = list(field(index, "documents"))
    if not raw_documents:
        errors.append("index contains no documents")
    documents: list[ScipDocument] = []
    occurrences: list[ScipOccurrence] = []
    symbols: list[ScipSymbol] = []
    seen_documents: set[str] = set()
    global_symbol_locations: dict[str, str] = {}
    symbol_keys: set[str] = set()

    for document_index, document in enumerate(raw_documents):
        prefix = f"documents[{document_index}]"
        relative_path = str(field(document, "relative_path"))
        try:
            relative_path = _canonical_document_path(relative_path)
        except ValueError as exc:
            errors.append(f"{prefix}.relative_path {exc}")
            continue
        if relative_path in seen_documents:
            errors.append(f"{prefix}.relative_path duplicates {relative_path}")
            continue
        seen_documents.add(relative_path)
        language = str(field(document, "language"))
        if not language:
            errors.append(f"{prefix}.language is empty")
        position_encoding = int(field(document, "position_encoding"))
        if position_encoding not in SUPPORTED_POSITION_ENCODINGS:
            errors.append(f"{prefix}.position_encoding is unspecified or unsupported")
        try:
            source_text, source_hash = _read_source(source_root, relative_path)
        except ValueError as exc:
            errors.append(f"{prefix}: {exc}")
            continue
        embedded_text = str(field(document, "text"))
        if embedded_text and embedded_text != source_text:
            errors.append(f"{prefix}.text differs from the current source bytes")
        documents.append(ScipDocument(relative_path, language, position_encoding, source_hash))
        lines = _source_lines(source_text)

        for symbol_index, information in enumerate(field(document, "symbols")):
            location = f"{prefix}.symbols[{symbol_index}]"
            symbol = str(field(information, "symbol"))
            if not symbol:
                errors.append(f"{location}.symbol is empty")
                continue
            key = _symbol_key(symbol, relative_path)
            if key in symbol_keys:
                errors.append(f"{location}.symbol duplicates {symbol!r}")
                continue
            if not symbol.startswith("local ") and symbol in global_symbol_locations:
                errors.append(
                    f"{location}.symbol was already defined in {global_symbol_locations[symbol]}"
                )
                continue
            symbol_keys.add(key)
            if not symbol.startswith("local "):
                global_symbol_locations[symbol] = relative_path
            signature = field(information, "signature_documentation")
            relationships: list[ScipRelationship] = []
            for relation_index, relation in enumerate(field(information, "relationships")):
                try:
                    relationships.append(
                        _relationship(
                            relation,
                            source_key=key,
                            document_path=relative_path,
                            location=f"{location}.relationships[{relation_index}]",
                        )
                    )
                except (ScipValidationError, ValueError) as exc:
                    errors.append(str(exc))
            symbols.append(
                ScipSymbol(
                    symbol_key=key,
                    symbol=symbol,
                    document_path=relative_path,
                    external=False,
                    kind=int(field(information, "kind")),
                    display_name=str(field(information, "display_name")),
                    signature_language=str(field(signature, "language")),
                    signature_text=str(field(signature, "text")),
                    enclosing_symbol=str(field(information, "enclosing_symbol")),
                    relationships=tuple(relationships),
                )
            )

        for occurrence_index, occurrence in enumerate(field(document, "occurrences")):
            location = f"{prefix}.occurrences[{occurrence_index}]"
            try:
                source_range = _occurrence_range(
                    occurrence, enclosing=False, location=f"{location}.range"
                )
                if source_range is None:
                    raise ValueError(f"{location}.range is absent")
                if position_encoding in SUPPORTED_POSITION_ENCODINGS:
                    _validate_range_bounds(
                        source_range,
                        lines=lines,
                        encoding=position_encoding,
                        location=f"{location}.range",
                    )
                enclosing_range = _occurrence_range(
                    occurrence, enclosing=True, location=f"{location}.enclosing_range"
                )
                if enclosing_range is not None:
                    if position_encoding in SUPPORTED_POSITION_ENCODINGS:
                        _validate_range_bounds(
                            enclosing_range,
                            lines=lines,
                            encoding=position_encoding,
                            location=f"{location}.enclosing_range",
                        )
                    if not enclosing_range.contains(source_range):
                        raise ValueError(
                            f"{location}.enclosing_range does not contain its occurrence"
                        )
                symbol = str(field(occurrence, "symbol"))
                roles = int(field(occurrence, "symbol_roles"))
                if roles & ~KNOWN_SYMBOL_ROLES:
                    raise ValueError(f"{location}.symbol_roles contains unknown bits")
                if not symbol and roles:
                    raise ValueError(f"{location} has symbol roles but no symbol")
                occurrences.append(
                    ScipOccurrence(
                        document_path=relative_path,
                        ordinal=occurrence_index,
                        symbol=symbol,
                        symbol_key=_symbol_key(symbol, relative_path) if symbol else "",
                        symbol_roles=roles,
                        source_range=source_range,
                        enclosing_range=enclosing_range,
                    )
                )
            except (ScipValidationError, ValueError) as exc:
                errors.append(str(exc))

    for external_index, information in enumerate(field(index, "external_symbols")):
        location = f"external_symbols[{external_index}]"
        symbol = str(field(information, "symbol"))
        if not symbol:
            errors.append(f"{location}.symbol is empty")
            continue
        try:
            key = _symbol_key(symbol, None)
        except ScipValidationError as exc:
            errors.extend(exc.errors)
            continue
        if key in symbol_keys:
            errors.append(f"{location}.symbol duplicates {symbol!r}")
            continue
        symbol_keys.add(key)
        signature = field(information, "signature_documentation")
        relationships: list[ScipRelationship] = []
        for relation_index, relation in enumerate(field(information, "relationships")):
            try:
                relationships.append(
                    _relationship(
                        relation,
                        source_key=key,
                        document_path=None,
                        location=f"{location}.relationships[{relation_index}]",
                    )
                )
            except (ScipValidationError, ValueError) as exc:
                errors.append(str(exc))
        symbols.append(
            ScipSymbol(
                symbol_key=key,
                symbol=symbol,
                document_path=None,
                external=True,
                kind=int(field(information, "kind")),
                display_name=str(field(information, "display_name")),
                signature_language=str(field(signature, "language")),
                signature_text=str(field(signature, "text")),
                enclosing_symbol=str(field(information, "enclosing_symbol")),
                relationships=tuple(relationships),
            )
        )

    for occurrence in occurrences:
        if occurrence.is_definition:
            matching = [
                symbol
                for symbol in symbols
                if symbol.symbol_key == occurrence.symbol_key
                and symbol.document_path == occurrence.document_path
            ]
            if len(matching) != 1:
                errors.append(
                    f"{occurrence.document_path}.occurrences[{occurrence.ordinal}] definition "
                    "does not resolve to exactly one document SymbolInformation"
                )
    if errors:
        raise ScipValidationError(errors)
    return ScipIndex(
        index_hash=index_hash,
        codec_identity=decoder.identity,
        tool_name=actual_tool[0],
        tool_version=actual_tool[1],
        tool_arguments=actual_tool[2],
        project_root_uri=project_root_uri,
        text_document_encoding=text_encoding,
        documents=tuple(documents),
        symbols=tuple(symbols),
        occurrences=tuple(occurrences),
    )


def load_scip_bytes(
    decoder: ScipDecoder,
    payload: bytes,
    source_root: Path,
    expectation: ScipExpectation,
) -> ScipIndex:
    """Decode and validate raw standard-SCIP bytes as one operation."""
    index = decoder.decode_bytes(payload)
    return _validate_scip_message(
        decoder,
        index,
        sha256_bytes(payload),
        source_root,
        expectation,
    )


def load_scip_index(
    decoder: ScipDecoder,
    index_path: Path,
    source_root: Path,
    expectation: ScipExpectation,
) -> ScipIndex:
    """Read, decode, and validate a standard-SCIP file atomically."""
    try:
        payload = index_path.read_bytes()
    except OSError as exc:
        raise ScipValidationError([f"unable to read SCIP index {index_path}: {exc}"]) from exc
    return load_scip_bytes(decoder, payload, source_root, expectation)


def _input_manifest(source_root: Path, input_files: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    if not input_files:
        raise ScipValidationError(["indexer input manifest is empty"])
    if tuple(sorted(set(input_files))) != input_files:
        raise ScipValidationError(["indexer input files must be unique and sorted"])
    values: list[tuple[str, str]] = []
    for offset, value in enumerate(input_files):
        try:
            path = _canonical_document_path(value)
            _, source_hash = _read_source(source_root, path)
        except ValueError as exc:
            raise ScipValidationError([f"input_files[{offset}] {exc}"]) from exc
        values.append((path, source_hash))
    return tuple(values)


def run_scip_indexer(
    decoder: ScipDecoder,
    source_root: Path,
    expectation: ScipExpectation,
    invocation: ScipIndexerInvocation,
    *,
    stdin_payload: bytes | None = None,
) -> tuple[ScipIndex, ScipGenerationAttestation, bytes]:
    """Run an exact external indexer and bind its output to unchanged source bytes."""
    executable = invocation.executable_path.resolve()
    if not executable.is_file():
        raise ScipValidationError([f"indexer executable does not exist: {executable}"])
    executable_hash = sha256_file(executable)
    if executable_hash != invocation.executable_sha256:
        raise ScipValidationError(
            [
                "indexer executable digest mismatch: "
                f"expected {invocation.executable_sha256}, got {executable_hash}"
            ]
        )
    if invocation.timeout_seconds <= 0:
        raise ScipValidationError(["indexer timeout must be positive"])
    if tuple(sorted(invocation.environment)) != invocation.environment:
        raise ScipValidationError(["indexer environment must be sorted"])
    environment_keys = [name for name, _ in invocation.environment]
    if len(set(environment_keys)) != len(environment_keys) or any(
        not name for name in environment_keys
    ):
        raise ScipValidationError(["indexer environment keys must be unique and non-empty"])

    root = source_root.resolve()
    if not root.is_dir():
        raise ScipValidationError([f"source root does not exist: {root}"])
    before = _input_manifest(root, invocation.input_files)
    if not invocation.indexed_files:
        raise ScipValidationError(["expected SCIP document set is empty"])
    if tuple(sorted(set(invocation.indexed_files))) != invocation.indexed_files:
        raise ScipValidationError(["expected SCIP documents must be unique and sorted"])
    if not set(invocation.indexed_files).issubset(invocation.input_files):
        raise ScipValidationError(["every expected SCIP document must be an indexer input"])
    output_tokens = sum(value == "{output}" for value in invocation.arguments)
    if output_tokens not in {0, 1}:
        raise ScipValidationError(["indexer arguments may contain {output} at most once"])
    for value in invocation.arguments:
        if ("{" in value or "}" in value) and value not in {"{output}", "{source_root}"}:
            raise ScipValidationError([f"unsupported indexer argument placeholder: {value}"])

    with tempfile.TemporaryDirectory(prefix="mkso-scip-index-") as directory:
        output_path = Path(directory) / "index.scip"
        arguments = tuple(
            str(output_path)
            if value == "{output}"
            else (str(root) if value == "{source_root}" else value)
            for value in invocation.arguments
        )
        try:
            result = subprocess.run(
                [str(executable), *arguments],
                cwd=root,
                env=dict(invocation.environment),
                input=stdin_payload,
                capture_output=True,
                timeout=invocation.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ScipValidationError([f"indexer execution error: {exc}"]) from exc
        if result.returncode != 0:
            raise ScipValidationError(
                [
                    f"indexer exited {result.returncode}; "
                    f"stdout_sha256={sha256_bytes(result.stdout)}; "
                    f"stderr_sha256={sha256_bytes(result.stderr)}"
                ]
            )
        if output_tokens:
            try:
                index_payload = output_path.read_bytes()
            except OSError as exc:
                raise ScipValidationError(
                    [f"indexer did not create its declared output: {exc}"]
                ) from exc
        else:
            index_payload = result.stdout
        if not index_payload:
            raise ScipValidationError(["indexer produced an empty SCIP index"])
        output_path.write_bytes(index_payload)

        after = _input_manifest(root, invocation.input_files)
        if after != before:
            raise ScipValidationError(["source manifest changed during SCIP indexing"])
        index = load_scip_index(decoder, output_path, root, expectation)

    indexed_files = tuple(sorted(document.relative_path for document in index.documents))
    if indexed_files != invocation.indexed_files:
        raise ScipValidationError(
            [
                "indexed document set differs from the frozen source manifest: "
                f"expected {invocation.indexed_files!r}, got {indexed_files!r}"
            ]
        )
    attestation = ScipGenerationAttestation(
        executable_path=str(executable),
        executable_sha256=executable_hash,
        arguments=invocation.arguments,
        environment_hash=hash_object(list(invocation.environment)),
        input_manifest=before,
        indexed_files=invocation.indexed_files,
        stdin_hash=None if stdin_payload is None else sha256_bytes(stdin_payload),
        index_hash=index.index_hash,
        stdout_hash=sha256_bytes(result.stdout),
        stderr_hash=sha256_bytes(result.stderr),
        exit_code=result.returncode,
    )
    return index, attestation, index_payload


def _load_contract(text: str, path: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ScipValidationError([f"unable to read contract {path}: {exc}"]) from exc
    if not isinstance(value, dict) or not isinstance(value.get("subjects"), list):
        raise ScipValidationError(["contract must contain a subjects array"])
    return value


def load_contract_document(
    contract_path: Path,
    *,
    project_root: Path,
) -> tuple[str, str, str, dict[str, Any]]:
    """Read one canonical in-project contract with duplicate-key rejection."""
    root = project_root.resolve()
    candidate = contract_path if contract_path.is_absolute() else root / contract_path
    try:
        relative_path = _canonical_document_path(candidate.relative_to(root).as_posix())
        contract_text, contract_sha256 = _read_source(root, relative_path)
    except ValueError as exc:
        raise ScipValidationError([f"contract path {exc}"]) from exc
    return (
        relative_path,
        contract_text,
        contract_sha256,
        _load_contract(contract_text, relative_path),
    )


def _parse_source_index_policy(contract: dict[str, Any]) -> ContractSourceIndexPolicy:
    raw = contract.get("source_index_policy")
    if not isinstance(raw, dict):
        raise ScipValidationError(["contract source_index_policy must be an object"])
    required_fields = {
        "tool_requirement_id",
        "mode",
        "indexed_paths",
        "input_paths",
        "language_ids",
        "inter_subject_relationship_policy",
        "unmappable_structure_effect",
    }
    if set(raw) != required_fields:
        raise ScipValidationError(
            ["contract source_index_policy fields do not match the frozen policy shape"]
        )
    if raw["mode"] != "full_target":
        raise ScipValidationError(["contract source_index_policy mode must be full_target"])
    if raw["inter_subject_relationship_policy"] != "closed_world_declared_edges":
        raise ScipValidationError(
            ["contract source_index_policy must require closed-world declared edges"]
        )
    if raw["unmappable_structure_effect"] != "CONTRACT_VIOLATION_REQUIRES_AMENDMENT":
        raise ScipValidationError(
            ["contract source_index_policy has a fail-open unmappable-structure effect"]
        )
    tool_requirement_id = raw["tool_requirement_id"]
    if not isinstance(tool_requirement_id, str) or not tool_requirement_id:
        raise ScipValidationError(
            ["contract source_index_policy tool_requirement_id must be non-empty"]
        )
    raw_tools = contract.get("tool_requirements")
    if not isinstance(raw_tools, list):
        raise ScipValidationError(["contract tool_requirements must be an array"])
    tool_ids: set[str] = set()
    for offset, tool in enumerate(raw_tools):
        if not isinstance(tool, dict) or not isinstance(tool.get("id"), str) or not tool["id"]:
            raise ScipValidationError([f"contract tool_requirements[{offset}] has no string id"])
        tool_id = tool["id"]
        if tool_id in tool_ids:
            raise ScipValidationError([f"contract tool_requirements duplicates {tool_id}"])
        tool_ids.add(tool_id)
    if tool_requirement_id not in tool_ids:
        raise ScipValidationError(
            [f"contract source_index_policy refers to unknown tool {tool_requirement_id}"]
        )

    def paths(field_name: str) -> tuple[str, ...]:
        values = raw[field_name]
        if not isinstance(values, list) or not values:
            raise ScipValidationError(
                [f"contract source_index_policy {field_name} must be a non-empty array"]
            )
        parsed: list[str] = []
        for offset, value in enumerate(values):
            if not isinstance(value, str):
                raise ScipValidationError(
                    [f"contract source_index_policy {field_name}[{offset}] is not a string"]
                )
            try:
                parsed.append(_canonical_document_path(value))
            except ValueError as exc:
                raise ScipValidationError(
                    [f"contract source_index_policy {field_name}[{offset}] {exc}"]
                ) from exc
        result = tuple(parsed)
        if result != tuple(sorted(set(result))):
            raise ScipValidationError(
                [f"contract source_index_policy {field_name} must be unique and sorted"]
            )
        return result

    indexed_paths = paths("indexed_paths")
    input_paths = paths("input_paths")
    if not set(indexed_paths).issubset(input_paths):
        raise ScipValidationError(
            ["every contract indexed path must be present in its indexer input scope"]
        )

    raw_languages = raw["language_ids"]
    if not isinstance(raw_languages, list) or not raw_languages:
        raise ScipValidationError(
            ["contract source_index_policy language_ids must be a non-empty array"]
        )
    languages: list[tuple[str, str]] = []
    for offset, mapping in enumerate(raw_languages):
        if not isinstance(mapping, dict) or set(mapping) != {
            "contract_language",
            "scip_language",
        }:
            raise ScipValidationError(
                [f"contract source_index_policy language_ids[{offset}] is malformed"]
            )
        contract_language = mapping["contract_language"]
        scip_language = mapping["scip_language"]
        if not all(
            isinstance(value, str) and value for value in (contract_language, scip_language)
        ):
            raise ScipValidationError(
                [f"contract source_index_policy language_ids[{offset}] is incomplete"]
            )
        languages.append((contract_language, scip_language))
    language_ids = tuple(languages)
    if language_ids != tuple(sorted(language_ids)) or len(
        {contract_language for contract_language, _ in language_ids}
    ) != len(language_ids):
        raise ScipValidationError(
            ["contract source_index_policy language_ids must have unique sorted contract IDs"]
        )
    return ContractSourceIndexPolicy(
        tool_requirement_id=tool_requirement_id,
        mode="full_target",
        indexed_paths=indexed_paths,
        input_paths=input_paths,
        language_ids=language_ids,
        inter_subject_relationship_policy="closed_world_declared_edges",
        unmappable_structure_effect="CONTRACT_VIOLATION_REQUIRES_AMENDMENT",
    )


def load_contract_source_index_policy(
    contract_path: Path,
    *,
    project_root: Path,
) -> ContractSourceIndexPolicy:
    """Load the contract-owned indexer scope without accepting caller overrides."""
    _, _, _, contract = load_contract_document(contract_path, project_root=project_root)
    return _parse_source_index_policy(contract)


def verify_contract_subjects(
    index: ScipIndex,
    contract_path: Path,
    *,
    project_root: Path,
) -> ContractScipAdmission:
    """Bind exact frozen subject selectors and their declared structural edges."""
    relative_path, _, contract_sha256, contract = load_contract_document(
        contract_path,
        project_root=project_root,
    )
    source_index_policy = _parse_source_index_policy(contract)
    language_ids = dict(source_index_policy.language_ids)
    errors: list[str] = []
    raw_subjects = contract["subjects"]
    subjects_by_id: dict[str, dict[str, Any]] = {}
    for offset, value in enumerate(raw_subjects):
        if not isinstance(value, dict) or not isinstance(value.get("id"), str):
            errors.append(f"subjects[{offset}] has no string id")
            continue
        subject_id = value["id"]
        if subject_id in subjects_by_id:
            errors.append(f"duplicate subject id {subject_id!r}")
        subjects_by_id[subject_id] = value

    documents = {document.relative_path: document for document in index.documents}
    bindings: dict[str, SubjectBinding] = {}
    managed_paths: set[str] = set()
    scip_paths: set[str] = set()
    for subject_id, subject in subjects_by_id.items():
        binding = subject.get("binding")
        location = subject.get("location")
        if not isinstance(binding, dict) or not isinstance(location, dict):
            errors.append(f"{subject_id}: missing subject binding or source location")
            continue
        family = binding.get("family")
        document_path = location.get("path")
        if not isinstance(document_path, str) or not document_path:
            errors.append(f"{subject_id}: incomplete source path")
            continue
        if family == "managed_artifact":
            managed_paths.add(document_path)
            continue
        if family != "scip":
            errors.append(f"{subject_id}: unsupported subject binding family {family!r}")
            continue
        scip = binding.get("selector")
        if not isinstance(scip, dict):
            errors.append(f"{subject_id}: missing SCIP selector")
            continue
        scip_paths.add(document_path)
        expected_symbol = scip.get("expected_symbol")
        contract_language = subject.get("language")
        if not all(
            isinstance(value, str) and value
            for value in (expected_symbol, document_path, contract_language)
        ):
            errors.append(f"{subject_id}: incomplete symbol, path, or language selector")
            continue
        if expected_symbol.startswith("local "):
            errors.append(f"{subject_id}: contract subjects cannot use document-local symbols")
            continue
        document = documents.get(document_path)
        if document is None:
            errors.append(f"{subject_id}: indexed document is absent: {document_path}")
            continue
        expected_language = language_ids.get(contract_language)
        if expected_language is None:
            errors.append(
                f"{subject_id}: no frozen SCIP language mapping for {contract_language!r}"
            )
        elif document.language != expected_language:
            errors.append(
                f"{subject_id}: expected SCIP language {expected_language!r}, "
                f"got {document.language!r}"
            )
        definitions = [
            occurrence
            for occurrence in index.occurrences
            if occurrence.document_path == document_path
            and occurrence.symbol == expected_symbol
            and occurrence.is_definition
        ]
        infos = [
            symbol
            for symbol in index.symbols
            if symbol.symbol == expected_symbol
            and symbol.document_path == document_path
            and not symbol.external
        ]
        if len(definitions) != 1 or len(infos) != 1:
            errors.append(
                f"{subject_id}: expected one definition and one document SymbolInformation "
                f"for {expected_symbol!r}, found {len(definitions)} and {len(infos)}"
            )
            continue
        definition = definitions[0]
        bindings[subject_id] = SubjectBinding(
            subject_id=subject_id,
            symbol=expected_symbol,
            document_path=document_path,
            definition_range=definition.source_range,
            enclosing_range=definition.enclosing_range,
            source_hash=document.source_hash,
        )

    indexed_paths = set(source_index_policy.indexed_paths)
    for path in sorted(scip_paths - indexed_paths):
        errors.append(f"SCIP-bound subject path is absent from indexed_paths: {path}")
    for path in sorted(managed_paths & indexed_paths):
        errors.append(f"managed-artifact subject path appears in indexed_paths: {path}")

    selector_owners: dict[tuple[str, str], str] = {}
    for subject_id, binding in bindings.items():
        selector = (binding.document_path, binding.symbol)
        previous = selector_owners.get(selector)
        if previous is not None:
            errors.append(
                f"{subject_id} and {previous} bind the same SCIP subject "
                f"{binding.document_path}:{binding.symbol}"
            )
        else:
            selector_owners[selector] = subject_id

    if len(bindings) > 1:
        for subject_id, binding in bindings.items():
            if binding.enclosing_range is None:
                errors.append(
                    f"{subject_id}: closed-world inter-subject reference validation "
                    "requires a definition enclosing range"
                )

    relationship_flags = {
        "relationship_reference": "is_reference",
        "implementation": "is_implementation",
        "type_definition": "is_type_definition",
        "definition": "is_definition",
    }
    supported_relationships = {"reference", *relationship_flags}
    declared: dict[tuple[str, str, str], ContractSubjectRelationship] = {}
    for subject_id, subject in subjects_by_id.items():
        binding = subject.get("binding")
        if not isinstance(binding, dict) or binding.get("family") != "scip":
            continue
        scip = binding.get("selector")
        if not isinstance(scip, dict):
            continue
        relationships = scip.get("expected_relationships")
        if not isinstance(relationships, list):
            errors.append(f"{subject_id}: expected_relationships must be an array")
            continue
        for offset, relationship in enumerate(relationships):
            location = f"{subject_id}.relationships[{offset}]"
            if not isinstance(relationship, dict):
                errors.append(f"{location} is not an object")
                continue
            kind = relationship.get("kind")
            target_id = relationship.get("target_subject_id")
            required = relationship.get("required", True)
            if kind not in supported_relationships:
                errors.append(f"{subject_id}: unsupported SCIP relationship kind {kind!r}")
                continue
            if not isinstance(target_id, str) or target_id not in bindings:
                errors.append(f"{location} target is not structurally bound")
                continue
            if not isinstance(required, bool):
                errors.append(f"{location}.required must be boolean")
                continue
            edge = ContractSubjectRelationship(subject_id, kind, target_id, required)
            key = (subject_id, kind, target_id)
            if key in declared:
                errors.append(f"{location} duplicates the declared inter-subject edge")
                continue
            declared[key] = edge

    observed: set[tuple[str, str, str]] = set()
    subject_by_symbol = {binding.symbol: subject_id for subject_id, binding in bindings.items()}
    for occurrence in index.occurrences:
        target_id = subject_by_symbol.get(occurrence.symbol)
        if target_id is None or occurrence.is_definition:
            continue
        candidates = [
            (subject_id, binding)
            for subject_id, binding in bindings.items()
            if binding.document_path == occurrence.document_path
            and binding.enclosing_range is not None
            and binding.enclosing_range.contains(occurrence.source_range)
        ]
        minimal = [
            candidate
            for candidate in candidates
            if not any(
                other[0] != candidate[0]
                and candidate[1].enclosing_range != other[1].enclosing_range
                and candidate[1].enclosing_range.contains(other[1].enclosing_range)
                for other in candidates
            )
        ]
        if len(minimal) > 1:
            owners = ", ".join(sorted(subject_id for subject_id, _ in minimal))
            errors.append(
                f"reference occurrence {occurrence.document_path}:{occurrence.ordinal} "
                f"has ambiguous contract-subject owners: {owners}"
            )
        elif minimal:
            observed.add((minimal[0][0], "reference", target_id))

    for source_id, binding in bindings.items():
        infos = [
            symbol
            for symbol in index.symbols
            if symbol.symbol == binding.symbol and symbol.document_path == binding.document_path
        ]
        for information in infos:
            for relationship in information.relationships:
                target_id = subject_by_symbol.get(relationship.target_symbol_key)
                if target_id is None:
                    continue
                for kind, flag in relationship_flags.items():
                    if getattr(relationship, flag):
                        observed.add((source_id, kind, target_id))

    for key, relationship in declared.items():
        if relationship.required and key not in observed:
            errors.append(
                f"{relationship.source_subject_id}: required {relationship.kind} edge to "
                f"{relationship.target_subject_id} is absent"
            )
    for source_id, kind, target_id in sorted(observed - set(declared)):
        errors.append(
            f"{source_id}: observed undeclared {kind} edge to {target_id}; "
            "the implementation departs from the frozen contract"
        )

    if errors:
        raise ScipValidationError(errors)
    return ContractScipAdmission(
        contract_path=relative_path,
        contract_sha256=contract_sha256,
        subject_bindings=tuple(bindings[subject_id] for subject_id in sorted(bindings)),
        subject_relationships=tuple(declared[key] for key in sorted(declared)),
        source_index_policy=source_index_policy,
    )
