"""Command-line surface for planning, indexing, checking, and evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from mkso.domain import CheckResult, EvidenceKind, NodeStatus
from mkso.evaluation import Evaluator
from mkso.evidence import run_evidence
from mkso.exporting import snapshot
from mkso.manifest import apply_manifest
from mkso.modelcheck import check_certificate, load_certificate, load_model, prove
from mkso.scip import (
    ScipExpectation,
    ScipIndexerInvocation,
    load_contract_source_index_policy,
)
from mkso.scip_codec import ScipDecoder
from mkso.store import Store
from mkso.stubs import render_stubs


def _store() -> Store:
    return Store.discover(Path.cwd())


def _write_json(value: Any, output: Path | None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(rendered, end="")
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")


def _print_tree(result: CheckResult, indent: str = "") -> None:
    print(f"{indent}[{result.status.value.upper()}] {result.id}")
    for reason in result.reasons:
        print(f"{indent}  - {reason}")
    for child in result.children:
        _print_tree(child, indent + "  ")


def _cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    store = Store.initialize(root)
    print(f"initialized mkso at {store.database}")
    return 0


def _cmd_plan_apply(args: argparse.Namespace) -> int:
    store = _store()
    manifest = apply_manifest(store, Path(args.manifest))
    print(
        f"accepted plan {manifest.digest}: {len(manifest.work_items)} work items, "
        f"{len(manifest.obligations)} obligations, {len(manifest.bindings)} bindings"
    )
    return 0


def _cmd_stubs_render(args: argparse.Namespace) -> int:
    created = render_stubs(_store())
    for path in created:
        print(path)
    if not created:
        print("no Python stub files were required")
    return 0


def _cmd_index_scip(args: argparse.Namespace) -> int:
    store = _store()
    source_root = Path(args.source_root)
    if not source_root.is_absolute():
        source_root = store.project_root / source_root
    source_root = source_root.resolve()
    if source_root != store.project_root:
        raise ValueError("v1 requires --source-root to be the initialized project root")
    contract_path = Path(args.contract)
    source_index_policy = load_contract_source_index_policy(
        contract_path,
        project_root=store.project_root,
    )
    environment: dict[str, str] = {}
    for value in args.indexer_env:
        name, separator, setting = value.partition("=")
        if not separator or not name or name in environment:
            raise ValueError("--indexer-env must be a unique non-empty NAME=VALUE mapping")
        environment[name] = setting
    if "{output}" not in args.indexer_argument:
        raise ValueError("--indexer-argument must contain one exact {output} token")
    decoder = ScipDecoder(
        protoc_path=Path(args.protoc),
        expected_protoc_sha256=args.protoc_sha256,
        expected_protobuf_runtime_version=args.protobuf_runtime_version,
    )
    expectation = ScipExpectation(
        tool_name=args.tool_name,
        tool_version=args.tool_version,
        tool_arguments=tuple(args.tool_argument),
        project_root_uri=args.project_root_uri,
    )
    invocation = ScipIndexerInvocation(
        executable_path=Path(args.indexer),
        executable_sha256=args.indexer_sha256,
        arguments=tuple(args.indexer_argument),
        environment=tuple(sorted(environment.items())),
        input_files=source_index_policy.input_paths,
        indexed_files=source_index_policy.indexed_paths,
        timeout_seconds=args.indexer_timeout,
    )
    receipt = store.admit_scip_index(
        decoder,
        expectation,
        invocation,
        contract_path,
    )
    print(
        f"accepted SCIP admission {receipt.admission_hash}: "
        f"{receipt.document_count} documents, "
        f"{receipt.symbol_count} symbols, {receipt.occurrence_count} occurrences, "
        f"{receipt.subject_count} contract subjects, "
        f"{receipt.resolved_bindings} planned bindings"
    )
    return 0


def _cmd_evidence_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    evidence = run_evidence(
        _store(),
        obligation_id=args.obligation_id,
        kind=EvidenceKind(args.kind),
        tool=args.tool,
        command=command,
        artifact=None if args.artifact is None else Path(args.artifact),
        timeout_seconds=args.timeout,
    )
    print(
        json.dumps(
            {
                "id": evidence.id,
                "obligation_id": evidence.obligation_id,
                "kind": evidence.kind.value,
                "status": evidence.status.value,
                "exit_code": evidence.exit_code,
                "subject_digest": evidence.subject_digest,
                "artifact_sha256": evidence.artifact_sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if evidence.status.value == "passed" else 1


def _cmd_check(args: argparse.Namespace) -> int:
    result = Evaluator(_store()).check_project()
    if args.json:
        _write_json(result.to_dict(), None)
    else:
        _print_tree(result)
    return 0 if result.status is NodeStatus.VERIFIED else 1


def _cmd_model_prove(args: argparse.Namespace) -> int:
    model = load_model(Path(args.model))
    certificate = prove(model, args.property_id)
    _write_json(certificate, Path(args.output))
    print(f"{certificate['result']}: {args.property_id}; certificate={args.output}")
    return 0 if certificate["result"] == "proved" else 1


def _cmd_model_check(args: argparse.Namespace) -> int:
    model = load_model(Path(args.model))
    certificate = load_certificate(Path(args.certificate))
    valid, message = check_certificate(model, certificate)
    result = certificate.get("result")
    print(f"{'valid' if valid else 'invalid'} {result} certificate: {message}")
    if not valid:
        return 1
    if args.expect is not None and result != args.expect:
        print(f"expected {args.expect}, got {result}", file=sys.stderr)
        return 1
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    value = snapshot(_store())
    _write_json(value, None if args.output is None else Path(args.output))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mkso",
        description="Proof-carrying requirements and implementation graph",
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    init = subparsers.add_parser("init", help="initialize state in a project")
    init.add_argument("path", nargs="?", default=".")
    init.set_defaults(handler=_cmd_init)

    plan = subparsers.add_parser("plan", help="manage the accepted plan")
    plan_sub = plan.add_subparsers(dest="plan_command", required=True)
    plan_apply = plan_sub.add_parser("apply", help="validate and atomically accept JSON plan")
    plan_apply.add_argument("manifest")
    plan_apply.set_defaults(handler=_cmd_plan_apply)

    stubs = subparsers.add_parser("stubs", help="materialize planned source stubs")
    stubs_sub = stubs.add_subparsers(dest="stubs_command", required=True)
    stubs_render = stubs_sub.add_parser("render")
    stubs_render.set_defaults(handler=_cmd_stubs_render)

    index = subparsers.add_parser("index", help="index source symbols")
    index_sub = index.add_subparsers(dest="index_command", required=True)
    index_scip = index_sub.add_parser("scip", help="validate and ingest a standard .scip index")
    index_scip.add_argument("--source-root", required=True)
    index_scip.add_argument("--contract", required=True)
    index_scip.add_argument("--protoc", required=True)
    index_scip.add_argument("--protoc-sha256", required=True)
    index_scip.add_argument("--protobuf-runtime-version", required=True)
    index_scip.add_argument("--tool-name", required=True)
    index_scip.add_argument("--tool-version", required=True)
    index_scip.add_argument("--tool-argument", action="append", default=[])
    index_scip.add_argument("--project-root-uri", required=True)
    index_scip.add_argument("--indexer", required=True)
    index_scip.add_argument("--indexer-sha256", required=True)
    index_scip.add_argument("--indexer-argument", action="append", required=True)
    index_scip.add_argument("--indexer-env", action="append", default=[])
    index_scip.add_argument("--indexer-timeout", type=float, required=True)
    index_scip.set_defaults(handler=_cmd_index_scip)

    evidence = subparsers.add_parser("evidence", help="run and record checker evidence")
    evidence_sub = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_run = evidence_sub.add_parser("run")
    evidence_run.add_argument("obligation_id")
    evidence_run.add_argument(
        "--kind",
        required=True,
        choices=[value.value for value in EvidenceKind],
    )
    evidence_run.add_argument("--tool", required=True)
    evidence_run.add_argument("--artifact")
    evidence_run.add_argument("--timeout", type=float, default=300.0)
    evidence_run.set_defaults(handler=_cmd_evidence_run, command=())

    check = subparsers.add_parser("check", help="evaluate every obligation and composition gate")
    check.add_argument("--json", action="store_true")
    check.set_defaults(handler=_cmd_check)

    model = subparsers.add_parser("model", help="finite-state all-path proof backend")
    model_sub = model.add_subparsers(dest="model_command", required=True)
    model_prove = model_sub.add_parser("prove")
    model_prove.add_argument("model")
    model_prove.add_argument("property_id")
    model_prove.add_argument("--output", "-o", required=True)
    model_prove.set_defaults(handler=_cmd_model_prove)
    model_check = model_sub.add_parser("check")
    model_check.add_argument("model")
    model_check.add_argument("certificate")
    model_check.add_argument("--expect", choices=("proved", "disproved"))
    model_check.set_defaults(handler=_cmd_model_check)

    export = subparsers.add_parser("export", help="export graph, SCIP records, and evidence")
    export.add_argument("--output", "-o")
    export.set_defaults(handler=_cmd_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    checker_command: list[str] | None = None
    if raw_args[:2] == ["evidence", "run"] and "--" in raw_args:
        separator = raw_args.index("--")
        checker_command = raw_args[separator + 1 :]
        raw_args = raw_args[:separator]
    args = parser.parse_args(raw_args)
    if checker_command is not None:
        args.command = checker_command
    try:
        return int(args.handler(args))
    except (FileNotFoundError, KeyError, ValueError, sqlite_error()) as exc:
        parser.exit(2, f"error: {exc}\n")


def sqlite_error() -> type[Exception]:
    # Imported lazily so `mkso --help` stays as small as possible.
    import sqlite3

    return sqlite3.Error
