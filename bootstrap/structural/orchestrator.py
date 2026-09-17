"""mkso-owned structural drafting: prepare, constrain, index, retain; never accept."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = ROOT / "bootstrap/baseline/deployment/implementor-runtime/deployment.json"
DEPLOYMENT_SHA256 = "248bcd3e51e8924fd31754274c368d35264e42dfbaef47ba0a0eac17cba1cf3f"
BROKER_SHA256 = "aeaf0bd7a08f89567665112f3e12cd3670d2fc642ec3572f0d2630ebad08e48d"
INDEXER_IMAGE = "sha256:b6ffc4b6164876715cb5a162346f84afe4789a105a559b03896a384b92c4f0bb"
PROTOC_PATH = "/usr/local/Cellar/protobuf/33.2/bin/protoc-33.2.0"
PROTOC_SHA256 = "0380cb775986f88987e441b239a651aa32db8cdcaf6ac7d6f2d3af046b750723"


def encode(value):
    """Encode public canonical ASCII JSON records."""
    # mkso:body:begin
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")
    # mkso:body:end


def read(path, limit):
    """Read only one explicit bounded public regular file without symlink following."""
    # mkso:body:begin
    if any(part == ".env" or part.startswith(".env.") for part in path.parts):
        raise ValueError("secret path is not public input")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError("invalid public artifact")
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        if len(raw) != before.st_size or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("public artifact changed")
        return raw
    # mkso:body:end


def write(path, raw):
    """Create exclusive owner-only public run artifacts and flush their bytes."""
    # mkso:body:begin
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    # mkso:body:end


def command(module, arguments):
    """Invoke an internal fixed module, without shell or inherited secrets."""
    # mkso:body:begin
    if module not in ("bootstrap.baseline.broker", "bootstrap.baseline.container_operator"):
        raise ValueError("unsupported internal operation")
    completed = subprocess.run(
        [sys.executable, "-E", "-s", "-B", "-m", module, *map(str, arguments)],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=1800,
    )
    if len(completed.stdout) > 2097152:
        raise ValueError("public result too large")
    value = json.loads(completed.stdout)
    if type(value) is not dict or value.get("authority") != "NONE":
        raise ValueError("invalid public result")
    return completed.returncode, value
    # mkso:body:end


def collect(state, result):
    """Locate the matching broker artifact and rederive source/index bindings."""
    # mkso:body:begin
    matches = []
    for directory in sorted((state / "drafts").iterdir()):
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("invalid draft directory")
        record_path = directory / "draft.json"
        if not record_path.exists():
            continue
        record = json.loads(read(record_path, 1048576))
        if record.get("result") != result:
            continue
        source = directory / "source"
        if source.is_symlink() or not source.is_dir():
            raise ValueError("invalid source directory")
        entries = []
        for path in sorted(source.iterdir()):
            raw = read(path, 262144)
            entries.append(
                {"path": path.name, "size": len(raw), "hash": hashlib.sha256(raw).hexdigest()}
            )
        if entries != record["source_entries"]:
            raise ValueError("candidate source changed")
        if hashlib.sha256(encode(entries)).hexdigest() != result["candidate_hash"]:
            raise ValueError("candidate identity changed")
        if (
            hashlib.sha256(read(directory / "index/index.scip", 16777216)).hexdigest()
            != result["index_hash"]
        ):
            raise ValueError("candidate index changed")
        matches.append(str(directory))
    if len(matches) != 1:
        raise ValueError("retained draft is ambiguous or absent")
    return matches[0]
    # mkso:body:end


def main():
    """Own preparation and the live constrained-worker lifecycle for one task."""
    # mkso:body:begin
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="One public scaffolded .py file")
    parser.add_argument("--function", required=True)
    parser.add_argument("--task", type=Path, required=True, help="Public UTF-8 task document")
    parser.add_argument(
        "--run-dir", type=Path, required=True, help="New operator-owned run directory"
    )
    parser.add_argument(
        "--predecessor-sha256", help="Declared prior draft; not an acceptance certificate"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        required=True,
        help="Authorize up to eight paid Terra requests for this structural draft",
    )
    args = parser.parse_args()
    report = {
        "schema_version": "mkso-structural-run/1",
        "authority": "NONE",
        "state": "UNAVAILABLE",
        "phase": "INPUT",
        "behavior_verified": False,
        "private_evaluation": False,
        "activated": False,
    }
    run = None
    try:
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}\.py", args.source.name):
            raise ValueError("unsupported source name")
        if args.task.suffix != ".md" or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", args.function):
            raise ValueError("unsupported task or function")
        if args.predecessor_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", args.predecessor_sha256
        ):
            raise ValueError("invalid predecessor")
        source = read(args.source, 262144)
        task = read(args.task, 65536)
        if not task.decode("utf-8").strip():
            raise ValueError("empty task")
        config_raw = read(DEPLOYMENT, 16384)
        if hashlib.sha256(config_raw).hexdigest() != DEPLOYMENT_SHA256:
            raise ValueError("deployment changed")
        config = json.loads(config_raw)
        if (
            hashlib.sha256(read(ROOT / "bootstrap/baseline/broker.py", 262144)).hexdigest()
            != BROKER_SHA256
        ):
            raise ValueError("broker changed")
        task_hash = hashlib.sha256(task).hexdigest()
        capsule = {
            "schema_version": "mkso-bootstrap-draft-capsule/1",
            "contract_hash": task_hash,
            "task_id": "structural-" + task_hash[:16],
            "predecessor_hash": args.predecessor_sha256,
            "slot_id": args.source.name + "." + args.function,
            "filename": args.source.name,
            "function": args.function,
            "sources": {args.source.name: base64.b64encode(source).decode("ascii")},
            "tools": {
                "docker_path": config["docker_path"],
                "docker_hash": config["docker_sha256"],
                "docker_host": config["docker_host"],
                "protoc_path": PROTOC_PATH,
                "protoc_hash": PROTOC_SHA256,
                "indexer_image": INDEXER_IMAGE,
            },
        }
        capsule_raw = encode(capsule)
        capsule_hash = hashlib.sha256(capsule_raw).hexdigest()
        target = args.run_dir.resolve()
        if any(part == ".env" or part.startswith(".env.") for part in target.parts):
            raise ValueError("invalid run path")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.mkdir(mode=0o700)
        run = target
        write(run / "task.md", task)
        write(run / "capsule.json", capsule_raw)
        report.update(
            {
                "phase": "PREPARE",
                "capsule_hash": capsule_hash,
                "task_sha256": task_hash,
                "deployment_sha256": DEPLOYMENT_SHA256,
                "orchestrator_sha256": hashlib.sha256(read(Path(__file__), 262144)).hexdigest(),
            }
        )
        write(run / "started.json", encode(report) + b"\n")
        print("mkso: preparing scaffold and direct SCIP", file=sys.stderr, flush=True)
        code, prepared = command(
            "bootstrap.baseline.broker",
            [
                "prepare",
                "--capsule",
                run / "capsule.json",
                "--capsule-hash",
                capsule_hash,
                "--state",
                run / "state",
            ],
        )
        if code != 0 or prepared.get("state") != "DRAFT_CAPSULE":
            raise ValueError("preparation unavailable")
        write(run / "prepared.json", encode(prepared) + b"\n")
        report["phase"] = "WORKER"
        print(
            "mkso: scaffold indexed; starting restricted Terra worker", file=sys.stderr, flush=True
        )
        code, worker = command(
            "bootstrap.baseline.container_operator",
            [
                "--deployment",
                DEPLOYMENT,
                "--deployment-sha256",
                DEPLOYMENT_SHA256,
                "--state",
                run / "state",
                "--capsule-hash",
                capsule_hash,
                "--task",
                run / "task.md",
                "--task-sha256",
                task_hash,
                "--model",
                "gpt-5.6-terra",
                "--output",
                run / "worker.json",
            ],
        )
        report["worker_state"] = worker.get("state", "UNAVAILABLE")
        if "provider_failure" in worker or "provider_request_number" in worker:
            category = worker.get("provider_failure")
            ordinal = worker.get("provider_request_number")
            if (
                type(category) is not str
                or category not in (
                    "UNKNOWN", "CHILD_UNAVAILABLE", "INPUT_INVALID", "TRANSPORT",
                    "TIMEOUT", "TLS", "HTTP_400", "HTTP_401", "HTTP_403",
                    "HTTP_429", "HTTP_404", "HTTP_OTHER_4XX", "HTTP_5XX",
                    "HTTP_UNEXPECTED_STATUS", "CONTENT_ENCODING",
                    "RESPONSE_TOO_LARGE", "RESPONSE_INVALID", "NONE",
                )
                or type(ordinal) is not int
                or not 1 <= ordinal <= 8
            ):
                raise ValueError("invalid provider reporting fields")
            report["provider_failure"] = category
            report["provider_request_number"] = ordinal
        if code != 0 or worker.get("state") != "STRUCTURALLY_ADMITTED_DRAFT":
            raise ValueError("worker did not produce a structurally admitted draft")
        if worker.get("cleanup_confirmed") is not True:
            raise ValueError("worker cleanup unavailable")
        report["phase"] = "RETAIN"
        result = worker["result"]
        if (
            result.get("capsule_hash") != capsule_hash
            or result.get("scaffold_hash") != prepared["scaffold_hash"]
        ):
            raise ValueError("draft binding differs")
        report["artifact_directory"] = collect(run / "state", result)
        report["result"] = result
        report["state"] = "STRUCTURALLY_ADMITTED_DRAFT"
        report["phase"] = "DONE"
    except Exception:
        report["state"] = "UNAVAILABLE"
    if run is not None:
        try:
            write(run / "result.json", encode(report) + b"\n")
        except Exception:
            report["state"] = "UNAVAILABLE"
            report["phase"] = "RECORD"
    print(encode(report).decode("ascii"))
    return 0 if report["state"] == "STRUCTURALLY_ADMITTED_DRAFT" else 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
