"""Operator-owned direct API bridge: public capsule and draft submission only."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import resource
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, suppress
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BROKER_HASH = "aeaf0bd7a08f89567665112f3e12cd3670d2fc642ec3572f0d2630ebad08e48d"
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_WIRE = 2_097_152
MAX_RESPONSE = 1_048_576
INSTRUCTIONS = (
    "Implement the supplied public task inside its existing marked body slot. "
    "Use public to obtain the scaffold, then submit canonical base64 of only the "
    "replacement body, indented four spaces and ending in LF. You may revise "
    "structurally rejected drafts. A draft is not tested, accepted or activated."
)


def _require(condition):
    """Reject unsupported public/configuration/provider input without diagnostics."""
    # mkso:body:begin
    if not condition:
        raise ValueError("bridge input unavailable or outside capability")
    # mkso:body:end


def _encode(value):
    """Serialize bounded protocol JSON, never executable content."""
    # mkso:body:begin
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    _require(len(raw) <= MAX_WIRE)
    return raw
    # mkso:body:end


def _pairs(items):
    """Reject duplicate JSON object members."""
    # mkso:body:begin
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result
    # mkso:body:end


def _decode(raw):
    """Decode bounded JSON without duplicate or nonfinite values."""
    # mkso:body:begin
    _require(len(raw) <= MAX_WIRE)
    value = json.loads(raw, object_pairs_hook=_pairs)
    _encode(value)
    return value
    # mkso:body:end


def _read(path, limit):
    """Read bounded regular public operator input without following symlinks."""
    # mkso:body:begin
    _require(not any(part == ".env" or part.startswith(".env.") for part in path.parts))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        _require(before.st_size <= limit)
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        _require(len(raw) == before.st_size <= limit)
        _require(
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        )
        return raw
    # mkso:body:end


def _identity():
    """Bind bridge, audited broker, installed framework and Python executable."""
    # mkso:body:begin
    paths = [
        Path(__file__).resolve(),
        ROOT / "bootstrap/baseline/broker.py",
        *(ROOT / "mkso").rglob("*.py"),
        ROOT / "mkso/_schema/scip.proto",
    ]
    entries = []
    for path in sorted(paths):
        raw = _read(path, MAX_WIRE)
        digest = hashlib.sha256(raw).hexdigest()
        if path == ROOT / "bootstrap/baseline/broker.py":
            _require(digest == BROKER_HASH)
        entries.append({"path": path.relative_to(ROOT).as_posix(), "sha256": digest})
    entries.append(
        {
            "path": "operator-python-executable",
            "sha256": hashlib.sha256(_read(Path(sys.executable).resolve(), 134217728)).hexdigest(),
        }
    )
    return {"sha256": hashlib.sha256(_encode(entries)).hexdigest(), "files": entries}
    # mkso:body:end


def _tools():
    """Return only strict public and body-only submit function schemas."""
    # mkso:body:begin
    return [
        {
            "type": "function",
            "name": "public",
            "description": "Read the installed public source capsule and task slot.",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        },
        {
            "type": "function",
            "name": "submit",
            "description": "Submit only canonical base64 of the indented replacement body.",
            "strict": True,
            "parameters": {
                "type": "object",
                "properties": {"body_base64": {"type": "string"}},
                "required": ["body_base64"],
                "additionalProperties": False,
            },
        },
    ]
    # mkso:body:end


def _credential(env_file):
    """Load one owner-only dotenv credential without exporting or disclosing it."""
    # mkso:body:begin
    ambient = os.environ.pop("OPENAI_API_KEY", "")
    path = (ROOT / ".env" if env_file is None else env_file).absolute()
    _require(path.resolve() == path)
    _require(path.name == ".env" or path.name.startswith(".env."))
    _require(path.name != ".env.example")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        _require(env_file is None)
        key = ambient
    else:
        with os.fdopen(descriptor, "rb") as handle:
            _require(not ambient)
            before = os.fstat(handle.fileno())
            _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
            _require(
                before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) in (0o400, 0o600)
            )
            _require(before.st_size <= 8192)
            raw = handle.read(8193)
            after = os.fstat(handle.fileno())
            _require(len(raw) == before.st_size <= 8192)
            _require(
                (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            )
        assignments = []
        for line in raw.decode("ascii").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, separator, value = line.partition("=")
            _require(separator == "=" and name.strip() == "OPENAI_API_KEY")
            value = value.strip()
            if len(value) >= 2 and value[0] in ("'", '"') and value[-1] == value[0]:
                value = value[1:-1]
            assignments.append(value)
        _require(len(assignments) == 1)
        key = assignments[0]
    _require(type(key) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", key))
    return key
    # mkso:body:end


def _secret_free(raw, key):
    """Reject known secret representations before public or temporary-file sinks."""
    # mkso:body:begin
    secret = key.encode("ascii")
    _require(bool(secret) and secret not in raw and base64.b64encode(secret) not in raw)
    # mkso:body:end


def _child(argv, payload, environment, timeout, limit, secret=None):
    """Operator-only bounded subprocess with private outputs and group cleanup."""
    # mkso:body:begin
    _require(len(payload) <= MAX_WIRE)
    with (
        ExitStack() as handles,
        tempfile.TemporaryFile() as input_file,
        tempfile.TemporaryFile() as output,
        tempfile.TemporaryFile() as errors,
    ):
        inherited = ()
        environment = dict(environment)
        _require("OPENAI_API_KEY" not in environment and "MKSO_API_KEY_FD" not in environment)
        if secret is not None:
            _secret_free(payload, secret)
            _secret_free(_encode(argv), secret)
            _secret_free(_encode(environment), secret)
            secret_bytes = secret.encode("ascii")
            read_fd, write_fd = os.pipe()
            reader = handles.enter_context(os.fdopen(read_fd, "rb"))
            with os.fdopen(write_fd, "wb") as writer:
                _require(0 < len(secret_bytes) <= os.fpathconf(write_fd, "PC_PIPE_BUF"))
                writer.write(secret_bytes)
            inherited = (reader.fileno(),)
            environment["MKSO_API_KEY_FD"] = str(reader.fileno())
        input_file.write(payload)
        input_file.seek(0)
        process = subprocess.Popen(
            argv,
            cwd=ROOT,
            env=environment,
            stdin=input_file,
            stdout=output,
            stderr=errors,
            start_new_session=True,
            close_fds=True,
            pass_fds=inherited,
        )
        deadline = time.monotonic() + timeout
        try:
            while process.poll() is None:
                _require(time.monotonic() < deadline)
                _require(os.fstat(output.fileno()).st_size <= limit)
                _require(os.fstat(errors.fileno()).st_size <= 65536)
                time.sleep(0.02)
            _require(time.monotonic() < deadline)
            _require(os.fstat(output.fileno()).st_size <= limit)
            _require(os.fstat(errors.fileno()).st_size == 0)
            output.seek(0)
            return process.returncode, output.read(limit + 1)
        finally:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
    # mkso:body:end


def _provider_worker():
    """Trusted transport child; fixed TLS endpoint, bounded input/output, no tools."""
    # mkso:body:begin
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        raw = sys.stdin.buffer.read(MAX_WIRE + 1)
        _decode(raw)
        descriptor = os.environ.pop("MKSO_API_KEY_FD")
        _require(re.fullmatch(r"[0-9]{1,10}", descriptor) and int(descriptor) > 2)
        with os.fdopen(int(descriptor), "rb") as credential:
            key = credential.read(4097).decode("ascii")
        _require(re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", key))
        _secret_free(raw, key)
        _secret_free(_encode(_decode(raw)), key)
        connection = http.client.HTTPSConnection(
            "api.openai.com", 443, timeout=30, context=ssl.create_default_context()
        )
        try:
            connection.request(
                "POST",
                "/v1/responses",
                body=raw,
                headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            _require(response.status == 200)
            _require(response.getheader("Content-Encoding", "identity") == "identity")
            content = response.read(MAX_RESPONSE + 1)
            _require(len(content) <= MAX_RESPONSE)
            _secret_free(content, key)
            _secret_free(_encode(_decode(content)), key)
            sys.stdout.buffer.write(content)
            sys.stdout.buffer.flush()
            return 0
        finally:
            connection.close()
    except Exception:
        return 1
    # mkso:body:end


def _provider(model, history, key):
    """Construct stateless, bounded requests outside model control."""
    # mkso:body:begin
    payload = _encode(
        {
            "model": model,
            "instructions": INSTRUCTIONS,
            "input": history,
            "tools": _tools(),
            "tool_choice": "auto",
            "parallel_tool_calls": False,
            "store": False,
            "stream": False,
            "max_output_tokens": 4096,
            "include": ["reasoning.encrypted_content"],
            "truncation": "disabled",
        }
    )
    code, raw = _child(
        [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--provider-worker"],
        payload,
        {"PATH": "/usr/bin:/bin"},
        120,
        MAX_RESPONSE,
        secret=key,
    )
    _require(code == 0)
    _secret_free(raw, key)
    return _decode(raw)
    # mkso:body:end


def _broker(state, capsule_hash, request):
    """Invoke the existing broker request CLI with no provider credentials."""
    # mkso:body:begin
    payload = _encode(request) + b"\n"
    _require(len(payload) <= 131072)
    code, raw = _child(
        [
            sys.executable,
            "-E",
            "-s",
            "-B",
            "-m",
            "bootstrap.baseline.broker",
            "request",
            "--state",
            str(state),
            "--capsule-hash",
            capsule_hash,
        ],
        payload,
        {"PATH": "/usr/bin:/bin"},
        240,
        MAX_RESPONSE,
    )
    value = _decode(raw)
    _require(type(value) is dict and code in (0, 1))
    _require(
        (code == 0) == (value.get("state") in ("DRAFT_CAPSULE", "STRUCTURALLY_ADMITTED_DRAFT"))
    )
    return value
    # mkso:body:end


def _projection(value, capsule_hash, public):
    """Release only exact broker public fields and correctly bound draft results."""
    # mkso:body:begin
    _require(type(value) is dict and value.get("authority") == "NONE")
    if value.get("state") in ("DRAFT_REJECTED", "DRAFT_UNAVAILABLE"):
        _require(set(value) == {"state", "authority"})
        return value
    bindings = {
        "capsule_hash",
        "scaffold_hash",
        "contract_hash",
        "task_id",
        "predecessor_hash",
        "slot_id",
    }
    _require(value.get("capsule_hash") == capsule_hash)
    for name in ("capsule_hash", "scaffold_hash", "contract_hash"):
        _require(type(value.get(name)) is str and HEX.fullmatch(value[name]))
    _require(
        value.get("predecessor_hash") is None
        or (type(value["predecessor_hash"]) is str and HEX.fullmatch(value["predecessor_hash"]))
    )
    for name in ("task_id", "slot_id"):
        _require(
            type(value.get(name)) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", value[name])
        )
    if public is None:
        _require(set(value) == bindings | {"state", "authority", "filename", "function", "sources"})
        _require(value["state"] == "DRAFT_CAPSULE")
        _require(type(value["sources"]) is dict and 1 <= len(value["sources"]) <= 8)
        _require(type(value["filename"]) is str and value["filename"] in value["sources"])
        _require(
            type(value["function"]) is str
            and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value["function"])
        )
        for name, encoded in value["sources"].items():
            _require(re.fullmatch(r"[a-z][a-z0-9_]{0,63}\.py", name))
            _require(type(encoded) is str and len(encoded) <= 349528)
            source = base64.b64decode(encoded, validate=True)
            _require(base64.b64encode(source).decode() == encoded)
        return value
    _require(
        set(value)
        == bindings | {"state", "authority", "broker_hash", "candidate_hash", "index_hash"}
    )
    _require(
        value["state"] == "STRUCTURALLY_ADMITTED_DRAFT" and value["broker_hash"] == BROKER_HASH
    )
    _require(all(value[name] == public[name] for name in bindings))
    for name in ("candidate_hash", "index_hash"):
        _require(type(value[name]) is str and HEX.fullmatch(value[name]))
    return value
    # mkso:body:end


def _call(response, model, seen):
    """Validate the whole model output before permitting one tool dispatch."""
    # mkso:body:begin
    _require(type(response) is dict and response.get("model") == model)
    _require(response.get("status") == "completed" and response.get("error") is None)
    output = response.get("output")
    _require(type(output) is list and len(output) <= 128)
    calls = []
    for item in output:
        _require(
            type(item) is dict and item.get("type") in ("function_call", "message", "reasoning")
        )
        if item["type"] == "function_call":
            _require(set(item) <= {"type", "id", "call_id", "name", "arguments", "status"})
            _require(item.get("name") in ("public", "submit"))
            _require(
                type(item.get("call_id")) is str
                and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", item["call_id"])
            )
            _require(item["call_id"] not in seen)
            _require(item.get("status", "completed") == "completed")
            _require(type(item.get("arguments")) is str and len(item["arguments"]) <= 131072)
            arguments = _decode(item["arguments"])
            _require(type(arguments) is dict)
            _require(set(arguments) == (set() if item["name"] == "public" else {"body_base64"}))
            calls.append(item)
        elif item["type"] == "message":
            _require(item.get("role") == "assistant")
            _require(type(item.get("content")) is list)
            _require(
                all(
                    type(part) is dict and part.get("type") == "output_text"
                    for part in item["content"]
                )
            )
        else:
            _require(
                set(item) <= {"type", "id", "summary", "content", "encrypted_content", "status"}
            )
    _require(len(calls) <= 1)
    if not calls:
        return None
    seen.add(calls[0]["call_id"])
    return calls[0]
    # mkso:body:end


def _dispatch(call, state, capsule_hash, public):
    """Dispatch only public or submit; derive all authority bindings locally."""
    # mkso:body:begin
    arguments = _decode(call["arguments"])
    _require(type(arguments) is dict)
    if call["name"] == "public":
        _require(not arguments)
        result = _projection(
            _broker(state, capsule_hash, {"operation": "public"}), capsule_hash, None
        )
        _require(result == public)
        return result
    _require(call["name"] == "submit" and set(arguments) == {"body_base64"})
    encoded = arguments["body_base64"]
    _require(type(encoded) is str and len(encoded) <= 87384)
    body = base64.b64decode(encoded, validate=True)
    _require(0 < len(body) <= 65536 and body.endswith(b"\n"))
    _require(base64.b64encode(body).decode() == encoded)
    request = {
        "operation": "submit",
        "body_base64": encoded,
        "capsule_hash": capsule_hash,
        "scaffold_hash": public["scaffold_hash"],
        "slot_id": public["slot_id"],
    }
    return _projection(_broker(state, capsule_hash, request), capsule_hash, public)
    # mkso:body:end


def _run(args, task, key, identity):
    """Fresh bounded model context; stop on broker draft success, never model claims."""
    # mkso:body:begin
    _secret_free(task.encode("utf-8"), key)
    _require(_identity() == identity)
    public = _projection(
        _broker(args.state, args.capsule_hash, {"operation": "public"}), args.capsule_hash, None
    )
    _require(public["state"] == "DRAFT_CAPSULE")
    _secret_free(_encode(public), key)
    for source in public["sources"].values():
        _secret_free(base64.b64decode(source, validate=True), key)
    _require(_identity() == identity)
    history = [{"role": "user", "content": _encode({"task": task, "capsule": public}).decode()}]
    seen = set()
    for _ in range(8):
        _require(_identity() == identity)
        response = _provider(args.model, history, key)
        call = _call(response, args.model, seen)
        _require(_identity() == identity)
        if call is None:
            return {"state": "NO_DRAFT", "authority": "NONE"}
        if call["name"] == "submit":
            arguments = _decode(call["arguments"])
            _secret_free(base64.b64decode(arguments["body_base64"], validate=True), key)
        result = _dispatch(call, args.state, args.capsule_hash, public)
        _secret_free(_encode(result), key)
        _require(_identity() == identity)
        if result["state"] in ("STRUCTURALLY_ADMITTED_DRAFT", "DRAFT_UNAVAILABLE"):
            return result
        history.extend(response["output"])
        history.append(
            {
                "type": "function_call_output",
                "call_id": call["call_id"],
                "output": _encode(result).decode(),
            }
        )
        _encode(history)
    return {"state": "TURN_LIMIT", "authority": "NONE"}
    # mkso:body:end


def main():
    """Operator configuration, exact task identity and exclusive safe terminal report."""
    # mkso:body:begin
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        print('{"state":"BRIDGE_UNAVAILABLE","authority":"NONE"}')
        return 1
    if sys.argv[1:] == ["--provider-worker"]:
        return _provider_worker()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--capsule-hash", required=True)
    parser.add_argument("--task", type=Path, required=True)
    parser.add_argument("--task-sha256", required=True)
    parser.add_argument(
        "--env-file", type=Path, help="operator-only dotenv file; default: repository .env"
    )
    parser.add_argument(
        "--model", required=True, help="exact provider model ID; no implicit default"
    )
    parser.add_argument("--output", type=Path, required=True, help="new operator-only report path")
    args = parser.parse_args()
    report = {
        "schema_version": "mkso-bootstrap-direct-bridge-run/1",
        "authority": "NONE",
        "state": "BRIDGE_UNAVAILABLE",
        "qualified_isolation": False,
    }
    try:
        _require(HEX.fullmatch(args.capsule_hash) and HEX.fullmatch(args.task_sha256))
        _require(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}", args.model))
        _require(args.state.is_absolute() and args.state.resolve() == args.state)
        info = args.state.stat()
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )
        task_raw = _read(args.task, 65536)
        _require(hashlib.sha256(task_raw).hexdigest() == args.task_sha256)
        task = task_raw.decode("utf-8")
        _require(bool(task.strip()))
        key = _credential(args.env_file)
        identity = _identity()
        report.update(
            {
                "implementation": identity,
                "task_sha256": args.task_sha256,
                "capsule_hash": args.capsule_hash,
                "model": args.model,
            }
        )
        descriptor = os.open(
            args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            _secret_free(_encode(report), key)
            handle.write(_encode(report) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            try:
                result = _run(args, task, key, identity)
                _require(_identity() == identity)
                report["result"] = result
                report["state"] = result["state"]
            except Exception:
                report["state"] = "BRIDGE_UNAVAILABLE"
            _secret_free(_encode(report), key)
            handle.seek(0)
            handle.write(_encode(report) + b"\n")
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        report = {"state": "BRIDGE_UNAVAILABLE", "authority": "NONE"}
    sys.stdout.buffer.write(_encode(report) + b"\n")
    sys.stdout.buffer.flush()
    return 0 if report["state"] == "STRUCTURALLY_ADMITTED_DRAFT" else 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
