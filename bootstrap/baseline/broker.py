"""Draft-only constrained submission; conventional seed, never acceptance.

Operator state and launch configuration must be outside the implementor's
capabilities. This module cannot revoke a host-capable agent's existing tools.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mkso.scip import ScipExpectation, load_scip_bytes
from mkso.scip_codec import ScipDecoder

_BEGIN = b"    # mkso:implementation:begin\n"
_END = b"    # mkso:implementation:end\n"
_MAX_REQUEST = 131072


class DraftRejected(ValueError):
    """The request does not fit the operator-installed draft capability."""


class DraftUnavailable(RuntimeError):
    """Required public infrastructure is unavailable; no draft is admitted."""


def _require(condition, message):
    """Reject unbound or unsupported public input."""
    # mkso:body:begin
    if not condition:
        raise DraftRejected(message)
    # mkso:body:end


def _canonical(value):
    """Encode the deliberately restricted canonical JSON domain."""
    # mkso:body:begin
    if value is None or type(value) is bool:
        pass
    elif type(value) is int:
        _require(abs(value) <= 2**53 - 1, "integer outside public domain")
    elif type(value) is str:
        _require(value.isascii(), "non-ASCII public metadata")
    elif type(value) is list:
        for child in value:
            _canonical(child)
    elif type(value) is dict:
        for key, child in value.items():
            _require(type(key) is str and key.isascii(), "invalid member name")
            _canonical(child)
    else:
        raise DraftRejected("unsupported public value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    # mkso:body:end


def _load(raw):
    """Reject duplicates, noncanonical JSON and unsupported value types."""
    # mkso:body:begin
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs)
        _require(_canonical(value) == raw, "public JSON must be canonical")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise DraftRejected("invalid canonical public JSON") from None
    # mkso:body:end


def _pairs(items):
    """Decode object members without silently overwriting duplicates."""
    # mkso:body:begin
    result = {}
    for key, value in items:
        _require(key not in result, "duplicate JSON member")
        result[key] = value
    return result
    # mkso:body:end


def _digest(raw):
    """Bind exact artifact bytes."""
    # mkso:body:begin
    return hashlib.sha256(raw).hexdigest()
    # mkso:body:end


def _read(path, limit):
    """Read one bounded, regular, single-link operator artifact without symlinks."""
    # mkso:body:begin
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "non-regular artifact")
        _require(before.st_size <= limit, "artifact exceeds limit")
        raw = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        _require(len(raw) == before.st_size <= limit, "artifact size changed")
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise DraftUnavailable("artifact changed while reading")
        return raw
    # mkso:body:end


def _write(path, raw):
    """Create a new artifact exclusively and flush its bytes."""
    # mkso:body:begin
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    # mkso:body:end


def _capsule(raw):
    """Validate the exact operator capsule and decode its complete baseline."""
    # mkso:body:begin
    value = _load(raw)
    _require(
        type(value) is dict
        and set(value)
        == {
            "schema_version",
            "contract_hash",
            "task_id",
            "predecessor_hash",
            "slot_id",
            "filename",
            "function",
            "sources",
            "tools",
        },
        "capsule fields differ",
    )
    _require(value["schema_version"] == "mkso-bootstrap-draft-capsule/1", "capsule version")
    for name in ("contract_hash", "predecessor_hash"):
        item = value[name]
        if name == "predecessor_hash" and item is None:
            continue
        _require(type(item) is str and re.fullmatch(r"[0-9a-f]{64}", item), "invalid binding")
    for name in ("task_id", "slot_id"):
        _require(
            type(value[name]) is str and re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", value[name]),
            "invalid task or slot",
        )
    _require(
        type(value["function"]) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value["function"]),
        "invalid function",
    )
    sources = value["sources"]
    _require(type(sources) is dict and 1 <= len(sources) <= 8, "source count")
    decoded = {}
    for filename, encoded in sources.items():
        _require(re.fullmatch(r"[a-z][a-z0-9_]{0,63}\.py", filename), "source name")
        _require(type(encoded) is str and len(encoded) <= 349528, "source encoding size")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise DraftRejected("source encoding") from None
        _require(base64.b64encode(content).decode() == encoded, "source encoding not canonical")
        _require(0 < len(content) <= 262144, "source size")
        _require(
            re.search(rb"coding[:=]\s*([-\w.]+)", b"\n".join(content.split(b"\n")[:2])) is None,
            "source encoding declarations are outside this UTF-8-only capsule",
        )
        content.decode("utf-8")
        compile(content, filename, "exec", dont_inherit=True)
        decoded[filename] = content
    _require(sum(map(len, decoded.values())) <= 262144, "source tree size")
    _require(type(value["filename"]) is str and value["filename"] in decoded, "slot source absent")
    _structure(decoded[value["filename"]], value["function"])
    tools = value["tools"]
    _require(
        type(tools) is dict
        and set(tools)
        == {
            "docker_path",
            "docker_hash",
            "docker_host",
            "protoc_path",
            "protoc_hash",
            "indexer_image",
        },
        "tool fields differ",
    )
    _require(
        type(tools["indexer_image"]) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", tools["indexer_image"]),
        "indexer must be pinned",
    )
    for name in ("docker", "protoc"):
        path, digest = tools[name + "_path"], tools[name + "_hash"]
        _require(
            type(path) is str and Path(path).is_absolute() and str(Path(path).resolve()) == path,
            "tool path must be absolute and resolved",
        )
        _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "tool hash")
    host = tools["docker_host"]
    _require(
        type(host) is str
        and host.startswith("unix:///")
        and "\x00" not in host
        and "\n" not in host,
        "operator Docker endpoint must be local Unix",
    )
    decoded["environment.json"] = b"[]"
    decoded["pyrightconfig.json"] = _canonical({"include": ["*.py"], "pythonVersion": "3.12"})
    return value, decoded
    # mkso:body:end


def _structure(raw, function):
    """Bind all syntax outside the marked function-body region."""
    # mkso:body:begin
    _require(raw.count(_BEGIN) == raw.count(_END) == 1, "ambiguous body slot")
    prefix, rest = raw.split(_BEGIN)
    body, suffix = rest.split(_END)
    _require(
        not any(character in raw for character in (b"\r", b"\f", b"\x00")),
        "unsupported source control character",
    )
    begin = prefix.count(b"\n") + 1
    end = (prefix + _BEGIN + body).count(b"\n") + 1
    module = ast.parse(raw.decode("utf-8"))
    functions = [
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == function
    ]
    _require(len(functions) == 1, "slot needs one top-level function")
    node = functions[0]
    _require(node.lineno < begin < end, "slot outside function")
    before, inside, after = [], [], []
    for statement in node.body:
        if statement.end_lineno < begin:
            before.append(statement)
        elif statement.lineno > end:
            after.append(statement)
        elif begin < statement.lineno <= statement.end_lineno < end:
            inside.append(statement)
        else:
            raise DraftRejected("syntax crosses a slot boundary")
    _require(bool(inside), "slot has no complete function-body statement")
    node.body = [*before, ast.Pass(), *after]
    return ast.dump(module, include_attributes=False), prefix, suffix
    # mkso:body:end


def _manifest(root):
    """Hash the bounded flat source tree, rejecting unexpected entries."""
    # mkso:body:begin
    _require(root.is_dir() and not root.is_symlink(), "invalid source directory")
    paths = sorted(root.iterdir())
    _require(1 <= len(paths) <= 10, "source entry count")
    entries = []
    for path in paths:
        _require(re.fullmatch(r"[a-z][a-z0-9_]*\.(py|json)", path.name), "source entry name")
        raw = _read(path, 262144)
        entries.append({"path": path.name, "size": len(raw), "hash": _digest(raw)})
    _require(sum(entry["size"] for entry in entries) <= 327680, "source tree exceeds limit")
    return entries
    # mkso:body:end


def _native(arguments, timeout):
    """Bound operator-selected public native work and suppress its diagnostics."""
    # mkso:body:begin
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            env={
                "PATH": "/usr/bin:/bin",
                "LC_ALL": "C",
                "TZ": "UTC",
                "HOME": "/nonexistent",
                "DOCKER_CONFIG": "/nonexistent",
            },
        )
        try:
            while process.poll() is None:
                if time.monotonic() >= deadline:
                    raise DraftUnavailable("public tool deadline")
                if os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > 1048576:
                    raise DraftUnavailable("public tool output limit")
                time.sleep(0.02)
            if (
                time.monotonic() >= deadline
                or os.fstat(output.fileno()).st_size + os.fstat(errors.fileno()).st_size > 1048576
            ):
                raise DraftUnavailable("public tool bounds exceeded")
            return process.returncode
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
    # mkso:body:end


def _index(source, destination, tools):
    """Generate direct SCIP in an isolated pinned container and bind unchanged source."""
    # mkso:body:begin
    for name in ("docker", "protoc"):
        if _digest(_read(Path(tools[name + "_path"]), 268435456)) != tools[name + "_hash"]:
            raise DraftUnavailable("public tool identity changed")
    before = _manifest(source)
    destination.mkdir(mode=0o777)
    destination.chmod(0o777)
    for path in (source, destination):
        _require(
            path.is_absolute() and path.as_posix().isascii() and "," not in str(path), "mount path"
        )
    name = "mkso-draft-index-" + os.urandom(16).hex()
    command = [tools["docker_path"], "--host", tools["docker_host"]]
    arguments = [
        *command,
        "run",
        "--name",
        name,
        "--pull",
        "never",
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65530:65530",
        "--pids-limit",
        "32",
        "--memory",
        "256m",
        "--cpus",
        "1",
        "--log-driver",
        "none",
        "--mount",
        f"type=bind,src={source},dst=/workspace,readonly",
        "--mount",
        f"type=bind,src={destination},dst=/output",
        "--entrypoint",
        "/usr/local/bin/node",
        tools["indexer_image"],
        "/opt/mkso-scip-python/index.js",
        "index",
        "--cwd",
        "/workspace",
        "--project-name",
        "mkso-bootstrap",
        "--project-version",
        "0.1",
        "--output",
        "/output/index.scip",
        "--environment",
        "/workspace/environment.json",
    ]
    try:
        if _native(arguments, 120) != 0:
            raise DraftUnavailable("public SCIP generation failed")
    finally:
        if _native([*command, "rm", "--force", name], 15) != 0:
            raise DraftUnavailable("public SCIP cleanup not established")
        for tool in ("docker", "protoc"):
            if _digest(_read(Path(tools[tool + "_path"]), 268435456)) != tools[tool + "_hash"]:
                raise DraftUnavailable("public tool identity changed")
    _require(_manifest(source) == before, "source changed during SCIP")
    raw = _read(destination / "index.scip", 16777216)
    decoder = ScipDecoder(
        protoc_path=Path(tools["protoc_path"]),
        expected_protoc_sha256=tools["protoc_hash"],
        expected_protobuf_runtime_version="6.33.2",
    )
    index = load_scip_bytes(
        decoder,
        raw,
        source,
        ScipExpectation("mkso-scip-python", "0.6.6-mkso.4", (), "file:///workspace"),
    )
    _require(
        sorted(d.relative_path for d in index.documents)
        == sorted(e["path"] for e in before if e["path"].endswith(".py")),
        "SCIP document set",
    )
    if _digest(_read(Path(tools["protoc_path"]), 268435456)) != tools["protoc_hash"]:
        raise DraftUnavailable("decoder tool identity changed")
    return {
        "index_hash": _digest(raw),
        "source_entries": before,
        "definitions": sorted(
            {
                o.symbol
                for o in index.occurrences
                if o.is_definition and not o.symbol.startswith("local ")
            }
        ),
        "references": sorted(
            {o.symbol for o in index.occurrences if not o.symbol.startswith("local ")}
        ),
    }
    # mkso:body:end


class DraftBroker:
    """One installed capsule; no operation can grant acceptance or activation."""

    _state: Path
    _capsule: dict
    _sources: dict
    _hash: str
    _scaffold: dict

    def __init__(self, state: Path, capsule_hash: str):
        """Load independently hash-bound operator state, not request-selected authority."""
        # mkso:body:begin
        _require(
            type(capsule_hash) is str and re.fullmatch(r"[0-9a-f]{64}", capsule_hash),
            "capsule hash",
        )
        _require(state.is_absolute() and state.resolve() == state, "state path must be resolved")
        info = state.lstat()
        _require(
            stat.S_ISDIR(info.st_mode)
            and stat.S_IMODE(info.st_mode) == 0o700
            and info.st_uid == os.getuid(),
            "state must be operator-owned mode 0700",
        )
        raw = _read(state / "capsule.json", 524288)
        _require(_digest(raw) == capsule_hash, "installed capsule differs")
        self._capsule, self._sources = _capsule(raw)
        self._state, self._hash = state, capsule_hash
        self._scaffold = _load(_read(state / "scaffold.json", 8388608))
        _require(
            type(self._scaffold) is dict
            and set(self._scaffold)
            == {
                "broker_hash",
                "capsule_hash",
                "index_hash",
                "source_entries",
                "definitions",
                "references",
            },
            "scaffold record shape",
        )
        _require(self._scaffold["capsule_hash"] == capsule_hash, "scaffold capsule differs")
        _require(
            self._scaffold["broker_hash"] == _digest(_read(Path(__file__), 262144)),
            "broker source changed since preparation",
        )
        expected = [
            {"path": name, "size": len(content), "hash": _digest(content)}
            for name, content in sorted(self._sources.items())
        ]
        _require(
            _manifest(state / "baseline") == expected == self._scaffold["source_entries"],
            "baseline differs from installed capsule",
        )
        _require(
            _digest(_read(state / "scaffold-index/index.scip", 16777216))
            == self._scaffold["index_hash"],
            "scaffold index changed",
        )
        _read(state / "lock", 0)
        _require(
            (state / "drafts").is_dir() and not (state / "drafts").is_symlink(),
            "draft store absent",
        )
        # mkso:body:end

    @classmethod
    def prepare(cls, state: Path, capsule_path: Path, capsule_hash: str):
        """Operator-only preparation: snapshot and index before permitting drafts."""
        # mkso:body:begin
        raw = _read(capsule_path, 524288)
        _require(_digest(raw) == capsule_hash, "operator capsule hash differs")
        capsule, sources = _capsule(raw)
        _require(
            state.is_absolute() and state.resolve() == state and "," not in str(state), "state path"
        )
        state.mkdir(mode=0o700)
        _write(state / "capsule.json", raw)
        _write(state / "lock", b"")
        (state / "baseline").mkdir(mode=0o755)
        (state / "drafts").mkdir(mode=0o700)
        for name, content in sources.items():
            path = state / "baseline" / name
            _write(path, content)
            path.chmod(0o444)
        indexed = _index(state / "baseline", state / "scaffold-index", capsule["tools"])
        symbol = (
            f"scip-python python mkso-bootstrap 0.1 "
            f"{capsule['filename'][:-3]}/{capsule['function']}()."
        )
        _require(
            indexed["definitions"].count(symbol) == 1, "SCIP did not bind the planned function"
        )
        _write(
            state / "scaffold.json",
            _canonical(
                {
                    "broker_hash": _digest(_read(Path(__file__), 262144)),
                    "capsule_hash": capsule_hash,
                    **indexed,
                }
            ),
        )
        return cls(state, capsule_hash)
        # mkso:body:end

    def public(self):
        """Expose only the installed public capsule and scaffold identity."""
        # mkso:body:begin
        return {
            "state": "DRAFT_CAPSULE",
            "authority": "NONE",
            "capsule_hash": self._hash,
            "scaffold_hash": _digest(_canonical(self._scaffold["source_entries"])),
            "contract_hash": self._capsule["contract_hash"],
            "task_id": self._capsule["task_id"],
            "predecessor_hash": self._capsule["predecessor_hash"],
            "slot_id": self._capsule["slot_id"],
            "filename": self._capsule["filename"],
            "function": self._capsule["function"],
            "sources": dict(self._capsule["sources"]),
        }
        # mkso:body:end

    def submit(self, request):
        """Reconstruct one slot, compile, index and retain a structurally admitted draft."""
        # mkso:body:begin
        _require(
            type(request) is dict
            and set(request)
            == {
                "operation",
                "capsule_hash",
                "scaffold_hash",
                "slot_id",
                "body_base64",
            },
            "submission fields differ",
        )
        _require(
            request["operation"] == "submit"
            and request["capsule_hash"] == self._hash
            and request["scaffold_hash"] == self.public()["scaffold_hash"]
            and request["slot_id"] == self._capsule["slot_id"],
            "submission capability differs",
        )
        encoded = request["body_base64"]
        _require(type(encoded) is str and len(encoded) <= 87384, "replacement encoding size")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise DraftRejected("replacement encoding") from None
        _require(base64.b64encode(body).decode() == encoded, "noncanonical replacement encoding")
        _require(0 < len(body) <= 65536 and body.endswith(b"\n"), "replacement size or newline")
        _require(_BEGIN not in body and _END not in body, "replacement contains slot marker")
        _require(
            all(not line.strip() or line.startswith(b"    ") for line in body.splitlines()),
            "replacement escapes indentation",
        )
        filename, function = self._capsule["filename"], self._capsule["function"]
        shape, prefix, suffix = _structure(self._sources[filename], function)
        replacement = prefix + _BEGIN + body + _END + suffix
        compile(replacement, filename, "exec", dont_inherit=True)
        _require(
            _structure(replacement, function)[0] == shape, "replacement changes surrounding syntax"
        )
        descriptor = os.open(self._state / "lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb+") as lock:
            info = os.fstat(lock.fileno())
            _require(
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0,
                "invalid lock",
            )
            deadline = time.monotonic() + 10
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise DraftUnavailable("draft store busy") from None
                    time.sleep(0.02)
            current = DraftBroker(self._state, self._hash)
            _require(current._scaffold == self._scaffold, "scaffold changed before submission")
            drafts = self._state / "drafts"
            _require(
                len(list(drafts.iterdir())) < 64, "draft storage limit; operator action required"
            )
            if shutil.disk_usage(self._state).free < 67108864:
                raise DraftUnavailable("insufficient draft storage")
            workspace = Path(tempfile.mkdtemp(prefix="draft-", dir=drafts))
            source = workspace / "source"
            source.mkdir(mode=0o755)
            for name, content in self._sources.items():
                path = source / name
                _write(path, replacement if name == filename else content)
                path.chmod(0o444)
            expected = [
                {
                    "path": name,
                    "size": len(replacement if name == filename else content),
                    "hash": _digest(replacement if name == filename else content),
                }
                for name, content in sorted(self._sources.items())
            ]
            _require(_manifest(source) == expected, "materialization differs")
            indexed = _index(source, workspace / "index", self._capsule["tools"])
            _require(indexed["source_entries"] == expected, "indexed source differs")
            _require(
                indexed["definitions"] == self._scaffold["definitions"],
                "undeclared SCIP definition",
            )
            _require(
                set(indexed["references"]) <= set(self._scaffold["references"]),
                "undeclared SCIP reference",
            )
            result = {
                "state": "STRUCTURALLY_ADMITTED_DRAFT",
                "authority": "NONE",
                "broker_hash": self._scaffold["broker_hash"],
                "capsule_hash": self._hash,
                "contract_hash": self._capsule["contract_hash"],
                "task_id": self._capsule["task_id"],
                "predecessor_hash": self._capsule["predecessor_hash"],
                "scaffold_hash": request["scaffold_hash"],
                "slot_id": request["slot_id"],
                "candidate_hash": _digest(_canonical(expected)),
                "index_hash": indexed["index_hash"],
            }
            _write(
                workspace / "draft.json",
                _canonical(
                    {
                        "result": result,
                        "replacement_hash": _digest(body),
                        "source_entries": expected,
                        "scaffold_index_hash": self._scaffold["index_hash"],
                    }
                ),
            )
            return result
        # mkso:body:end


def main():
    """Separate operator preparation from one bounded public stdio request."""
    # mkso:body:begin
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser(
        "prepare", help="operator-only: install and index a new public capsule"
    )
    prepare.add_argument("--capsule", type=Path, required=True)
    prepare.add_argument("--state", type=Path, required=True)
    prepare.add_argument("--capsule-hash", required=True)
    request = commands.add_parser(
        "request", help="one public request on a fixed operator capability"
    )
    request.add_argument("--state", type=Path, required=True)
    request.add_argument("--capsule-hash", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = DraftBroker.prepare(args.state, args.capsule, args.capsule_hash).public()
        else:
            broker = DraftBroker(args.state, args.capsule_hash)
            descriptor = sys.stdin.fileno()
            os.set_blocking(descriptor, False)
            payload = bytearray()
            deadline = time.monotonic() + 10
            while True:
                if time.monotonic() >= deadline:
                    raise DraftUnavailable("request input deadline")
                try:
                    chunk = os.read(descriptor, 16384)
                except BlockingIOError:
                    time.sleep(0.02)
                    continue
                if not chunk:
                    break
                payload.extend(chunk)
                _require(len(payload) <= _MAX_REQUEST, "request exceeds limit")
            value = _load(bytes(payload).removesuffix(b"\n"))
            result = broker.public() if value == {"operation": "public"} else broker.submit(value)
        sys.stdout.buffer.write(_canonical(result) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (DraftRejected, SyntaxError, UnicodeError, binascii.Error):
        result = {"state": "DRAFT_REJECTED", "authority": "NONE"}
    except Exception:
        result = {"state": "DRAFT_UNAVAILABLE", "authority": "NONE"}
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    sys.stdout.buffer.flush()
    return 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
