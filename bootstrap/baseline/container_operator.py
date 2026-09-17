"""Fixed-operation host supervisor for a Docker-isolated draft implementor session."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING

import bootstrap.baseline.diagnostics as diagnostics
import bootstrap.baseline.direct_bridge as bridge

ROOT = Path(__file__).resolve().parents[2]
BRIDGE_SHA256 = "9a0b1ba1a36136985a218366996ef4299c48eb0d28e76e6c51d291e762378cd1"
DIAGNOSTICS_SHA256 = "e1c95c12c367a47c24dd031d01ecc2d2e96815836881706665083814197c1756"
SCHEMA = "mkso-bootstrap-container-deployment/1"
MODULE = "bootstrap.baseline.container_session"
TMPFS = "rw,noexec,nosuid,nodev,size=16777216,mode=0700,uid=65532,gid=65532"

if TYPE_CHECKING:
    # Frozen SCIP breadcrumb for operator-only reporting; never executed.
    diagnostics.failure_stage(Exception())


def digest(path):
    """Hash one bounded public regular file; never read credential paths."""
    # mkso:body:begin
    bridge._require(path.is_absolute() and path.resolve() == path)
    return hashlib.sha256(bridge._read(path, 134217728)).hexdigest()
    # mkso:body:end


def deployment(path, expected_hash):
    """Validate exact operator-selected canonical manifest, source, CLI and syscall pins."""
    # mkso:body:begin
    bridge._require(type(expected_hash) is str and bridge.HEX.fullmatch(expected_hash))
    bridge._require(path.is_absolute() and path.resolve() == path)
    raw = bridge._read(path, 16384)
    bridge._require(hashlib.sha256(raw).hexdigest() == expected_hash)
    value = bridge._decode(raw)
    bridge._require(type(value) is dict and bridge._encode(value) == raw)
    bridge._require(
        set(value)
        == {
            "schema_version",
            "image_id",
            "docker_path",
            "docker_sha256",
            "docker_host",
            "session_sha256",
            "operator_sha256",
            "bridge_sha256",
            "containerfile_sha256",
            "seccomp_sha256",
            "filter_source_sha256",
            "filter_sha256",
        }
    )
    bridge._require(value["schema_version"] == SCHEMA)
    bridge._require(
        type(value["image_id"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_id"])
    )
    for name in (
        "session",
        "operator",
        "bridge",
        "containerfile",
        "seccomp",
        "docker",
        "filter_source",
        "filter",
    ):
        bridge._require(
            type(value[name + "_sha256"]) is str and bridge.HEX.fullmatch(value[name + "_sha256"])
        )
    directory = ROOT / "bootstrap/baseline/deployment/implementor-runtime"
    paths = {
        "session": ROOT / "bootstrap/baseline/container_session.py",
        "operator": Path(__file__).resolve(),
        "bridge": ROOT / "bootstrap/baseline/direct_bridge.py",
        "containerfile": directory / "Containerfile",
        "seccomp": directory / "seccomp.json",
        "filter_source": directory / "post-launch.bpf.hex",
        "filter": directory / "post-launch.bpf",
    }
    bridge._require(value["bridge_sha256"] == BRIDGE_SHA256)
    bridge._require(digest(ROOT / "bootstrap/baseline/diagnostics.py") == DIAGNOSTICS_SHA256)
    for name, source in paths.items():
        bridge._require(digest(source) == value[name + "_sha256"])
    filter_bytes = bytes.fromhex(bridge._read(paths["filter_source"], 1024).decode("ascii"))
    bridge._require(len(filter_bytes) == 32 and filter_bytes == bridge._read(paths["filter"], 32))
    bridge._require(type(value["docker_path"]) is str and type(value["docker_host"]) is str)
    executable = Path(value["docker_path"])
    bridge._require(digest(executable) == value["docker_sha256"] and os.access(executable, os.X_OK))
    bridge._require(value["docker_host"].startswith("unix:///"))
    socket = Path(value["docker_host"][7:])
    bridge._require(socket.is_absolute() and socket.resolve() == socket)
    info = socket.lstat()
    bridge._require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid())
    value["seccomp_path"] = str(paths["seccomp"])
    return value
    # mkso:body:end


def docker(config, arguments):
    """Run an internal fixed Docker operation using explicit endpoint and empty config."""
    # mkso:body:begin
    bridge._require(digest(Path(config["docker_path"])) == config["docker_sha256"])
    code, raw = bridge._child(
        [
            config["docker_path"],
            "--config",
            "/nonexistent/mkso-docker",
            "--host",
            config["docker_host"],
            *arguments,
        ],
        b"",
        {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        30,
        bridge.MAX_WIRE,
    )
    bridge._require(code == 0 and digest(Path(config["docker_path"])) == config["docker_sha256"])
    return raw
    # mkso:body:end


def inspect_container(config, name):
    """Resolve only this operator-generated name and bind image and ownership label."""
    # mkso:body:begin
    bridge._require(re.fullmatch(r"mkso-draft-[0-9a-f]{32}", name))
    values = bridge._decode(docker(config, ["container", "inspect", name]))
    bridge._require(type(values) is list and len(values) == 1 and type(values[0]) is dict)
    value = values[0]
    bridge._require(type(value.get("Id")) is str and bridge.HEX.fullmatch(value["Id"]))
    bridge._require(value.get("Name") == "/" + name and value.get("Image") == config["image_id"])
    bridge._require(value["Config"]["Labels"].get("org.mkso.draft-owner") == name)
    return value
    # mkso:body:end


def prepare(config, name):
    """Create, do not yet start, a mount-free bounded container and check resolved settings."""
    # mkso:body:begin
    image = bridge._decode(docker(config, ["image", "inspect", config["image_id"]]))
    bridge._require(
        type(image) is list and len(image) == 1 and image[0]["Id"] == config["image_id"]
    )
    bridge._require(image[0]["Os"] == "linux" and image[0]["Architecture"] == "amd64")
    bridge._require(not image[0]["Config"].get("Volumes") and not image[0]["Config"].get("OnBuild"))
    bridge._require(not image[0]["Config"].get("Healthcheck"))
    raw = docker(
        config,
        [
            "container",
            "create",
            "--pull",
            "never",
            "--platform",
            "linux/amd64",
            "--name",
            name,
            "--label",
            "org.mkso.draft-owner=" + name,
            "--read-only",
            "--network",
            "none",
            "--ipc",
            "none",
            "--cgroupns",
            "private",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--security-opt",
            "seccomp=" + config["seccomp_path"],
            "--pids-limit",
            "32",
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "--cpus",
            "1",
            "--ulimit",
            "core=0:0",
            "--ulimit",
            "nofile=128:128",
            "--user",
            "65532:65532",
            "--tmpfs",
            "/tmp:" + TMPFS,
            "--workdir",
            "/tmp",
            "--log-driver",
            "none",
            "--restart",
            "no",
            "--interactive",
            config["image_id"],
        ],
    )
    value = inspect_container(config, name)
    bridge._require(raw == (value["Id"] + "\n").encode())
    host, process = value["HostConfig"], value["Config"]
    bridge._require(value["State"]["Status"] == "created" and not value["State"]["Running"])
    bridge._require(
        not value.get("Mounts")
        or all(
            item.get("Type") == "tmpfs"
            and item.get("Destination") == "/tmp"
            and not item.get("Source")
            for item in value["Mounts"]
        )
    )
    bridge._require(process["User"] == "65532:65532" and process["WorkingDir"] == "/tmp")
    bridge._require(
        process["Entrypoint"]
        == [
            "/usr/bin/env",
            "-i",
            "/usr/bin/unshare",
            "--user",
            "--map-current-user",
            "--keep-caps",
            "/usr/bin/setpriv",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--seccomp-filter",
            "/opt/mkso/post-launch.bpf",
            "/usr/local/bin/python",
            "-I",
            "-B",
            "-m",
            MODULE,
        ]
    )
    bridge._require(
        not process.get("Cmd") and not process.get("Volumes") and not process.get("Healthcheck")
    )
    bridge._require(process["OpenStdin"] and not process["Tty"])
    bridge._require(host["ReadonlyRootfs"] and not host["Privileged"])
    bridge._require(
        host["NetworkMode"] == "none"
        and host["IpcMode"] == "none"
        and host["CgroupnsMode"] == "private"
    )
    bridge._require(not host["PidMode"] and not host["UsernsMode"] and not host.get("CgroupParent"))
    bridge._require(host["CapDrop"] == ["ALL"] and not host["CapAdd"])
    bridge._require(host["Memory"] == 268435456 and host["MemorySwap"] == 268435456)
    bridge._require(host["NanoCpus"] == 1000000000 and host["PidsLimit"] == 32)
    bridge._require(host["Tmpfs"] == {"/tmp": TMPFS})
    bridge._require(host["LogConfig"] == {"Type": "none", "Config": {}})
    bridge._require(host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0})
    bridge._require(not host["PublishAllPorts"] and not host["AutoRemove"])
    for field in (
        "Binds",
        "Mounts",
        "VolumesFrom",
        "Links",
        "PortBindings",
        "Devices",
        "DeviceRequests",
        "GroupAdd",
        "ExtraHosts",
        "Dns",
    ):
        bridge._require(not host.get(field))
    limits = host["Ulimits"]
    bridge._require(type(limits) is list and len(limits) == 2)
    bridge._require(
        {item["Name"]: (item["Soft"], item["Hard"]) for item in limits}
        == {"core": (0, 0), "nofile": (128, 128)}
    )
    options = host["SecurityOpt"]
    bridge._require(type(options) is list and len(options) == 2)
    bridge._require("no-new-privileges:true" in options or "no-new-privileges" in options)
    policies = [option[8:] for option in options if option.startswith("seccomp=")]
    bridge._require(len(policies) == 1)
    bridge._require(
        bridge._decode(policies[0])
        == bridge._decode(bridge._read(Path(config["seccomp_path"]), 65536))
    )
    return value
    # mkso:body:end


def exchange(process, payload, key):
    """Transfer a bounded canonical frame with nonblocking IO and a single deadline."""
    # mkso:body:begin
    raw = bridge._encode(payload) + b"\n"
    bridge._secret_free(raw, key)
    sent, received = 0, bytearray()
    deadline = time.monotonic() + 15
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdin, selectors.EVENT_WRITE)
        selector.register(process.stdout, selectors.EVENT_READ)
        selector.register(process.stderr, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            bridge._require(remaining > 0)
            events = selector.select(remaining)
            bridge._require(bool(events))
            for event, _ in events:
                if event.fileobj is process.stdin:
                    try:
                        amount = os.write(process.stdin.fileno(), raw[sent : sent + 65536])
                    except BlockingIOError:
                        continue
                    bridge._require(amount > 0)
                    sent += amount
                    if sent == len(raw):
                        selector.unregister(process.stdin)
                else:
                    try:
                        chunk = os.read(event.fd, 65536)
                    except BlockingIOError:
                        continue
                    if event.fileobj is process.stderr:
                        bridge._require(not chunk)
                        selector.unregister(process.stderr)
                    else:
                        bridge._require(bool(chunk))
                        received.extend(chunk)
                        bridge._require(len(received) <= bridge.MAX_WIRE + 1)
            if b"\n" in received:
                bridge._require(
                    sent == len(raw) and received.endswith(b"\n") and received.count(b"\n") == 1
                )
                frame = bytes(received)
                bridge._secret_free(frame, key)
                result = bridge._decode(frame[:-1])
                bridge._require(bridge._encode(result) + b"\n" == frame)
                bridge._secret_free(bridge._encode(result), key)
                return result
    # mkso:body:end


def serve(process, args, public, task, key, identity, config, report):
    """Mirror history and validate every container request before fixed provider/broker dispatch."""
    # mkso:body:begin
    history = [
        {"role": "user", "content": bridge._encode({"task": task, "capsule": public}).decode()}
    ]
    request = exchange(process, {"model": args.model, "task": task, "capsule": public}, key)
    bridge._require(type(request) is dict and set(request) == {"operation", "runtime"})
    bridge._require(request["operation"] == "ready" and type(request["runtime"]) is dict)
    runtime = request["runtime"]
    bridge._require(
        set(runtime)
        == {
            "uid",
            "gid",
            "pid",
            "uid_map",
            "gid_map",
            "setgroups",
            "capabilities",
            "no_new_privs",
            "seccomp_mode",
            "seccomp_filters",
            "namespaces",
        }
    )
    for name, expected in (
        ("uid", 65532),
        ("gid", 65532),
        ("pid", 1),
        ("no_new_privs", 1),
        ("seccomp_mode", 2),
    ):
        bridge._require(type(runtime[name]) is int and runtime[name] == expected)
    for name in ("uid_map", "gid_map"):
        bridge._require(
            type(runtime[name]) is list and all(type(value) is int for value in runtime[name])
        )
        bridge._require(runtime[name] == [65532, 65532, 1])
    bridge._require(runtime["setgroups"] == "deny")
    bridge._require(
        runtime["capabilities"]
        == {name: "0000000000000000" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    )
    bridge._require(
        type(runtime["seccomp_filters"]) is int and 2 <= runtime["seccomp_filters"] <= 4096
    )
    namespaces = runtime["namespaces"]
    bridge._require(
        type(namespaces) is dict
        and set(namespaces) == {"user", "mnt", "pid", "ipc", "net", "cgroup"}
    )
    for name, value in namespaces.items():
        bridge._require(type(value) is str and re.fullmatch(name + r":\[[0-9]{1,20}\]", value))
    report["session_runtime"] = runtime
    request = exchange(process, {"operation": "continue"}, key)
    seen = set()
    for _ in range(8):
        bridge._require(request == {"operation": "provider", "history": history})
        bridge._require(
            bridge._identity() == identity
            and deployment(args.deployment, args.deployment_sha256) == config
        )
        response = observed_provider(args.model, history, key, report)
        call = bridge._call(response, args.model, seen)
        bridge._require(
            bridge._identity() == identity
            and deployment(args.deployment, args.deployment_sha256) == config
        )
        request = exchange(process, response, key)
        if call is None:
            bridge._require(request == {"operation": "finish", "state": "NO_DRAFT"})
            return {"state": "NO_DRAFT", "authority": "NONE"}
        bridge._require(request == {"operation": "call", "call": call})
        if call["name"] == "submit":
            arguments = bridge._decode(call["arguments"])
            bridge._secret_free(
                base64.b64decode(arguments["body_base64"], validate=True), key
            )
        result = bridge._dispatch(call, args.state, args.capsule_hash, public)
        bridge._require(
            bridge._identity() == identity
            and deployment(args.deployment, args.deployment_sha256) == config
        )
        request = exchange(process, result, key)
        if result["state"] in ("STRUCTURALLY_ADMITTED_DRAFT", "DRAFT_UNAVAILABLE"):
            bridge._require(request == {"operation": "finish", "state": result["state"]})
            return result
        history.extend(response["output"])
        history.append(
            {
                "type": "function_call_output",
                "call_id": call["call_id"],
                "output": bridge._encode(result).decode(),
            }
        )
        bridge._encode(history)
    bridge._require(request == {"operation": "finish", "state": "TURN_LIMIT"})
    return {"state": "TURN_LIMIT", "authority": "NONE"}
    # mkso:body:end


def cleanup(config, name, process):
    """Stop attachment and remove only the exact owned container; fail closed on uncertainty."""
    # mkso:body:begin
    if process is not None:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    value = inspect_container(config, name)
    docker(config, ["container", "rm", "--force", value["Id"]])
    remaining = docker(
        config, ["container", "ls", "--all", "--filter", "id=" + value["Id"], "--format", "{{.ID}}"]
    )
    bridge._require(remaining == b"")
    # mkso:body:end


def run(args, config, task, key, report):
    """Own container lifecycle and retain only safe public bindings and terminal draft state."""
    # mkso:body:begin
    bridge._secret_free(task.encode("utf-8"), key)
    identity = bridge._identity()
    public = bridge._projection(
        bridge._broker(args.state, args.capsule_hash, {"operation": "public"}),
        args.capsule_hash,
        None,
    )
    bridge._require(public["state"] == "DRAFT_CAPSULE")
    bridge._secret_free(bridge._encode(public), key)
    for source in public["sources"].values():
        bridge._secret_free(base64.b64decode(source, validate=True), key)
    bridge._require(
        bridge._identity() == identity
        and deployment(args.deployment, args.deployment_sha256) == config
    )
    name, process = report["container_name"], None
    report["implementation"] = identity
    try:
        observed = prepare(config, name)
        report["container_id"] = observed["Id"]
        report["created_configuration_sha256"] = hashlib.sha256(
            bridge._encode(observed)
        ).hexdigest()
        bridge._require(deployment(args.deployment, args.deployment_sha256) == config)
        process = subprocess.Popen(
            [
                config["docker_path"],
                "--config",
                "/nonexistent/mkso-docker",
                "--host",
                config["docker_host"],
                "container",
                "start",
                "--attach",
                "--interactive",
                observed["Id"],
            ],
            cwd=ROOT,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=True,
        )
        for stream in (process.stdin, process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
        result = serve(process, args, public, task, key, identity, config, report)
        process.stdin.close()
        bridge._require(process.wait(timeout=5) == 0)
        bridge._require(process.stdout.read(1) == b"" and process.stderr.read(1) == b"")
        ended = inspect_container(config, name)
        bridge._require(ended["Id"] == observed["Id"] and ended["State"]["Status"] == "exited")
        bridge._require(ended["State"]["ExitCode"] == 0 and not ended["State"]["OOMKilled"])
        bridge._require(
            bridge._identity() == identity
            and deployment(args.deployment, args.deployment_sha256) == config
        )
    finally:
        cleanup(config, name, process)
        report["cleanup_confirmed"] = True
    return result
    # mkso:body:end


def observed_provider(model, history, key, report):
    """Observe one provider ordinal/category without changing worker authority."""
    # mkso:implementation:begin
    if report is None:
        phase = 10
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            raw = sys.stdin.buffer.read(bridge.MAX_WIRE + 1)
            bridge._decode(raw)
            descriptor = os.environ.pop("MKSO_API_KEY_FD")
            bridge._require(re.fullmatch(r"[0-9]{1,10}", descriptor) and int(descriptor) > 2)
            with os.fdopen(int(descriptor), "rb") as credential:
                key = credential.read(4097).decode("ascii")
            bridge._require(re.fullmatch(r"[A-Za-z0-9_-]{1,4096}", key))
            bridge._secret_free(raw, key)
            bridge._secret_free(bridge._encode(bridge._decode(raw)), key)
            phase = 20
            connection = bridge.http.client.HTTPSConnection(
                "api.openai.com", 443, timeout=120, context=bridge.ssl.create_default_context()
            )
            try:
                connection.request(
                    "POST", "/v1/responses", body=raw,
                    headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
                )
                response = connection.getresponse()
                if response.status != 200:
                    if 400 <= response.status <= 499:
                        return {400: 40, 401: 41, 403: 42, 429: 43, 404: 44}.get(response.status, 45)
                    if 500 <= response.status <= 599:
                        return 46
                    return 47
                if response.getheader("Content-Encoding", "identity") != "identity":
                    return 48
                content = response.read(bridge.MAX_RESPONSE + 1)
                if len(content) > bridge.MAX_RESPONSE:
                    return 49
                phase = 50
                bridge._secret_free(content, key)
                bridge._secret_free(bridge._encode(bridge._decode(content)), key)
                phase = 20
                sys.stdout.buffer.write(content)
                sys.stdout.buffer.flush()
                return 0
            finally:
                connection.close()
        except TimeoutError:
            return 21
        except bridge.ssl.SSLError:
            return 22
        except Exception:
            return phase
    ordinal = report.get("provider_request_number", 0)
    bridge._require(type(ordinal) is int and 0 <= ordinal < 8)
    report["provider_request_number"] = ordinal + 1
    report["provider_failure"] = "UNKNOWN"
    payload = bridge._encode({
        "model": model,
        "instructions": bridge.INSTRUCTIONS,
        "input": history,
        "tools": bridge._tools(),
        "tool_choice": "auto",
        "parallel_tool_calls": False,
        "store": False,
        "stream": False,
        "max_output_tokens": 16384,
        "include": ["reasoning.encrypted_content"],
        "truncation": "disabled",
    })
    launcher = (
        "import sys,runpy; sys.path.insert(0," + repr(str(ROOT)) + "); "
        "scope=runpy.run_path(" + repr(str(Path(__file__).resolve())) + "); "
        "raise SystemExit(scope['observed_provider'](None,None,None,None))"
    )
    try:
        code, raw = bridge._child(
            [sys.executable, "-I", "-B", "-c", launcher], payload,
            {"PATH": "/usr/bin:/bin"}, 120, bridge.MAX_RESPONSE, secret=key,
        )
    except Exception:
        report["provider_failure"] = "CHILD_UNAVAILABLE"
        raise
    report["provider_failure"] = {
        0: "RESPONSE_INVALID", 10: "INPUT_INVALID", 20: "TRANSPORT",
        21: "TIMEOUT", 22: "TLS", 40: "HTTP_400", 41: "HTTP_401",
        42: "HTTP_403", 43: "HTTP_429", 44: "HTTP_404", 45: "HTTP_OTHER_4XX",
        46: "HTTP_5XX", 47: "HTTP_UNEXPECTED_STATUS", 48: "CONTENT_ENCODING",
        49: "RESPONSE_TOO_LARGE", 50: "RESPONSE_INVALID",
    }.get(code, "UNKNOWN")
    bridge._require(code == 0)
    bridge._secret_free(raw, key)
    response = bridge._decode(raw)
    report["provider_failure"] = "NONE"
    return response
    # mkso:implementation:end


def main():
    """Accept operator-only pinned configuration, preserve failed reports, never activate code."""
    # mkso:body:begin
    report = {
        "schema_version": "mkso-bootstrap-container-run/1",
        "authority": "NONE",
        "state": "CONTAINER_UNAVAILABLE",
        "qualified_isolation": False,
        "cleanup_confirmed": False,
        "failure_stage": "UNKNOWN",
    }
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--deployment", type=Path, required=True)
        parser.add_argument("--deployment-sha256", required=True)
        parser.add_argument("--state", type=Path, required=True)
        parser.add_argument("--capsule-hash", required=True)
        parser.add_argument("--task", type=Path, required=True)
        parser.add_argument("--task-sha256", required=True)
        parser.add_argument("--env-file", type=Path)
        parser.add_argument("--model", required=True)
        parser.add_argument("--output", type=Path, required=True)
        args = parser.parse_args()
        config = deployment(args.deployment, args.deployment_sha256)
        bridge._require(args.model == "gpt-5.6-terra")
        bridge._require(
            bridge.HEX.fullmatch(args.capsule_hash) and bridge.HEX.fullmatch(args.task_sha256)
        )
        bridge._require(args.state.is_absolute() and args.state.resolve() == args.state)
        info = args.state.stat()
        bridge._require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )
        task_raw = bridge._read(args.task, 65536)
        bridge._require(hashlib.sha256(task_raw).hexdigest() == args.task_sha256)
        task = task_raw.decode("utf-8")
        bridge._require(bool(task.strip()))
        bridge._require(args.output.is_absolute() and args.output.resolve() == args.output)
        bridge._require(
            not any(part == ".env" or part.startswith(".env.") for part in args.output.parts)
        )
        report.update(
            {
                "deployment_sha256": args.deployment_sha256,
                "image_id": config["image_id"],
                "model": args.model,
                "task_sha256": args.task_sha256,
                "capsule_hash": args.capsule_hash,
                "container_name": "mkso-draft-" + uuid.uuid4().hex,
            }
        )
        descriptor = os.open(
            args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(bridge._encode(report) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
            key = None
            try:
                key = bridge._credential(args.env_file)
                result = run(args, config, task, key, report)
                report["result"] = result
                report["state"] = result["state"]
                report["failure_stage"] = "NONE"
            except Exception as error:
                report["state"] = "CONTAINER_UNAVAILABLE"
                report["failure_stage"] = diagnostics.failure_stage(error)
                if report["failure_stage"] == "SESSION_PROTOCOL":
                    trace = error.__traceback__
                    for _ in range(64):
                        if trace is None:
                            break
                        code = trace.tb_frame.f_code
                        if code.co_filename == __file__ and code.co_name == "serve":
                            report["failure_site"] = f"container_operator.serve:{trace.tb_lineno}"
                            break
                        trace = trace.tb_next
            if key is not None:
                bridge._secret_free(bridge._encode(report), key)
            handle.seek(0)
            handle.write(bridge._encode(report) + b"\n")
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as error:
        report = {
            "authority": "NONE",
            "state": "CONTAINER_UNAVAILABLE",
            "failure_stage": diagnostics.failure_stage(error),
        }
    sys.stdout.buffer.write(bridge._encode(report) + b"\n")
    sys.stdout.buffer.flush()
    return 0 if report["state"] == "STRUCTURALLY_ADMITTED_DRAFT" else 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
