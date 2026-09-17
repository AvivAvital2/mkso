"""Unprivileged draft session: bounded stdio only, no local execution tools."""

from __future__ import annotations

import os
import resource
import sys

import bootstrap.baseline.direct_bridge as bridge


def runtime_guard():
    """Require namespace-local non-root identity, zero capabilities and both syscall filters."""
    # mkso:body:begin
    bridge._require(os.getpid() == 1)
    bridge._require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 65532)
    bridge._require(set(os.getgroups()) <= {65532})
    values = {}
    for name in ("uid_map", "gid_map", "setgroups", "status"):
        with open("/proc/self/" + name, "rb") as handle:
            raw = handle.read(16385)
        bridge._require(len(raw) <= 16384)
        values[name] = raw.decode("ascii")
    for name in ("uid_map", "gid_map"):
        bridge._require(values[name].split() == ["65532", "65532", "1"])
    bridge._require(values["setgroups"] == "deny\n")
    status = {}
    for line in values["status"].splitlines():
        name, separator, value = line.partition(":")
        bridge._require(separator and name not in status)
        status[name] = value.strip()
    bridge._require(status["Uid"].split() == ["65532"] * 4)
    bridge._require(status["Gid"].split() == ["65532"] * 4)
    capabilities = {
        name: status[name] for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    }
    bridge._require(all(value == "0000000000000000" for value in capabilities.values()))
    bridge._require(status["NoNewPrivs"] == "1" and status["Seccomp"] == "2")
    filters = int(status["Seccomp_filters"])
    bridge._require(2 <= filters <= 4096)
    namespaces = {}
    for name in ("user", "mnt", "pid", "ipc", "net", "cgroup"):
        value = os.readlink("/proc/self/ns/" + name)
        bridge._require(bridge.re.fullmatch(name + r":\[[0-9]{1,20}\]", value))
        namespaces[name] = value
    return {
        "uid": 65532,
        "gid": 65532,
        "pid": 1,
        "uid_map": [65532, 65532, 1],
        "gid_map": [65532, 65532, 1],
        "setgroups": "deny",
        "capabilities": capabilities,
        "no_new_privs": 1,
        "seccomp_mode": 2,
        "seccomp_filters": filters,
        "namespaces": namespaces,
    }
    # mkso:body:end


def receive():
    """Read one bounded canonical operator frame; EOF or ambiguity stops the session."""
    # mkso:body:begin
    raw = sys.stdin.buffer.readline(bridge.MAX_WIRE + 2)
    bridge._require(0 < len(raw) <= bridge.MAX_WIRE + 1 and raw.endswith(b"\n"))
    value = bridge._decode(raw[:-1])
    bridge._require(bridge._encode(value) + b"\n" == raw)
    return value
    # mkso:body:end


def exchange(request):
    """Write one typed request and wait for one operator response over stdio."""
    # mkso:body:begin
    sys.stdout.buffer.write(bridge._encode(request) + b"\n")
    sys.stdout.buffer.flush()
    return receive()
    # mkso:body:end


def run(initial):
    """Keep a fresh bounded model history; request only provider/public/submit operations."""
    # mkso:body:begin
    bridge._require(type(initial) is dict and set(initial) == {"model", "task", "capsule"})
    model, task, public = initial["model"], initial["task"], initial["capsule"]
    bridge._require(model == "gpt-5.6-terra" and type(task) is str and bool(task.strip()))
    bridge._require(len(task.encode("utf-8")) <= 65536 and type(public) is dict)
    bridge._require(
        bridge._projection(public, public["capsule_hash"], None) == public
        and public["state"] == "DRAFT_CAPSULE"
    )
    history = [
        {"role": "user", "content": bridge._encode({"task": task, "capsule": public}).decode()}
    ]
    seen = set()
    for _ in range(8):
        response = exchange({"operation": "provider", "history": history})
        call = bridge._call(response, model, seen)
        if call is None:
            return "NO_DRAFT"
        result = exchange({"operation": "call", "call": call})
        bridge._projection(
            result, public["capsule_hash"], None if call["name"] == "public" else public
        )
        if result["state"] in ("STRUCTURALLY_ADMITTED_DRAFT", "DRAFT_UNAVAILABLE"):
            return result["state"]
        if call["name"] == "public":
            bridge._require(result == public)
        history.extend(response["output"])
        history.append(
            {
                "type": "function_call_output",
                "call_id": call["call_id"],
                "output": bridge._encode(result).decode(),
            }
        )
        bridge._encode(history)
    return "TURN_LIMIT"
    # mkso:body:end


def main():
    """Disable core dumps and fail silently without revealing protocol diagnostics."""
    # mkso:body:begin
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        bridge._require(len(sys.argv) == 1)
        runtime = runtime_guard()
        initial = receive()
        bridge._require(
            exchange({"operation": "ready", "runtime": runtime}) == {"operation": "continue"}
        )
        state = run(initial)
        sys.stdout.buffer.write(bridge._encode({"operation": "finish", "state": state}) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
