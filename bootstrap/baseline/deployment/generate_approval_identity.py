"""Out-of-band human approval identity setup; never run by the implementation agent."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import resource
import stat
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


class SetupError(ValueError):
    """A public setup prerequisite is missing; no provisioning is established."""


def _require(condition: bool, message: str) -> None:
    """Reject with a controlled public-safe explanation."""
    # mkso:body:begin
    if not condition:
        raise SetupError(message)
    # mkso:body:end


def _timestamp(value: str) -> datetime:
    """Parse exact whole-second, timezone-explicit ISO 8601 into bounded UTC."""
    # mkso:body:begin
    _require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", value) is not None,
        "Use a whole-second date such as 2026-09-09T12:00:00Z, with a timezone.",
    )
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    _require(0 <= int(parsed.timestamp()) <= 253402300799, "Date is outside the supported range.")
    return parsed
    # mkso:body:end


def _destination(value: str, repository: Path) -> Path:
    """Require a fresh canonical path outside repository and Git worktrees."""
    # mkso:body:begin
    _require(bool(value) and value.isprintable(), "Enter a printable absolute destination path.")
    path = Path(value).expanduser()
    _require(path.is_absolute(), "The destination must be absolute.")
    _require(path.resolve(strict=False) == path, "Use a canonical destination without symlinks.")
    _require(not path.exists() and not path.is_symlink(), "The destination must not already exist.")
    _require(
        not path.is_relative_to(repository), "Private material cannot be created in the repository."
    )
    _require(path.parent.is_dir(), "The destination parent must already exist.")
    for parent in path.parents:
        info = parent.stat()
        _require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in (0, os.getuid())
            and not stat.S_IMODE(info.st_mode) & 0o022,
            "Destination ancestors must be operator/root-owned and not writable by others.",
        )
        _require(
            not (parent / ".git").exists() and not (parent / ".git").is_symlink(),
            "Choose a destination outside every Git worktree.",
        )
    _require(path.parent.stat().st_uid == os.getuid(), "The destination parent must belong to you.")
    return path
    # mkso:body:end


def _tool(value: str) -> tuple[Path, str]:
    """Bind one local non-writable-by-others regular ssh-keygen executable."""
    # mkso:body:begin
    path = Path(value)
    _require(path.is_absolute(), "ssh-keygen must be an explicitly selected absolute path.")
    path = path.resolve(strict=True)
    info = path.stat()
    _require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid in (0, os.getuid())
        and not stat.S_IMODE(info.st_mode) & 0o022
        and os.access(path, os.X_OK),
        "ssh-keygen must be a trusted local executable, not writable by other users.",
    )
    for parent in path.parents:
        info = parent.stat()
        _require(
            info.st_uid in (0, os.getuid()) and not stat.S_IMODE(info.st_mode) & 0o022,
            "The ssh-keygen executable directory must not be writable by other users.",
        )
    return path, hashlib.sha256(path.read_bytes()).hexdigest()
    # mkso:body:end


def _public_key(path: Path) -> str:
    """Read only the generated public file and validate its complete Ed25519 blob."""
    # mkso:body:begin
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == os.getuid()
            and 0 < before.st_size <= 4096,
            "The generated public key has invalid file metadata.",
        )
        raw = handle.read(4097)
        after = os.fstat(handle.fileno())
        _require(
            len(raw) == before.st_size
            and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "The generated public key changed while being read.",
        )
    fields = raw.decode("ascii").split()
    _require(len(fields) == 2 and fields[0] == "ssh-ed25519", "Unexpected public-key format.")
    blob = base64.b64decode(fields[1], validate=True)
    _require(
        base64.b64encode(blob).decode("ascii") == fields[1]
        and len(blob) == 51
        and blob[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20",
        "The public key is not a canonical, complete Ed25519 key.",
    )
    return " ".join(fields)
    # mkso:body:end


def _encrypted_header(path: Path) -> None:
    """Read only the OpenSSH format prefix, rejecting unencrypted key metadata."""
    # mkso:body:begin
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_nlink == 1
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o600
            and 0 < before.st_size <= 16384,
            "The private key must be a single operator-owned mode-0600 file.",
        )
        _require(
            handle.readline(64) == b"-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "Unsupported private-key container format.",
        )
        # 68 base64 characters decode to 51 bytes: only the format header and
        # cipher/KDF metadata, not the private-key payload. Never read the rest.
        header = base64.b64decode(handle.read(68), validate=True)
        after = os.fstat(handle.fileno())
        _require(
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
            "Private-key metadata changed while being read.",
        )
    _require(header[:15] == b"openssh-key-v1\x00", "Unsupported private-key container format.")
    offset = 15
    for required in (b"aes256-ctr", b"bcrypt"):
        _require(len(header) >= offset + 4, "Truncated encryption metadata.")
        size = int.from_bytes(header[offset : offset + 4], "big")
        offset += 4
        _require(
            size == len(required) and header[offset : offset + size] == required,
            "An encrypted key is required. Choose a non-empty passphrase in a fresh setup run.",
        )
        offset += size
    # mkso:body:end


def _write_public(directory: Path, name: str, raw: bytes) -> None:
    """Exclusively create a mode-0600 public artifact and flush its bytes."""
    # mkso:body:begin
    _require(
        name in {"approval-key.pub", "revocations.txt", "identity.json"},
        "Unsupported public artifact name.",
    )
    descriptor = os.open(
        directory / name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    # mkso:body:end


def _generate(directory: Path, executable: Path, executable_hash: str) -> str:
    """Let native ssh-keygen own the passphrase and private key; return public key only."""
    # mkso:body:begin
    _require(
        hashlib.sha256(executable.read_bytes()).hexdigest() == executable_hash,
        "ssh-keygen changed before generation.",
    )
    print("Enter a non-empty passphrase directly into ssh-keygen; this script does not receive it.")
    result = subprocess.run(
        [
            str(executable),
            "-q",
            "-t",
            "ed25519",
            "-a",
            "100",
            "-Z",
            "aes256-ctr",
            "-C",
            "",
            "-f",
            "approval_ed25519",
        ],
        cwd=directory,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        close_fds=True,
        timeout=600,
        check=False,
    )
    _require(result.returncode == 0, "ssh-keygen did not finish successfully.")
    _require(
        hashlib.sha256(executable.read_bytes()).hexdigest() == executable_hash,
        "ssh-keygen changed during generation.",
    )
    _encrypted_header(directory / "approval_ed25519")
    return _public_key(directory / "approval_ed25519.pub")
    # mkso:body:end


def _bundle(
    directory: Path,
    public_key: str,
    principal: str,
    valid_after: datetime,
    valid_before: datetime,
    executable_hash: str,
) -> str:
    """Emit public provisioning-request metadata, never an installed trust policy."""
    # mkso:body:begin
    blob = base64.b64decode(public_key.split()[1], validate=True)
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    revocations = b""
    metadata = {
        "schema_version": "mkso-bootstrap-approval-identity-request/1",
        "authority": "NONE",
        "status": "OPERATOR_PROVISIONING_REQUIRED",
        "principal": principal,
        "public_key": public_key,
        "public_key_file": "approval-key.pub",
        "public_key_fingerprint": fingerprint,
        "key_valid_after": int(valid_after.timestamp()),
        "key_valid_before": int(valid_before.timestamp()),
        "intended_namespace": "mkso.bootstrap-action-approval.v1",
        "revocation_policy": "explicit_empty_key_list",
        "revocations_file": "revocations.txt",
        "revocations_sha256": hashlib.sha256(revocations).hexdigest(),
        "generator_ssh_keygen_sha256": executable_hash,
    }
    raw = json.dumps(metadata, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "ascii"
    )
    _write_public(directory, "approval-key.pub", (public_key + "\n").encode("ascii"))
    _write_public(directory, "revocations.txt", revocations)
    # Write the complete metadata last. No earlier file is a completed bundle.
    _write_public(directory, "identity.json", raw)
    print("Public-key fingerprint:", fingerprint)
    return hashlib.sha256(raw).hexdigest()
    # mkso:body:end


def main() -> int:
    """Require a real terminal, explicit human choices and an external fresh destination."""
    # mkso:body:begin
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--output-dir", help="fresh absolute directory outside Git worktrees")
    parser.add_argument("--ssh-keygen", default="/usr/bin/ssh-keygen")
    args = parser.parse_args()
    created = None
    try:
        _require(sys.version_info >= (3, 12), "Python 3.12 or newer is required.")
        _require(os.getuid() != 0, "Run as your normal operator account, not root.")
        _require(
            sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty(),
            "Run in your own interactive terminal, without pipes, redirection or an agent.",
        )
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.umask(0o077)
        repository = args.repository_root.expanduser()
        _require(
            repository.is_absolute(),
            "--repository-root must be the absolute workspace path to exclude.",
        )
        # The excluded workspace need not exist on a separate signing machine.
        repository = repository.resolve(strict=False)
        executable, executable_hash = _tool(args.ssh_keygen)
        print("This creates a NEW dedicated approval key, not an installed mkso trust policy.")
        print("Do not run inside a recorded terminal, notebook, container or model session.")
        output = _destination(
            args.output_dir or input("New external output directory (absolute path): ").strip(),
            repository,
        )
        principal = input("Signer name [mkso-approver]: ").strip() or "mkso-approver"
        _require(
            re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", principal) is not None,
            "Signer name must be 1..128 ASCII letters, digits, or _.@-.",
        )
        now = datetime.now(UTC).replace(microsecond=0)
        default_start = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        start = _timestamp(input(f"Valid from [{default_start}]: ").strip() or default_start)
        default_end = (start + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = _timestamp(input(f"Valid until, exclusive [{default_end}]: ").strip() or default_end)
        _require(start < end and end > now, "Expiry must follow the start and be in the future.")
        print("The validity dates are policy metadata; a raw SSH key does not expire by itself.")
        _require(
            input("Type NONE to explicitly start with no revoked keys: ").strip() == "NONE",
            "No revocation policy was confirmed; nothing will be generated.",
        )
        print("\nReview:")
        print("  Signer:", principal)
        print("  Valid from:", start.isoformat())
        print("  Valid until (exclusive):", end.isoformat())
        print("  New private directory:", output / "private")
        print("  Public handoff directory:", output / "public")
        print("  Revocations: explicitly empty")
        _require(
            input("Type CREATE to generate this identity: ").strip() == "CREATE",
            "Creation was not confirmed; nothing will be generated.",
        )
        # Revalidate immediately before exclusive creation; trust in the local
        # owner/root and filesystem remains an explicit out-of-band premise.
        _require(_destination(str(output), repository) == output, "Destination changed.")
        output.mkdir(mode=0o700)
        created = output
        private = output / "private"
        private.mkdir(mode=0o700)
        key = _generate(private, executable, executable_hash)
        public = output / "public"
        public.mkdir(mode=0o700)
        digest = _bundle(public, key, principal, start, end, executable_hash)
        print("\nCreated public provisioning request:", public)
        print("Public identity.json SHA-256:", digest)
        print("Share ONLY the public/ directory. Never share private/ or the parent directory.")
        print("Keep the private key and passphrase out of Git, Docker, .env, chat and model tools.")
        print("No trust policy was installed and no mkso action was approved.")
        return 0
    except SetupError as exc:
        print("Setup stopped:", str(exc), file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print("\nSetup cancelled.", file=sys.stderr)
    except Exception:
        print(
            "Setup failed; no provisioning is established. Native errors are not approval.",
            file=sys.stderr,
        )
    if created is not None:
        print(
            "Partial output was retained. Do not share it; inspect the chosen directory locally.",
            file=sys.stderr,
        )
    return 1
    # mkso:body:end


if __name__ == "__main__":
    raise SystemExit(main())
