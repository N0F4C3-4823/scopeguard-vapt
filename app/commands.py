from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import signal
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

SAFE_EXECUTABLES = {
    Path(sys.executable).name,
    "python",
    "python3",
    "nmap",
    "openssl",
    "curl",
    "dig",
    "nc",
    "ssh-keyscan",
}


def iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class CommandRejected(ValueError):
    pass


def _tool_version(executable: str) -> str:
    """Read a short version string from an allowlisted executable only."""
    name = Path(executable).name
    if name in {Path(sys.executable).name, "python", "python3"}:
        return f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    version_args = {
        "nmap": ("--version",),
        "curl": ("--version",),
        "openssl": ("version",),
        "dig": ("-v",),
        "ssh-keyscan": ("-V",),
        "nc": ("-h",),
    }.get(name)
    if not version_args:
        return "unknown"
    resolved = shutil.which(executable) or executable
    try:
        probe = subprocess.run(
            [resolved, *version_args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            shell=False,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    output = (probe.stdout + probe.stderr).decode("utf-8", errors="replace").strip()
    return output.splitlines()[0][:240] if output else "unknown"


@dataclass(frozen=True)
class CommandResult:
    id: str
    argv: tuple[str, ...]
    displayed_command: str
    cwd: str
    started_at: str
    ended_at: str
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes
    status: str
    tool_version: str

    @property
    def stdout_sha256(self) -> str:
        return sha256_bytes(self.stdout)

    @property
    def stderr_sha256(self) -> str:
        return sha256_bytes(self.stderr)

    @property
    def combined_output(self) -> bytes:
        return self.stdout + self.stderr

    @property
    def combined_sha256(self) -> str:
        return sha256_bytes(self.combined_output)


def validate_argv(argv: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not argv or any(not isinstance(item, str) or not item for item in argv):
        raise CommandRejected("Command argv must contain non-empty strings")
    executable = Path(argv[0]).name
    if executable not in SAFE_EXECUTABLES:
        raise CommandRejected(f"Executable is not allowlisted: {executable}")
    if any("\x00" in item for item in argv):
        raise CommandRejected("Command argv contains a NUL byte")
    return tuple(argv)


def run_command(
    argv: list[str] | tuple[str, ...],
    *,
    timeout_seconds: float,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> CommandResult:
    safe_argv = validate_argv(argv)
    started_at = iso_now()
    command_id = str(uuid.uuid4())
    process: subprocess.Popen[bytes] | None = None
    stdout = b""
    stderr = b""
    exit_code: int | None = None
    timed_out = False
    try:
        process = subprocess.Popen(
            list(safe_argv),
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            exit_code = process.returncode
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout = error.stdout or b""
            stderr = error.stderr or b""
            os.killpg(process.pid, signal.SIGTERM)
            try:
                more_stdout, more_stderr = process.communicate(timeout=1)
                stdout += more_stdout or b""
                stderr += more_stderr or b""
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                more_stdout, more_stderr = process.communicate()
                stdout += more_stdout or b""
                stderr += more_stderr or b""
            exit_code = process.returncode
    except OSError as error:
        stderr = str(error).encode("utf-8", errors="replace")
        exit_code = None
    ended_at = iso_now()
    if timed_out:
        status = "TIMEOUT"
    elif exit_code == 0:
        status = "COMPLETED"
    else:
        status = "FAILED"
    return CommandResult(
        id=command_id,
        argv=safe_argv,
        displayed_command=shlex.join(safe_argv),
        cwd=str(cwd),
        started_at=started_at,
        ended_at=ended_at,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        status=status,
        tool_version=_tool_version(safe_argv[0]),
    )
