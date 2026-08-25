"""Safe argv-only execution boundary for pinned native build tools."""

from __future__ import annotations

import shlex
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class ToolError(RuntimeError):
    """Raised when a native tool cannot complete successfully."""


@dataclass(frozen=True)
class CompletedTool:
    """Captured result of one successful native-tool invocation."""

    argv: tuple[str, ...]
    cwd: Path
    returncode: int
    stdout: str
    stderr: str


class ToolRunner:
    """Run native tools without invoking a shell."""

    def __init__(self, timeout_seconds: float = 60.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.timeout_seconds = timeout_seconds

    def run(self, argv: Sequence[str], cwd: Path) -> CompletedTool:
        """Run one argv in an existing working directory or raise ``ToolError``."""

        command = _validated_argv(argv)
        working_directory = Path(cwd)
        if not working_directory.is_dir():
            raise ValueError(
                f"working directory does not exist: {working_directory}"
            )
        try:
            completed = subprocess.run(
                command,
                cwd=working_directory,
                capture_output=True,
                check=False,
                shell=False,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            stdout = _timeout_text(error.stdout)
            stderr = _timeout_text(error.stderr)
            raise ToolError(
                _diagnostic(
                    command,
                    (
                        "timed out after "
                        f"{self.timeout_seconds:g} seconds"
                    ),
                    stdout,
                    stderr,
                )
            ) from error
        except OSError as error:
            raise ToolError(
                f"cannot execute {shlex.join(command)}: {error}"
            ) from error

        if completed.returncode != 0:
            raise ToolError(
                _diagnostic(
                    command,
                    f"exited with status {completed.returncode}",
                    completed.stdout,
                    completed.stderr,
                )
            )
        return CompletedTool(
            argv=command,
            cwd=working_directory,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _validated_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise TypeError("argv must be a sequence of argument strings, not a command")
    command = tuple(argv)
    if not command:
        raise ValueError("argv must not be empty")
    if any(not isinstance(argument, str) for argument in command):
        raise TypeError("every argv item must be a string")
    if any(not argument for argument in command):
        raise ValueError("argv items must not be empty")
    return command


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _diagnostic(
    argv: tuple[str, ...], reason: str, stdout: str, stderr: str
) -> str:
    details = [f"tool {shlex.join(argv)} {reason}"]
    if stdout:
        details.append(f"stdout:\n{stdout.rstrip()}")
    if stderr:
        details.append(f"stderr:\n{stderr.rstrip()}")
    return "\n".join(details)
