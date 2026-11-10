"""Sandboxed command execution for agent tools.

Only tool code builds commands, never the LLM. Guarantees enforced here:

- fixed executables only (`python` = this interpreter, `git`), resolved to
  absolute paths at start-up;
- argv lists only, never a shell, with each argument checked (no NUL bytes,
  bounded length);
- an allowlist of argument prefixes per executable (`python -m pytest|pyflakes`;
  a fixed set of git subcommands);
- the working directory must be inside the run's disposable workspace;
- a scrubbed environment (no inherited secrets, no user/system git config,
  no LD_PRELOAD);
- a timeout and output truncation.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

MAX_ARG_LENGTH = 4096
MAX_OUTPUT_CHARS = 20_000
PYTHON_MODULES = frozenset({"pytest", "pyflakes"})
GIT_SUBCOMMANDS = frozenset({"init", "add", "commit", "diff", "log", "apply", "status", "rev-parse", "show"})


class CommandNotAllowed(Exception):
    """The requested command violates the runner's allowlist."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_s: float

    def to_dict(self) -> dict[str, object]:
        return {"argv": list(self.argv), "returncode": self.returncode, "stdout": self.stdout,
                "stderr": self.stderr, "timed_out": self.timed_out, "duration_s": round(self.duration_s, 3)}


def _executables() -> dict[str, str]:
    found = {"python": sys.executable}
    git = shutil.which("git")
    if git:
        found["git"] = git
    return found


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_OUTPUT_CHARS else text[:MAX_OUTPUT_CHARS] + "\n...[truncated]"


class CommandRunner:
    def __init__(self, workspace: Path, workspace_root: Path, default_timeout_s: float = 120.0) -> None:
        workspace = workspace.resolve()
        root = workspace_root.resolve()
        if root not in workspace.parents:
            raise CommandNotAllowed(f"workspace {workspace} is not inside {root}")
        self.workspace = workspace
        self.default_timeout_s = default_timeout_s
        self.executables = _executables()

    def _environment(self) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.workspace), "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                "GIT_AUTHOR_NAME": "aegis-agent", "GIT_AUTHOR_EMAIL": "agent@aegis.invalid",
                "GIT_COMMITTER_NAME": "aegis-agent", "GIT_COMMITTER_EMAIL": "agent@aegis.invalid"}

    def _check(self, program: str, args: Sequence[str]) -> list[str]:
        if program not in self.executables:
            raise CommandNotAllowed(f"executable {program!r} is not allowlisted")
        checked = []
        for arg in args:
            if not isinstance(arg, str) or "\x00" in arg or len(arg) > MAX_ARG_LENGTH:
                raise CommandNotAllowed("invalid argument")
            checked.append(arg)
        if program == "python":
            if len(checked) < 2 or checked[0] != "-m" or checked[1] not in PYTHON_MODULES:
                raise CommandNotAllowed("python may only run: -m " + "|".join(sorted(PYTHON_MODULES)))
        if program == "git":
            subcommand = next((a for a in checked if not a.startswith("-")), None)
            if subcommand not in GIT_SUBCOMMANDS or any(a.startswith("-c") for a in checked):
                raise CommandNotAllowed(f"git subcommand {subcommand!r} is not allowlisted")
        return checked

    def run(self, program: str, args: Sequence[str], timeout_s: float | None = None) -> CommandResult:
        argv = [self.executables.get(program, program), *self._check(program, args)]
        import time

        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, allowlisted executable, no shell
                argv, cwd=self.workspace, env=self._environment(), capture_output=True, text=True,
                timeout=timeout_s or self.default_timeout_s, shell=False, check=False,
                stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return CommandResult(tuple(argv), None, _truncate(out), "timed out", True,
                                 time.monotonic() - started)
        return CommandResult(tuple(argv), completed.returncode, _truncate(completed.stdout),
                             _truncate(completed.stderr), False, time.monotonic() - started)
