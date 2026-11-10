"""Disposable per-run copies of the synthetic demo repository."""

from __future__ import annotations

import shutil
from pathlib import Path

from app.agents.runner import CommandRunner
from app.config import REPO_ROOT

TEMPLATE = REPO_ROOT / "demo-workspace"
# Scenario 2 regression: carry folding is dropped from the checksum loop.
CI_REGRESSION_OLD = "        total = (total & 0xFFFF) + (total >> 16)\n"
CI_REGRESSION_NEW = "        total = total & 0xFFFF  # fold only at the end (optimisation)\n"


class WorkspaceError(Exception):
    pass


def create_workspace(root: Path, run_id: str, scenario: str) -> tuple[Path, CommandRunner]:
    """Copies the template, initialises git with history, and applies scenario setup."""
    if not TEMPLATE.is_dir():
        raise WorkspaceError(f"demo workspace template missing at {TEMPLATE}")
    root.mkdir(parents=True, exist_ok=True)
    path = root / run_id
    if path.exists():
        raise WorkspaceError(f"workspace {path} already exists")
    shutil.copytree(TEMPLATE, path)
    runner = CommandRunner(path, root)
    for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "Initial import of packet-gateway service"]):
        result = runner.run("git", args)
        if result.returncode != 0:
            raise WorkspaceError(f"git {args[0]} failed: {result.stderr.strip()}")
    if scenario == "failed_ci":
        target = path / "pgw" / "checksum.py"
        source = target.read_text()
        if CI_REGRESSION_OLD not in source:
            raise WorkspaceError("template changed; cannot stage the CI regression")
        target.write_text(source.replace(CI_REGRESSION_OLD, CI_REGRESSION_NEW))
        for args in (["add", "pgw/checksum.py"], ["commit", "-q", "-m", "Optimise checksum carry folding"]):
            result = runner.run("git", args)
            if result.returncode != 0:
                raise WorkspaceError(f"git {args[0]} failed: {result.stderr.strip()}")
    return path, runner


def inside(workspace: Path, relative: str) -> Path:
    """Resolves a workspace-relative path, rejecting anything that escapes the workspace."""
    candidate = (workspace / relative).resolve()
    if candidate != workspace.resolve() and workspace.resolve() not in candidate.parents:
        raise WorkspaceError(f"path {relative!r} escapes the workspace")
    return candidate
