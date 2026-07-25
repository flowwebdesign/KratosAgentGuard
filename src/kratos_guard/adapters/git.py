"""Read-only Git observations."""

import subprocess
from pathlib import Path

from kratos_guard.core.policy import assert_read_only_git
from kratos_guard.models import CommandEvidence


def run_git(path: Path, arguments: list[str]) -> CommandEvidence:
    assert_read_only_git(arguments)
    completed = subprocess.run(
        ["git", "-C", str(path), *arguments],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    return CommandEvidence(
        argv=["git", "-C", str(path), *arguments],
        cwd=str(path),
        exit_code=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def git_value(path: Path, arguments: list[str]) -> str:
    evidence = run_git(path, arguments)
    return evidence.stdout if evidence.exit_code == 0 else ""
