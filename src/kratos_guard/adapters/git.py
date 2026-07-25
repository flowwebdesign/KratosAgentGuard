"""Read-only Git observations."""

import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from kratos_guard.core.policy import assert_read_only_git
from kratos_guard.models import CommandEvidence
from kratos_guard.reporting.redaction import redact_text


def run_git(path: Path, arguments: list[str]) -> CommandEvidence:
    assert_read_only_git(arguments)
    started = datetime.now(UTC)
    timed_out = False
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        raw_stdout = error.stdout or ""
        raw_stderr = error.stderr or ""
        stdout = (
            raw_stdout.decode(errors="replace") if isinstance(raw_stdout, bytes) else raw_stdout
        )
        stderr = (
            raw_stderr.decode(errors="replace") if isinstance(raw_stderr, bytes) else raw_stderr
        )
        exit_code = 124
    finished = datetime.now(UTC)
    return CommandEvidence(
        command_id=str(uuid4()),
        started_at=started,
        finished_at=finished,
        duration_ms=(finished - started).total_seconds() * 1000,
        executable="git",
        sanitised_arguments=[redact_text(item) for item in ["-C", str(path), *arguments]],
        working_directory=str(path),
        exit_code=exit_code,
        stdout_sha256=sha256(stdout.encode()).hexdigest(),
        stderr_sha256=sha256(stderr.encode()).hexdigest(),
        stdout_excerpt=redact_text(stdout[:4096]).strip(),
        stderr_excerpt=redact_text(stderr[:4096]).strip(),
        mutation_classification="READ_ONLY",
        policy_decision="ALLOW",
        timed_out=timed_out,
    )


def git_value(path: Path, arguments: list[str]) -> str:
    evidence = run_git(path, arguments)
    return evidence.stdout_excerpt if evidence.exit_code == 0 else ""
