"""Bootstrap-specific authority semantics."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BootstrapFacts:
    remote_matches: bool
    remote_empty: bool
    local_path: Path
    local_entries: tuple[str, ...]
    inside_target_worktree: bool
    local_git_common_directory: str = ""
    head: str = ""


def bootstrap_verdict(facts: BootstrapFacts) -> str:
    if not facts.remote_matches or not facts.remote_empty:
        return "BLOCKED_REMOTE_AUTHORITY"
    if facts.inside_target_worktree:
        return "BLOCKED_STANDALONE_BOUNDARY"
    authorised = {"evidence"}
    if any(entry not in authorised for entry in facts.local_entries):
        return "BLOCKED_LOCAL_PATH_OWNERSHIP"
    return "PASS_TO_BOOTSTRAP"
