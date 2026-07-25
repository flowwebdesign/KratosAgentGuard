from pathlib import Path

from kratos_guard.core.bootstrap_gate import BootstrapFacts, bootstrap_verdict


def facts(**changes: object) -> BootstrapFacts:
    values: dict[str, object] = {
        "remote_matches": True,
        "remote_empty": True,
        "local_path": Path("guard"),
        "local_entries": (),
        "inside_target_worktree": False,
    }
    values.update(changes)
    return BootstrapFacts(**values)  # type: ignore[arg-type]


def test_empty_remote_is_valid_start() -> None:
    assert bootstrap_verdict(facts()) == "PASS_TO_BOOTSTRAP"


def test_missing_head_is_not_blocker() -> None:
    assert bootstrap_verdict(facts(head="")) == "PASS_TO_BOOTSTRAP"


def test_missing_common_directory_is_not_blocker() -> None:
    assert bootstrap_verdict(facts(local_git_common_directory="")) == "PASS_TO_BOOTSTRAP"


def test_inside_target_worktree_blocks() -> None:
    assert bootstrap_verdict(facts(inside_target_worktree=True)) == "BLOCKED_STANDALONE_BOUNDARY"


def test_outside_target_authority_passes() -> None:
    assert bootstrap_verdict(facts(inside_target_worktree=False)) == "PASS_TO_BOOTSTRAP"


def test_unexplained_files_block() -> None:
    assert (
        bootstrap_verdict(facts(local_entries=("mystery.txt",))) == "BLOCKED_LOCAL_PATH_OWNERSHIP"
    )
