"""Read-only policy enforcement."""

from pathlib import Path

READ_ONLY_GIT_SUBCOMMANDS = frozenset(
    {"branch", "diff", "ls-files", "remote", "rev-parse", "status"}
)


def assert_read_only_git(argv: list[str]) -> None:
    if not argv or argv[0] not in READ_ONLY_GIT_SUBCOMMANDS:
        raise PermissionError(f"Git subcommand is not read-only allowlisted: {argv!r}")


def assert_target_unchanged(before: dict[str, tuple[int, int]], target: Path) -> None:
    after = filesystem_snapshot(target)
    if before != after:
        raise RuntimeError("target filesystem changed during read-only inspection")


def filesystem_snapshot(target: Path) -> dict[str, tuple[int, int]]:
    if not target.exists():
        return {}
    if target.is_file():
        stat = target.stat()
        return {str(target.resolve()): (stat.st_size, stat.st_mtime_ns)}
    result: dict[str, tuple[int, int]] = {}
    children = (child for child in target.iterdir() if child.name != ".git")
    for child in sorted(children, key=lambda item: item.name)[:500]:
        stat = child.stat()
        result[str(child.resolve())] = (stat.st_size, stat.st_mtime_ns)
    return result
