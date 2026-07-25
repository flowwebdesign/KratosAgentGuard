"""Deterministic bounded source and artefact manifests."""

import os
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from kratos_guard import __version__
from kratos_guard.adapters.git import git_value, run_git
from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import ManifestEntry, SourceManifest

DEFAULT_EXCLUSIONS = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "build",
    ".next",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "logs",
}
EXCLUDED_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".log", ".pyc"}


def _normalise(relative: Path) -> str:
    return relative.as_posix()


def _entry_bytes(entry: ManifestEntry) -> bytes:
    return (
        f"{entry.path}\0{entry.kind}\0{entry.size}\0{entry.sha256}\0{entry.link_target}\n"
    ).encode()


def generate_manifest(
    root: Path,
    *,
    scope: str = ".",
    max_files: int = 5000,
    max_total_bytes: int = 100_000_000,
    exclusions: set[str] | None = None,
) -> SourceManifest:
    root = root.resolve()
    excluded_names = DEFAULT_EXCLUSIONS | (exclusions or set())
    entries: list[ManifestEntry] = []
    excluded_paths: list[str] = []
    total = 0
    scope_root = (root / scope).resolve()
    if os.path.commonpath([str(root), str(scope_root)]) != str(root):
        raise ValueError("manifest scope escapes source root")
    for current, directories, files in os.walk(scope_root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in excluded_names and not (current_path / directory).is_symlink()
        )
        for name in sorted(files):
            path = current_path / name
            relative = path.relative_to(root)
            relative_value = _normalise(relative)
            if name in excluded_names or path.suffix.lower() in EXCLUDED_SUFFIXES:
                excluded_paths.append(relative_value)
                continue
            if len(entries) >= max_files:
                raise ValueError(f"maximum file count exceeded: {max_files}")
            if path.is_symlink():
                target = os.readlink(path)
                entries.append(
                    ManifestEntry(
                        path=relative_value,
                        kind="symlink",
                        size=0,
                        link_target=target,
                    )
                )
                continue
            try:
                size = path.stat().st_size
                if total + size > max_total_bytes:
                    raise ValueError(f"maximum total bytes exceeded: {max_total_bytes}")
                digest = sha256(path.read_bytes()).hexdigest()
            except PermissionError as error:
                raise ValueError(f"unreadable manifest file: {relative_value}") from error
            total += size
            entries.append(
                ManifestEntry(path=relative_value, kind="file", size=size, sha256=digest)
            )
    entries.sort(key=lambda item: item.path.casefold())
    overall = sha256(b"".join(_entry_bytes(entry) for entry in entries)).hexdigest()
    common = git_value(root, ["rev-parse", "--git-common-dir"])
    status = run_git(root, ["status", "--porcelain=v2", "--untracked-files=all"])
    staged = run_git(root, ["diff", "--cached", "--name-only"])
    return SourceManifest(
        repository_root=str(root),
        git_common_directory=str((root / common).resolve()) if common else "",
        branch=git_value(root, ["branch", "--show-current"]),
        head=git_value(root, ["rev-parse", "--verify", "HEAD"]),
        dirty=bool(status.stdout_excerpt),
        staged=bool(staged.stdout_excerpt),
        scope=scope,
        included_paths=[entry.path for entry in entries],
        excluded_paths=sorted(excluded_paths),
        file_count=len(entries),
        total_bytes=total,
        entries=entries,
        manifest_sha256=overall,
        generated_at=datetime.now(UTC),
        tool_version=__version__,
        state=EvidenceState.PROVEN,
        limitations=[
            "Manifest represents current working-tree bytes, not clean HEAD alone."
            if status.stdout_excerpt
            else "Manifest represents observed working-tree bytes."
        ],
    )
