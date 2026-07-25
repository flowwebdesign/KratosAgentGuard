"""Bounded Git and sentinel mutation witness."""

import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from kratos_guard.core.hashing import hash_file
from kratos_guard.models.provenance import MutationSnapshot, MutationWitnessResult


def _git_bytes(root: Path, arguments: list[str]) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        check=False,
        timeout=20,
    )
    if completed.returncode not in {0, 1}:
        return f"INSPECTION_FAILED:{arguments[0]}".encode()
    if len(completed.stdout) > 25_000_000:
        return f"COVERAGE_LIMIT_EXCEEDED:{arguments[0]}".encode()
    return completed.stdout


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


class MutationWitness:
    def __init__(self, target: Path, sentinels: list[str]) -> None:
        self.target = target.resolve()
        self.sentinels = sentinels
        self.started_at = datetime.now(UTC)
        self.before = self.capture()

    def capture(self) -> MutationSnapshot:
        sentinel_hashes = []
        for relative in self.sentinels:
            candidate = self.target / relative
            if candidate.is_file() and not candidate.is_symlink():
                sentinel_hashes.append(hash_file(candidate))
        stat = self.target.stat()
        root_metadata = f"{self.target}|{stat.st_mode}|{stat.st_size}".encode()
        return MutationSnapshot(
            captured_at=datetime.now(UTC),
            git_status_hash=_digest(
                _git_bytes(self.target, ["status", "--porcelain=v2", "--untracked-files=all", "-z"])
            ),
            tracked_diff_hash=_digest(
                _git_bytes(self.target, ["diff", "--no-ext-diff", "--binary"])
            ),
            staged_diff_hash=_digest(
                _git_bytes(self.target, ["diff", "--cached", "--no-ext-diff", "--binary"])
            ),
            conflicted_paths_hash=_digest(
                _git_bytes(self.target, ["diff", "--name-only", "--diff-filter=U", "-z"])
            ),
            untracked_manifest_hash=_digest(
                _git_bytes(self.target, ["ls-files", "--others", "--exclude-standard", "-z"])
            ),
            sentinel_hashes=sentinel_hashes,
            root_metadata_hash=_digest(root_metadata),
            coverage=[
                "Git porcelain-v2 status",
                "tracked working-tree diff",
                "staged diff",
                "conflicted paths",
                "untracked path manifest",
                "configured sentinel file bytes",
                "target root mode and size",
            ],
            exclusions=[
                "Git object storage bytes",
                "non-sentinel ignored files",
                "kernel-level write monitoring",
            ],
        )

    def finish(self) -> MutationWitnessResult:
        after = self.capture()
        changed = self.before.model_dump(exclude={"captured_at"}) != after.model_dump(
            exclude={"captured_at"}
        )
        return MutationWitnessResult(
            started_at=self.started_at,
            finished_at=datetime.now(UTC),
            before=self.before,
            after=after,
            changed=changed,
            verdict="TARGET_CHANGED_DURING_INSPECTION" if changed else "NO_OBSERVED_TARGET_CHANGE",
            limitations=[
                "Zero observed change is limited to witness coverage.",
                "This is not kernel-level write prevention.",
            ],
        )
