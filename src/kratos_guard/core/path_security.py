"""Canonical protected-path and output policy."""

import os
from pathlib import Path

from pydantic import Field

from kratos_guard.models.evidence import StrictModel


class ProtectedPath(StrictModel):
    path: str
    reason: str


class PathContainmentResult(StrictModel):
    candidate: str
    protected_path: str = ""
    contained: bool
    reason: str


def canonical_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _normalised(path: Path) -> str:
    return os.path.normcase(str(canonical_path(path)))


def contains(root: Path, candidate: Path) -> bool:
    root_value = _normalised(root)
    candidate_value = _normalised(candidate)
    try:
        return os.path.commonpath([root_value, candidate_value]) == root_value
    except ValueError:
        return False


class SafeOutputPolicy(StrictModel):
    verifier_root: str
    authorised_external_roots: list[str] = Field(default_factory=list)
    protected_paths: list[ProtectedPath] = Field(default_factory=list)

    def evaluate(self, output: Path) -> PathContainmentResult:
        resolved = canonical_path(output)
        for protected in self.protected_paths:
            if contains(Path(protected.path), resolved):
                return PathContainmentResult(
                    candidate=str(resolved),
                    protected_path=str(canonical_path(Path(protected.path))),
                    contained=True,
                    reason=protected.reason,
                )
        allowed = contains(Path(self.verifier_root), resolved) or any(
            contains(Path(root), resolved) for root in self.authorised_external_roots
        )
        return PathContainmentResult(
            candidate=str(resolved),
            contained=False,
            reason="authorised output root" if allowed else "outside authorised output roots",
        )

    def require_safe(self, output: Path) -> Path:
        result = self.evaluate(output)
        if result.contained or result.reason != "authorised output root":
            raise ValueError(f"unsafe output path: {result.reason}: {result.candidate}")
        return Path(result.candidate)
