import subprocess
from pathlib import Path

from kratos_guard.core.mutation_witness import MutationWitness


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    (root / "tracked.txt").write_text("one", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "tracked.txt"], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "initial"], check=True, capture_output=True
    )
    return root


def test_witness_detects_changed_tracked_file(tmp_path: Path) -> None:
    root = repository(tmp_path)
    witness = MutationWitness(root, ["tracked.txt"])
    (root / "tracked.txt").write_text("two", encoding="utf-8")
    assert witness.finish().verdict == "TARGET_CHANGED_DURING_INSPECTION"


def test_witness_detects_changed_untracked_manifest(tmp_path: Path) -> None:
    root = repository(tmp_path)
    witness = MutationWitness(root, [])
    (root / "new.txt").write_text("new", encoding="utf-8")
    assert witness.finish().changed


def test_witness_preserves_dirty_unchanged_repository(tmp_path: Path) -> None:
    root = repository(tmp_path)
    (root / "tracked.txt").write_text("already dirty", encoding="utf-8")
    witness = MutationWitness(root, ["tracked.txt"])
    result = witness.finish()
    assert not result.changed
    assert result.verdict == "NO_OBSERVED_TARGET_CHANGE"
