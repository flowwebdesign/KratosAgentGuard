import os
from pathlib import Path

import pytest

from kratos_guard.core.path_security import ProtectedPath, SafeOutputPolicy, contains


def policy(guard: Path, target: Path) -> SafeOutputPolicy:
    return SafeOutputPolicy(
        verifier_root=str(guard),
        protected_paths=[ProtectedPath(path=str(target), reason="target")],
    )


def test_output_directly_inside_target_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        policy(tmp_path / "guard", tmp_path / "target").require_safe(
            tmp_path / "target/report.json"
        )


def test_output_in_target_subdirectory_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target"
    with pytest.raises(ValueError):
        policy(tmp_path / "guard", target).require_safe(target / "nested" / "report.json")


def test_path_traversal_into_target_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        policy(tmp_path / "guard", tmp_path / "target").require_safe(
            tmp_path / "guard" / ".." / "target" / "report.json"
        )


def test_similar_prefix_is_not_containment(tmp_path: Path) -> None:
    assert not contains(tmp_path / "target", tmp_path / "target-sibling" / "report.json")


def test_authorised_guard_evidence_path_passes(tmp_path: Path) -> None:
    guard, target = tmp_path / "guard", tmp_path / "target"
    result = policy(guard, target).require_safe(guard / "evidence" / "report.json")
    assert result.name == "report.json"


def test_relative_path_resolves_under_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard, target = tmp_path / "guard", tmp_path / "target"
    guard.mkdir()
    monkeypatch.chdir(guard)
    assert policy(guard, target).require_safe(Path("evidence/report.json")).is_absolute()


@pytest.mark.skipif(os.name != "nt", reason="Windows path rule")
def test_windows_comparison_is_case_insensitive(tmp_path: Path) -> None:
    target = tmp_path / "Target"
    assert contains(target, Path(str(target).upper()) / "child")


def test_different_root_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        policy(tmp_path / "guard", tmp_path / "target").require_safe(tmp_path / "elsewhere/x")


@pytest.mark.skipif(os.name != "nt", reason="Windows drive semantics")
def test_different_drive_is_not_false_containment() -> None:
    assert not contains(Path("C:/target"), Path("D:/evidence/report.json"))


def test_symlink_into_target_rejected_when_supported(tmp_path: Path) -> None:
    guard, target = tmp_path / "guard", tmp_path / "target"
    guard.mkdir()
    target.mkdir()
    link = guard / "linked"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError):
        policy(guard, target).require_safe(link / "report.json")
