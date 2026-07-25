import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kratos_guard.core.artifacts import (
    discover_artifacts,
    parse_static_javascript_metadata,
    source_to_build_link,
)
from kratos_guard.core.manifests import generate_manifest
from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import (
    ArtifactCandidate,
    ArtifactManifest,
    SourceManifest,
)


def initialise(root: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)


def test_source_manifest_is_deterministic(tmp_path: Path) -> None:
    initialise(tmp_path)
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    first = generate_manifest(tmp_path)
    second = generate_manifest(tmp_path)
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.included_paths == ["a.txt", "b.txt"]


def test_dirty_working_bytes_change_manifest(tmp_path: Path) -> None:
    initialise(tmp_path)
    path = tmp_path / "a.txt"
    path.write_text("clean", encoding="utf-8")
    clean = generate_manifest(tmp_path)
    path.write_text("dirty", encoding="utf-8")
    assert generate_manifest(tmp_path).manifest_sha256 != clean.manifest_sha256


def test_excluded_files_do_not_affect_manifest(tmp_path: Path) -> None:
    initialise(tmp_path)
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    cache = tmp_path / "node_modules"
    cache.mkdir()
    (cache / "x.js").write_text("one", encoding="utf-8")
    first = generate_manifest(tmp_path)
    (cache / "x.js").write_text("two", encoding="utf-8")
    assert generate_manifest(tmp_path).manifest_sha256 == first.manifest_sha256


def test_manifest_maximum_file_count(tmp_path: Path) -> None:
    initialise(tmp_path)
    (tmp_path / "a").write_text("a", encoding="utf-8")
    (tmp_path / "b").write_text("b", encoding="utf-8")
    with pytest.raises(ValueError, match="maximum file count"):
        generate_manifest(tmp_path, max_files=1)


def test_manifest_maximum_total_bytes(tmp_path: Path) -> None:
    initialise(tmp_path)
    (tmp_path / "a").write_text("large", encoding="utf-8")
    with pytest.raises(ValueError, match="maximum total bytes"):
        generate_manifest(tmp_path, max_total_bytes=2)


def test_staged_state_is_recorded(tmp_path: Path) -> None:
    initialise(tmp_path)
    (tmp_path / "a").write_text("a", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "a"], check=True)
    assert generate_manifest(tmp_path).staged


def test_symlink_is_recorded_without_following(tmp_path: Path) -> None:
    initialise(tmp_path)
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    manifest = generate_manifest(tmp_path)
    entry = next(item for item in manifest.entries if item.path == "link.txt")
    assert entry.kind == "symlink"
    assert entry.sha256 == ""


def test_static_javascript_parser_never_executes(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    script = tmp_path / "buildInfo.js"
    script.write_text(
        f'require("fs").writeFileSync("{marker}", "bad"); version: "1.0"', encoding="utf-8"
    )
    assert parse_static_javascript_metadata(script) == {}
    assert not marker.exists()


def test_artifact_discovery_respects_count_limit(tmp_path: Path) -> None:
    initialise(tmp_path)
    artifact_root = tmp_path / "extension"
    artifact_root.mkdir()
    (artifact_root / "a").write_text("a", encoding="utf-8")
    (artifact_root / "b").write_text("b", encoding="utf-8")
    profile = {
        "build_discovery_roots": ["extension"],
        "limits": {"artifact_max_files": 1, "artifact_max_bytes": 100},
    }
    with pytest.raises(ValueError, match="maximum file count"):
        discover_artifacts(tmp_path, profile)


def source(hash_value: str = "a" * 64, head: str = "abcdef") -> SourceManifest:
    return SourceManifest(
        repository_root="repo",
        git_common_directory="repo/.git",
        branch="main",
        head=head,
        dirty=True,
        staged=False,
        scope=".",
        included_paths=[],
        excluded_paths=[],
        file_count=0,
        total_bytes=0,
        entries=[],
        manifest_sha256=hash_value,
        generated_at=datetime.now(UTC),
        tool_version="0.2.0",
        state=EvidenceState.PROVEN,
    )


def artifact(**changes: str) -> ArtifactManifest:
    values = {
        "embedded_version": "1.0",
        "embedded_git_head": "",
        "embedded_source_hash": "",
    }
    values.update(changes)
    return ArtifactManifest(
        candidate=ArtifactCandidate(
            path="folder-named-build-abcdef",
            artifact_type="extension_directory",
            discovery_method="test",
            evidence_state=EvidenceState.PROVEN,
        ),
        file_count=1,
        total_bytes=1,
        manifest_sha256="b" * 64,
        **values,
    )


def test_folder_name_and_version_do_not_prove_build() -> None:
    assert source_to_build_link(source(), artifact()).verdict is EvidenceState.UNPROVEN


def test_matching_head_alone_is_insufficient_for_dirty_source() -> None:
    assert (
        source_to_build_link(source(), artifact(embedded_git_head="abcdef")).verdict
        is EvidenceState.UNPROVEN
    )


def test_matching_head_and_source_hash_proves_link() -> None:
    link = source_to_build_link(
        source(), artifact(embedded_git_head="abcdef", embedded_source_hash="a" * 64)
    )
    assert link.verdict is EvidenceState.PROVEN


def test_mismatched_source_hash_is_contradicted() -> None:
    link = source_to_build_link(source(), artifact(embedded_source_hash="c" * 64))
    assert link.verdict is EvidenceState.CONTRADICTED
