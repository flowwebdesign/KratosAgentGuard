import json
import subprocess
from pathlib import Path

import pytest

from kratos_guard.core.sealed_build import (
    _minimal_environment,
    build_input_manifest,
    candidate_root,
    command_policy,
    compare_candidates,
    component_build_definition,
    execute_static_build,
    snapshot_component,
    verify_snapshot_equivalence,
)


def target_repository(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    extension = root / "Study_master" / "extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "manifest_version": 3,
                "name": "Test",
                "version": "1.0.0",
                "background": {"service_worker": "background.js"},
            }
        ),
        encoding="utf-8",
    )
    (extension / "README.md").write_text("# Test Extension\nnode --check", encoding="utf-8")
    (extension / "background.js").write_text("const value = 1;\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "source"], check=True, capture_output=True
    )
    return root


def profile() -> dict[str, object]:
    return {"mutation_sentinels": ["Study_master/extension/manifest.json"]}


def definition_and_manifest(root: Path):
    definition = component_build_definition(root, profile())
    manifest = build_input_manifest(root, definition, "r" * 64, "witness")
    return definition, manifest


def test_component_source_not_inferred_from_folder_name(tmp_path: Path) -> None:
    root = tmp_path / "target"
    (root / "Study_master" / "extension").mkdir(parents=True)
    assert (
        component_build_definition(root, profile()).verdict == "COMPONENT_BUILD_DEFINITION_UNPROVEN"
    )


def test_unproven_build_command_blocks_execution(tmp_path: Path) -> None:
    root = tmp_path / "target"
    (root / "Study_master" / "extension").mkdir(parents=True)
    definition = component_build_definition(root, profile())
    with pytest.raises(PermissionError):
        build_input_manifest(root, definition, "x", "w")


def test_snapshot_copies_only_manifest_entries(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    definition, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    copied = sorted(
        path.relative_to(workspace / "source").as_posix()
        for path in (workspace / "source").rglob("*")
        if path.is_file()
    )
    assert copied == sorted(manifest.included_files)
    assert definition.verdict == "COMPONENT_BUILD_DEFINITION_PROVEN"


def test_copied_snapshot_equals_original_manifest(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    _, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    assert verify_snapshot_equivalence(workspace, manifest)


def test_extra_copied_file_is_rejected(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    _, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    (workspace / "source" / "extra").write_text("unexpected", encoding="utf-8")
    assert not verify_snapshot_equivalence(workspace, manifest)


def test_secrets_are_excluded(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    secret = root / "Study_master" / "extension" / ".env"
    secret.write_text("API_KEY=secret", encoding="utf-8")
    _, manifest = definition_and_manifest(root)
    assert "Study_master/extension/.env" in manifest.excluded_files
    assert all(entry.path != "Study_master/extension/.env" for entry in manifest.entries)


def test_private_key_material_is_excluded(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    key = root / "Study_master" / "extension" / "signing.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nsecret", encoding="utf-8")
    _, manifest = definition_and_manifest(root)
    assert key.relative_to(root).as_posix() in manifest.excluded_files


def test_candidate_workspace_cannot_escape_guard(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        candidate_root(tmp_path / "guard", "../escape")


def test_build_command_never_uses_target_working_directory(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    definition, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    execution, _ = execute_static_build(workspace, manifest, definition)
    assert execution.working_directory == "source/Study_master/extension"
    assert str(root) not in execution.working_directory


def test_minimal_environment_excludes_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    environment = _minimal_environment(tmp_path)
    assert "OPENAI_API_KEY" not in environment
    assert set(environment) <= {"PATH", "SystemRoot", "TEMP", "TMP"}


def test_frozen_dependency_policy_is_not_applicable_for_static_extension(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    definition, _ = definition_and_manifest(root)
    assert definition.dependency_lockfiles == []
    assert definition.install_command == []
    assert definition.lifecycle_script_policy == "DENY_ALL"


def test_build_policy_denies_network_and_lifecycle_scripts(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    definition, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    policy = command_policy(workspace, definition)
    assert policy.network_mode == "DENY"
    assert policy.lifecycle_script_mode == "DENY_ALL"


def test_command_output_is_bounded_and_secret_environment_absent(tmp_path: Path) -> None:
    root = target_repository(tmp_path)
    definition, manifest = definition_and_manifest(root)
    workspace = snapshot_component(root, tmp_path / "guard", manifest, "candidate")
    execution, _ = execute_static_build(workspace, manifest, definition)
    assert len(execution.stdout_excerpt) <= 4096
    assert len(execution.stderr_excerpt) <= 4096
    assert all("KEY" not in key for key in execution.environment_keys)


def test_identical_payloads_are_reproducible(tmp_path: Path) -> None:
    first = tmp_path / "first" / "artefact" / "extension"
    second = tmp_path / "second" / "artefact" / "extension"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "a").write_text("same", encoding="utf-8")
    (second / "a").write_text("same", encoding="utf-8")
    assert (
        compare_candidates(first.parents[1], second.parents[1]).state == "REPRODUCIBLE_BUILD_PROVEN"
    )


def test_nondeterministic_files_are_reported_precisely(tmp_path: Path) -> None:
    first = tmp_path / "first" / "artefact" / "extension"
    second = tmp_path / "second" / "artefact" / "extension"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "timestamp.txt").write_text("one", encoding="utf-8")
    (second / "timestamp.txt").write_text("two", encoding="utf-8")
    result = compare_candidates(first.parents[1], second.parents[1])
    assert result.state == "REPRODUCIBLE_BUILD_CONTRADICTED"
    assert result.differing_paths == ["timestamp.txt"]
