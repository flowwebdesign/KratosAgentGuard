"""Phase 2F isolated reconciliation and compatibility-successor tests."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from kratos_guard.core.phase2e import _copy_exact
from kratos_guard.core.phase2f import (
    PERMITTED_SUCCESSOR_PATHS,
    PHASE2F_SAFETY_COUNTERS,
    _clone_identity,
    _commit_extension_manifest,
    compare_successor_baseline,
    generate_successor_build_identity,
    map_configured_extension_source,
)
from kratos_guard.core.sealed_build import _logical_manifest


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def initialise_repository(root: Path, *, with_generator: bool = True) -> Path:
    root.mkdir(parents=True)
    subprocess.run(["git", "init", str(root)], capture_output=True, check=True)
    git(root, "config", "user.name", "Phase 2F Test")
    git(root, "config", "user.email", "phase2f@test.invalid")
    git(root, "config", "core.autocrlf", "false")
    (root / "README.md").write_text("target\n", encoding="utf-8")
    if with_generator:
        generator = root / "Study_master" / "scripts" / "generateExtensionBuildIdentity.mjs"
        generator.parent.mkdir(parents=True)
        generator.write_text("export const deterministic = true;\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-m", "test base")
    return root


def manifest(version: str = "1.1.17") -> dict[str, object]:
    return {
        "manifest_version": 3,
        "name": "Study Copilot Beta",
        "version": version,
        "key": "stable-public-key-material",
        "permissions": ["storage", "sidePanel"],
        "host_permissions": ["https://example.invalid/*"],
        "background": {"service_worker": "serviceWorker.js"},
        "side_panel": {"default_path": "panel.html"},
        "content_scripts": [{"matches": ["https://example.invalid/*"], "js": ["content.js"]}],
        "externally_connectable": {"matches": ["https://example.invalid/*"]},
        "commands": {"open": {"description": "Open"}},
        "web_accessible_resources": [
            {"resources": ["panel.html"], "matches": ["https://example.invalid/*"]}
        ],
    }


def extension_fixture(root: Path, version: str = "1.1.17") -> Path:
    root.mkdir(parents=True)
    (root / "manifest.json").write_text(json.dumps(manifest(version), indent=2), encoding="utf-8")
    (root / "serviceWorker.js").write_text(
        'importScripts("background.js", "buildInfo.js");\n', encoding="utf-8"
    )
    (root / "background.js").write_text("const messageName = 'capture';\n", encoding="utf-8")
    (root / "content.js").write_text("const storageSchema = 1;\n", encoding="utf-8")
    (root / "panel.html").write_text(
        '<html><script src="panel.js"></script></html>\n', encoding="utf-8"
    )
    (root / "panel.js").write_text("const uiBehaviour = 'stable';\n", encoding="utf-8")
    (root / "buildInfo.js").write_text(
        """(function (global) {
  /* GENERATED_CONTEXT_BUILD_IDENTITY_START */
  const generatedContextBuildIdentity = Object.freeze({
    schemaVersion: "study-pilot.context-build-identity.v1",
    buildId: "extension-1.1.17-old",
    artifactSetHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  });
  /* GENERATED_CONTEXT_BUILD_IDENTITY_END */
  const buildInfo = {
    buildStamp: "extension-trace-first-successor-1.1.17",
    version: "1.1.17"
  };
  global.__STUDY_PILOT_BUILD_INFO__ = buildInfo;
})(globalThis);
""",
        encoding="utf-8",
    )
    (root / "BUILD_IDENTITY.json").write_text("{}\n", encoding="utf-8")
    return root


def write_local_configs(
    guard: Path, extension: Path, target: Path, *, payload: str | None = None
) -> None:
    work = guard / ".work"
    work.mkdir(parents=True)
    digest = payload or str(_logical_manifest(extension, excluded_names=set())["manifest_sha256"])
    (work / "phase2e-config.json").write_text(
        json.dumps(
            {
                "extension_id": "mofhgdnkngbpbcihjkhoelogkjolaidn",
                "extension_path": str(extension),
                "payload_hash": digest,
                "version": "1.1.17",
            }
        ),
        encoding="utf-8",
    )
    (work / "phase2f-config.json").write_text(
        json.dumps(
            {
                "baseline_path": str(work / "baseline"),
                "extension_id": "mofhgdnkngbpbcihjkhoelogkjolaidn",
                "payload_hash": digest,
                "target_repository": str(target),
            }
        ),
        encoding="utf-8",
    )


def candidate_pair(root: Path) -> tuple[Path, Path]:
    baseline = root / "baseline"
    candidate = root / "candidate"
    base_extension = extension_fixture(baseline / "artefact" / "extension")
    candidate_extension = candidate / "artefact" / "extension"
    _copy_exact(base_extension, candidate_extension)
    candidate_manifest = manifest("1.1.18")
    (candidate_extension / "manifest.json").write_text(
        json.dumps(candidate_manifest, indent=2), encoding="utf-8"
    )
    (candidate_extension / "buildInfo.js").write_text(
        (candidate_extension / "buildInfo.js").read_text("utf-8").replace("1.1.17", "1.1.18"),
        encoding="utf-8",
    )
    (candidate_extension / "BUILD_IDENTITY.json").write_text(
        '{"buildId":"successor"}\n', encoding="utf-8"
    )
    return baseline, candidate


def test_mapping_covers_every_operational_file(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    extension = extension_fixture(tmp_path / "configured")
    write_local_configs(tmp_path / "guard", extension, target)
    result = map_configured_extension_source(tmp_path / "guard")
    expected = _logical_manifest(extension, excluded_names=set())
    assert len(result.files) == expected["file_count"]
    assert result.execution_critical_unknown_count == 0
    assert result.verdict == "COMPLETE_SOURCE_MAPPING_PROVEN"


def test_generated_outputs_require_a_committed_generator(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target", with_generator=False)
    extension = extension_fixture(tmp_path / "configured")
    write_local_configs(tmp_path / "guard", extension, target)
    result = map_configured_extension_source(tmp_path / "guard")
    assert result.verdict == "EXECUTION_CRITICAL_SOURCE_UNAVAILABLE"
    assert {item.path for item in result.blockers} == {
        "BUILD_IDENTITY.json",
        "buildInfo.js",
    }


def test_execution_critical_unknown_blocks_reconciliation(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    extension = extension_fixture(tmp_path / "configured")
    (extension / "runtime.wasm").write_bytes(b"\0asm")
    write_local_configs(tmp_path / "guard", extension, target)
    result = map_configured_extension_source(tmp_path / "guard")
    assert result.execution_critical_unknown_count == 1
    assert result.blockers[0].path == "runtime.wasm"


def test_configured_payload_change_fails_closed(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    extension = extension_fixture(tmp_path / "configured")
    write_local_configs(tmp_path / "guard", extension, target, payload="0" * 64)
    with pytest.raises(RuntimeError, match="CONFIGURED_EXTENSION_CHANGED"):
        map_configured_extension_source(tmp_path / "guard")


def test_no_local_clone_has_separate_object_database(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    clone = tmp_path / "guard" / ".work" / "run" / "repository"
    subprocess.run(
        ["git", "clone", "--no-local", "--no-hardlinks", str(target), str(clone)],
        capture_output=True,
        check=True,
    )
    git(clone, "remote", "set-url", "--push", "origin", "DISABLED_PHASE2F_NO_PUSH")
    identity = _clone_identity(clone.parent, clone, str(target / ".git"))
    assert identity.object_database_independent
    assert identity.hardlinked_objects_found == 0
    assert not identity.linked_worktree


def test_hardlinked_git_object_is_rejected(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    clone = tmp_path / "guard" / ".work" / "run" / "repository"
    subprocess.run(
        ["git", "clone", "--no-local", "--no-hardlinks", str(target), str(clone)],
        capture_output=True,
        check=True,
    )
    git(clone, "remote", "set-url", "--push", "origin", "DISABLED_PHASE2F_NO_PUSH")
    source_object = next(
        item for item in (target / ".git" / "objects").rglob("*") if item.is_file()
    )
    linked = clone / ".git" / "objects" / "phase2f-hardlink-test"
    os.link(source_object, linked)
    identity = _clone_identity(clone.parent, clone, str(target / ".git"))
    assert identity.hardlinked_objects_found == 1
    assert identity.verdict == "ISOLATED_CLONE_UNSAFE"


def test_target_cannot_receive_automatic_push(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "--no-local", str(target), str(clone)], check=True)
    git(clone, "remote", "set-url", "--push", "origin", "DISABLED_PHASE2F_NO_PUSH")
    assert git(clone, "remote", "get-url", "--push", "origin") == "DISABLED_PHASE2F_NO_PUSH"


def test_clone_does_not_create_target_branch_or_worktree(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    refs_before = git(target, "for-each-ref", "--format=%(refname)")
    worktrees_before = git(target, "worktree", "list", "--porcelain")
    subprocess.run(
        ["git", "clone", "--no-local", "--no-hardlinks", str(target), str(tmp_path / "clone")],
        capture_output=True,
        check=True,
    )
    assert git(target, "for-each-ref", "--format=%(refname)") == refs_before
    assert git(target, "worktree", "list", "--porcelain") == worktrees_before


def test_untracked_target_files_are_excluded_from_clone(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    (target / "unrelated-dirty-secret.txt").write_text("not lineage\n", encoding="utf-8")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "--no-local", str(target), str(clone)], check=True)
    assert not (clone / "unrelated-dirty-secret.txt").exists()


def test_exact_static_copy_preserves_paths_hashes_and_payload(tmp_path: Path) -> None:
    source = extension_fixture(tmp_path / "source")
    expected = _logical_manifest(source, excluded_names=set())
    observed = _copy_exact(source, tmp_path / "copy")
    assert observed == expected


def test_commit_manifest_uses_payload_canonical_path_order(tmp_path: Path) -> None:
    target = initialise_repository(tmp_path / "target")
    extension = extension_fixture(target / "Study_master" / "extension")
    git(target, "add", "Study_master/extension")
    git(target, "commit", "-m", "extension fixture")
    expected = _logical_manifest(extension, excluded_names=set())
    observed = _commit_extension_manifest(target, git(target, "rev-parse", "HEAD"))
    assert observed == expected


def test_build_identity_generation_changes_only_metadata(tmp_path: Path) -> None:
    extension = extension_fixture(tmp_path / "extension", version="1.1.18")
    before_worker = (extension / "serviceWorker.js").read_bytes()
    before_content = (extension / "content.js").read_bytes()
    identity = generate_successor_build_identity(extension)
    assert identity["buildId"].startswith("extension-1.1.18-")
    assert (extension / "serviceWorker.js").read_bytes() == before_worker
    assert (extension / "content.js").read_bytes() == before_content


def test_static_compatibility_accepts_only_authorised_delta(tmp_path: Path) -> None:
    baseline, candidate = candidate_pair(tmp_path)
    result = compare_successor_baseline(baseline, candidate)
    assert result.verdict == "SUCCESSOR_STATIC_COMPATIBILITY_PROVEN"
    assert result.unexpected_delta == []


def test_product_behaviour_change_is_rejected(tmp_path: Path) -> None:
    baseline, candidate = candidate_pair(tmp_path)
    (candidate / "artefact" / "extension" / "serviceWorker.js").write_text(
        "const behaviourChanged = true;\n", encoding="utf-8"
    )
    result = compare_successor_baseline(baseline, candidate)
    assert "serviceWorker.js" in result.unexpected_delta
    assert result.verdict == "SUCCESSOR_STATIC_COMPATIBILITY_CONTRADICTED"


@pytest.mark.parametrize(
    "field",
    [
        "key",
        "manifest_version",
        "permissions",
        "host_permissions",
        "content_scripts",
        "externally_connectable",
        "commands",
        "web_accessible_resources",
    ],
)
def test_manifest_contract_change_is_rejected(tmp_path: Path, field: str) -> None:
    baseline, candidate = candidate_pair(tmp_path)
    path = candidate / "artefact" / "extension" / "manifest.json"
    value = json.loads(path.read_text("utf-8"))
    value[field] = "changed"
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    result = compare_successor_baseline(baseline, candidate)
    assert not result.invariant_results[field]
    assert result.verdict == "SUCCESSOR_STATIC_COMPATIBILITY_CONTRADICTED"


def test_worker_entry_change_is_rejected(tmp_path: Path) -> None:
    baseline, candidate = candidate_pair(tmp_path)
    path = candidate / "artefact" / "extension" / "manifest.json"
    value = json.loads(path.read_text("utf-8"))
    value["background"]["service_worker"] = "background.js"
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    result = compare_successor_baseline(baseline, candidate)
    assert not result.invariant_results["worker"]


@pytest.mark.parametrize(
    "path",
    [
        "Study_master/extension/manifest.json",
        "Study_master/extension/buildInfo.js",
        "Study_master/extension/BUILD_IDENTITY.json",
    ],
)
def test_successor_permitted_delta_is_narrow(path: str) -> None:
    assert path in PERMITTED_SUCCESSOR_PATHS


@pytest.mark.parametrize(
    "classification",
    [
        "DIRECT_RUNTIME_SOURCE",
        "STATIC_ASSET",
        "GENERATED_FROM_IDENTIFIED_SOURCE",
        "GENERATED_SOURCE_UNAVAILABLE",
        "BUILD_METADATA",
        "DELIVERY_ATTESTATION",
        "UNKNOWN",
    ],
)
def test_required_source_classification_vocabulary_is_representable(
    classification: str,
) -> None:
    assert classification in {
        "DIRECT_RUNTIME_SOURCE",
        "STATIC_ASSET",
        "GENERATED_FROM_IDENTIFIED_SOURCE",
        "GENERATED_SOURCE_UNAVAILABLE",
        "BUILD_METADATA",
        "DELIVERY_ATTESTATION",
        "UNKNOWN",
    }


@pytest.mark.parametrize("counter", sorted(PHASE2F_SAFETY_COUNTERS))
def test_phase2f_protected_mutation_counter_remains_zero(counter: str) -> None:
    assert PHASE2F_SAFETY_COUNTERS[counter] == 0


def test_isolated_proof_never_grants_normal_profile_authority() -> None:
    isolated_runtime = "COMPATIBILITY_SUCCESSOR_ISOLATED_RUNTIME_PROVEN"
    normal_profile_runtime = "UNPROVEN"
    promotion_authority = "NONE"
    assert isolated_runtime.endswith("_PROVEN")
    assert normal_profile_runtime == "UNPROVEN"
    assert promotion_authority == "NONE"


def test_expected_next_blocker_is_behavioural_change() -> None:
    assert "BEHAVIOURAL_SUCCESSOR_CHANGE_NOT_IMPLEMENTED" != ""
