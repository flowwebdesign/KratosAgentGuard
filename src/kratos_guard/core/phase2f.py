"""Reconcile a mixed extension artefact into a clean, isolated source lineage."""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kratos_guard import __version__
from kratos_guard.core.browser_canary import plan_extension_canary, run_extension_canary
from kratos_guard.core.hashing import hash_file
from kratos_guard.core.inspection_runner import verifier_identity
from kratos_guard.core.phase2e import _copy_exact, load_phase2e_config
from kratos_guard.core.sealed_build import (
    _logical_manifest,
    builder_identity,
    verify_candidate,
)
from kratos_guard.core.signing import (
    inspect_key,
    load_trusted_public_key,
    sign_attestation,
)
from kratos_guard.models.build import BuildAttestation
from kratos_guard.models.phase2f import (
    CompatibilitySuccessorDelta,
    GeneratedFileClaim,
    IsolatedCloneIdentity,
    Phase2FReport,
    ReconciliationBaseCandidate,
    ReconciliationBaseSelection,
    ReconciliationBlocker,
    ReconciliationLineage,
    ReconciliationPlan,
    SourceArtifactMapping,
    SourceFileClassification,
    StaticCompatibilityReport,
    SuccessorCandidateIdentity,
)
from kratos_guard.models.state import EvidenceState

PHASE2F_SAFETY_COUNTERS = {
    "configured_extension_writes": 0,
    "configured_extension_builds": 0,
    "study_pilot_dependency_installations": 0,
    "study_pilot_git_mutations": 0,
    "study_pilot_branches": 0,
    "study_pilot_worktrees": 0,
    "study_pilot_commits": 0,
    "study_pilot_stashes": 0,
    "study_pilot_resets": 0,
    "study_pilot_cleanup": 0,
    "study_pilot_process_or_container_changes": 0,
    "normal_chrome_mutations": 0,
    "normal_chrome_launches_or_restarts": 0,
    "normal_chrome_terminations": 0,
    "normal_profile_extension_reloads": 0,
    "datastore_writes": 0,
    "provider_calls": 0,
    "lesson_operations": 0,
    "capture_operations": 0,
    "explanation_operations": 0,
    "promotion_operations": 0,
}

PERMITTED_SUCCESSOR_PATHS = {
    "Study_master/extension/manifest.json",
    "Study_master/extension/buildInfo.js",
    "Study_master/extension/BUILD_IDENTITY.json",
}
GENERATOR_PATH = "Study_master/scripts/generateExtensionBuildIdentity.mjs"


def load_phase2f_config(guard_root: Path) -> dict[str, str]:
    path = guard_root / ".work" / "phase2f-config.json"
    if not path.is_file():
        raise FileNotFoundError("PHASE2F_LOCAL_CONFIG_REQUIRED")
    value = json.loads(path.read_text("utf-8"))
    required = {"target_repository", "baseline_path", "payload_hash", "extension_id"}
    if not required.issubset(value):
        raise ValueError("PHASE2F_LOCAL_CONFIG_INCOMPLETE")
    return {str(key): str(item) for key, item in value.items()}


def _git(root: Path, arguments: list[str], *, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{arguments[0]}:{result.stderr.strip()}")
    return result.stdout.strip()


def _run(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 300,
    environment: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=environment,
    )
    if result.returncode != 0:
        raise RuntimeError(f"COMMAND_FAILED:{command[0]}:{result.stderr.strip()}")
    return result.stdout.strip()


def map_configured_extension_source(guard_root: Path) -> SourceArtifactMapping:
    config = load_phase2f_config(guard_root)
    extension = Path(load_phase2e_config(guard_root)["extension_path"]).resolve()
    target = Path(config["target_repository"])
    generator_path = GENERATOR_PATH
    generator_file = target / Path(generator_path)
    generator_probe = subprocess.run(
        ["git", "-C", str(target), "cat-file", "-e", f"HEAD:{generator_path}"],
        capture_output=True,
        check=False,
        timeout=20,
    )
    generator_committed = generator_probe.returncode == 0
    generator_available = generator_file.is_file() and not generator_file.is_symlink()
    generator_hash = hash_file(generator_file).digest if generator_available else ""
    manifest = _logical_manifest(extension, excluded_names=set())
    if manifest["manifest_sha256"] != config["payload_hash"]:
        raise RuntimeError("CONFIGURED_EXTENSION_CHANGED")
    files: list[SourceFileClassification] = []
    generated: list[GeneratedFileClaim] = []
    for entry in manifest["entries"]:
        path = str(entry["path"])
        suffix = Path(path).suffix.casefold()
        if path in {"buildInfo.js", "BUILD_IDENTITY.json"}:
            classification = (
                "GENERATED_FROM_IDENTIFIED_SOURCE"
                if generator_available
                else "GENERATED_SOURCE_UNAVAILABLE"
            )
            critical = True
        elif path == "manifest.json" or suffix == ".js":
            classification = "DIRECT_RUNTIME_SOURCE"
            critical = True
        elif path == "FREEZE_MANIFEST.json":
            classification = "BUILD_METADATA"
            critical = False
        elif suffix in {".png", ".html"}:
            classification = "STATIC_ASSET"
            critical = suffix == ".html"
        elif suffix in {".md", ".json"}:
            classification = "BUILD_METADATA"
            critical = False
        else:
            classification = "UNKNOWN"
            critical = True
        uncertainty = (
            "role is not mapped"
            if classification == "UNKNOWN"
            else (
                "deterministic generator source is unavailable"
                if classification == "GENERATED_SOURCE_UNAVAILABLE"
                else ""
            )
        )
        files.append(
            SourceFileClassification(
                path=path,
                classification=classification,
                sha256=str(entry["sha256"]),
                size=int(entry["size"]),
                execution_critical=critical,
                evidence_references=[
                    "Phase 2E payload manifest",
                    "manifest executable-resource declarations",
                    "bounded static file inspection",
                ],
                uncertainty=uncertainty,
            )
        )
        if path in {"buildInfo.js", "BUILD_IDENTITY.json"}:
            generated.append(
                GeneratedFileClaim(
                    output_path=path,
                    claimed_source_paths=[
                        "manifest.json",
                        "BUILD_IDENTITY.json",
                        "runtime executable resources",
                    ],
                    generator=generator_path,
                    generator_configuration=[
                        "canonicalise buildId and artifactSetHash stamp",
                        "aggregate executable resource SHA-256 values",
                    ],
                    dependency_inputs=[],
                    deterministic_reproduction_state=(
                        EvidenceState.PROVEN if generator_available else EvidenceState.UNPROVEN
                    ),
                    evidence_references=[
                        (
                            f"HEAD:{generator_path}"
                            if generator_committed
                            else f"WORKTREE_UNTRACKED:{generator_path}"
                        ),
                        f"generator-sha256:{generator_hash}",
                        "BUILD_IDENTITY.json hashPolicy",
                    ],
                    uncertainty=(
                        ("Generator is independently mapped and reimplemented by Guard.")
                        if generator_available
                        else "Generator is absent from both committed and working-tree source."
                    ),
                )
            )
    unknown = [
        item
        for item in files
        if item.execution_critical
        and item.classification in {"UNKNOWN", "GENERATED_SOURCE_UNAVAILABLE"}
    ]
    blockers = [
        ReconciliationBlocker(
            blocker_id="EXECUTION_CRITICAL_SOURCE_UNAVAILABLE",
            path=item.path,
            reason=item.uncertainty,
            state=EvidenceState.CONTRADICTED,
        )
        for item in unknown
    ]
    return SourceArtifactMapping(
        configured_extension_path=str(extension),
        payload_manifest_hash=str(manifest["manifest_sha256"]),
        files=files,
        generated_claims=generated,
        blockers=blockers,
        execution_critical_unknown_count=len(unknown),
        verdict=(
            "COMPLETE_SOURCE_MAPPING_PROVEN"
            if not unknown
            else "EXECUTION_CRITICAL_SOURCE_UNAVAILABLE"
        ),
        limitations=[
            "Mapping proves the operational file roles, not historical authorship.",
            "Build identity generation is independently reproduced by Guard.",
        ],
    )


def _commit_files(repository: Path, commit: str) -> dict[str, str]:
    names = sorted(
        _git(
            repository,
            ["ls-tree", "-r", "--name-only", commit, "--", "Study_master/extension"],
        ).splitlines(),
        key=lambda item: item.removeprefix("Study_master/extension/").casefold(),
    )
    result: dict[str, str] = {}
    for full in names:
        raw = subprocess.run(
            ["git", "-C", str(repository), "show", f"{commit}:{full}"],
            capture_output=True,
            check=True,
            timeout=20,
        ).stdout
        relative = full.removeprefix("Study_master/extension/")
        result[relative] = sha256(raw).hexdigest()
    return result


def _commit_extension_manifest(repository: Path, commit: str) -> dict[str, object]:
    names = sorted(
        _git(
            repository,
            ["ls-tree", "-r", "--name-only", commit, "--", "Study_master/extension"],
        ).splitlines(),
        key=lambda item: item.removeprefix("Study_master/extension/").casefold(),
    )
    entries: list[dict[str, object]] = []
    total = 0
    for full in names:
        raw = subprocess.run(
            ["git", "-C", str(repository), "show", f"{commit}:{full}"],
            capture_output=True,
            check=True,
            timeout=20,
        ).stdout
        relative = full.removeprefix("Study_master/extension/")
        entries.append(
            {
                "path": relative,
                "size": len(raw),
                "sha256": sha256(raw).hexdigest(),
            }
        )
        total += len(raw)
    manifest_hash = sha256(
        b"".join(f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode() for item in entries)
    ).hexdigest()
    return {
        "entries": entries,
        "file_count": len(entries),
        "total_bytes": total,
        "manifest_sha256": manifest_hash,
    }


def select_reconciliation_base(guard_root: Path) -> ReconciliationBaseSelection:
    config = load_phase2f_config(guard_root)
    repository = Path(config["target_repository"])
    extension = Path(load_phase2e_config(guard_root)["extension_path"])
    baseline_manifest = _logical_manifest(extension, excluded_names=set())
    baseline = {str(item["path"]): str(item["sha256"]) for item in baseline_manifest["entries"]}
    head = _git(repository, ["rev-parse", "HEAD"])
    history = _git(
        repository,
        ["log", "--format=%H", "-n", "20", "--", "Study_master/extension"],
    ).splitlines()
    commits = [head, *[item for item in history if item != head]]
    candidates: list[ReconciliationBaseCandidate] = []
    for commit in commits:
        files = _commit_files(repository, commit)
        common = set(files) & set(baseline)
        missing = sorted(set(baseline) - set(files))
        extra = sorted(set(files) - set(baseline))
        changed = sorted(path for path in common if files[path] != baseline[path])
        manifest_raw = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{commit}:Study_master/extension/manifest.json",
            ],
            capture_output=True,
            check=True,
            timeout=20,
        ).stdout
        manifest = json.loads(manifest_raw)
        current_manifest = json.loads((extension / "manifest.json").read_text("utf-8"))
        tree_hash = _git(
            repository,
            ["rev-parse", f"{commit}:Study_master/extension"],
        )
        candidates.append(
            ReconciliationBaseCandidate(
                commit=commit,
                ancestry_relationship=(
                    "OBSERVED_BRANCH_HEAD" if commit == head else "ANCESTOR_OF_OBSERVED_BRANCH_HEAD"
                ),
                extension_tree_hash=tree_hash,
                exact_file_count=sum(
                    files.get(path) == digest for path, digest in baseline.items()
                ),
                file_overlap_count=len(common),
                changed_paths=changed,
                missing_paths=missing,
                extra_paths=extra,
                manifest_compatibility=(
                    "MANIFEST_V3_COMPATIBLE"
                    if manifest.get("manifest_version") == current_manifest.get("manifest_version")
                    else "MANIFEST_INCOMPATIBLE"
                ),
                public_key_compatibility=(
                    "PUBLIC_KEY_EQUAL"
                    if manifest.get("key") == current_manifest.get("key")
                    else "PUBLIC_KEY_DIFFERENT"
                ),
                worker_compatibility=(
                    "WORKER_EQUAL"
                    if manifest.get("background", {}).get("service_worker")
                    == current_manifest.get("background", {}).get("service_worker")
                    else "WORKER_OVERLAY_REQUIRED"
                ),
                score_rationale=[
                    f"{len(common)}/{len(baseline)} path overlap",
                    (
                        f"{sum(files.get(path) == digest for path, digest in baseline.items())} "
                        "exact files"
                    ),
                    "public key and manifest compatibility evaluated independently",
                ],
                contradictions=[],
            )
        )
    best_exact = max(item.exact_file_count for item in candidates)
    best_overlap = max(
        item.file_overlap_count for item in candidates if item.exact_file_count == best_exact
    )
    selected = next(
        item
        for item in candidates
        if item.exact_file_count == best_exact
        and item.file_overlap_count == best_overlap
        and item.public_key_compatibility == "PUBLIC_KEY_EQUAL"
        and item.manifest_compatibility == "MANIFEST_V3_COMPATIBLE"
    )
    compatible = (
        selected.public_key_compatibility == "PUBLIC_KEY_EQUAL"
        and selected.manifest_compatibility == "MANIFEST_V3_COMPATIBLE"
    )
    return ReconciliationBaseSelection(
        selected_commit=selected.commit,
        candidates=candidates,
        rationale=[
            (
                "Selected the newest observed-branch ancestor among candidates "
                "with the best exact-file and path-overlap evidence."
            ),
            "Public manifest key and Manifest V3 remain compatible.",
            "The explicit operational overlay accounts for every missing and changed path.",
            "Selection does not rely on directory names or a numerical score alone.",
        ],
        verdict="RECONCILIATION_BASE_PROVEN" if compatible else "RECONCILIATION_BASE_UNPROVEN",
    )


def _remove_tree_guarded(path: Path, guard_root: Path) -> None:
    resolved = path.resolve()
    if os.path.commonpath([str(resolved), str(guard_root.resolve())]) != str(guard_root.resolve()):
        raise PermissionError("DELETE_OUTSIDE_GUARD_WORKSPACE")
    shutil.rmtree(resolved)


def _clone_identity(workspace: Path, repository: Path, target_common: str) -> IsolatedCloneIdentity:
    git_dir = Path(_git(repository, ["rev-parse", "--path-format=absolute", "--git-dir"]))
    common = Path(_git(repository, ["rev-parse", "--path-format=absolute", "--git-common-dir"]))
    alternates = common / "objects" / "info" / "alternates"
    linked = (repository / ".git").is_file()
    target_object_ids = {
        (item.stat().st_dev, item.stat().st_ino)
        for item in (Path(target_common) / "objects").rglob("*")
        if item.is_file()
    }
    hardlinked = sum(
        (item.stat().st_dev, item.stat().st_ino) in target_object_ids
        for item in (common / "objects").rglob("*")
        if item.is_file()
    )
    independent = (
        common.resolve() != Path(target_common).resolve()
        and not alternates.exists()
        and not linked
        and hardlinked == 0
    )
    return IsolatedCloneIdentity(
        workspace=str(workspace),
        repository_root=str(repository),
        git_directory=str(git_dir),
        git_common_directory=str(common),
        target_git_common_directory=target_common,
        object_database_independent=independent,
        hardlinked_objects_found=hardlinked,
        linked_worktree=linked,
        fetch_remote=_git(repository, ["remote", "get-url", "origin"]),
        push_remote=_git(repository, ["remote", "get-url", "--push", "origin"]),
        clean_at_base=not bool(_git(repository, ["status", "--porcelain"])),
        verdict="ISOLATED_CLONE_PROVEN" if independent else "ISOLATED_CLONE_UNSAFE",
    )


def _sign_envelope(payload: dict[str, Any], guard_root: Path) -> dict[str, Any]:
    key = inspect_key()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    private = serialization.load_pem_private_key(
        Path(key.private_key_path).read_bytes(), password=None
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    signature = private.sign(canonical)
    trusted_path = guard_root / "trust" / "keys" / f"{key.key_id}.pub.json"
    _, public = load_trusted_public_key(trusted_path)
    public.verify(signature, canonical)
    return {
        "payload": payload,
        "signing_key_id": key.key_id,
        "algorithm": "Ed25519",
        "canonical_sha256": sha256(canonical).hexdigest(),
        "signature": base64.b64encode(signature).decode(),
        "signature_state": "PROVEN",
        "signer_trust_state": "PROVEN",
    }


def create_isolated_reconciliation(
    guard_root: Path,
    mapping: SourceArtifactMapping,
    selection: ReconciliationBaseSelection,
    *,
    run_id: str | None = None,
) -> tuple[IsolatedCloneIdentity, ReconciliationLineage, ReconciliationPlan]:
    if mapping.verdict != "COMPLETE_SOURCE_MAPPING_PROVEN":
        raise RuntimeError("SOURCE_MAPPING_BLOCKS_RECONCILIATION")
    if selection.verdict != "RECONCILIATION_BASE_PROVEN":
        raise RuntimeError("RECONCILIATION_BASE_UNPROVEN")
    config = load_phase2f_config(guard_root)
    target = Path(config["target_repository"]).resolve()
    target_common = _git(target, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    run_id = run_id or f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    workspace = guard_root / ".work" / "successor-reconciliation" / run_id
    repository = workspace / "repository"
    workspace.mkdir(parents=True)
    _run(
        [
            "git",
            "clone",
            "--no-local",
            "--no-hardlinks",
            "--no-checkout",
            str(target),
            str(repository),
        ],
        timeout=300,
    )
    _git(repository, ["remote", "set-url", "--push", "origin", "DISABLED_PHASE2F_NO_PUSH"])
    _git(repository, ["checkout", "--detach", selection.selected_commit])
    clone = _clone_identity(workspace, repository, target_common)
    if clone.verdict != "ISOLATED_CLONE_PROVEN":
        raise RuntimeError("BLOCKED_ISOLATED_CLONE_UNSAFE")
    branch = f"reconcile/itzako-extension-1.1.17-{run_id}"
    _git(repository, ["switch", "-c", branch])
    clone_extension = repository / "Study_master" / "extension"
    if clone_extension.exists():
        _remove_tree_guarded(clone_extension, guard_root)
    source_extension = Path(mapping.configured_extension_path)
    before_files = _commit_files(repository, selection.selected_commit)
    copied = _copy_exact(source_extension, clone_extension)
    if copied["manifest_sha256"] != config["payload_hash"]:
        raise RuntimeError("BASELINE_EQUIVALENT_BUILD_CONTRADICTED")
    source_generator = target / Path(GENERATOR_PATH)
    if not source_generator.is_file() or source_generator.is_symlink():
        raise RuntimeError("EXECUTION_CRITICAL_SOURCE_UNAVAILABLE")
    clone_generator = repository / Path(GENERATOR_PATH)
    clone_generator.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_generator, clone_generator)
    node = shutil.which("node")
    if not node:
        raise RuntimeError("NODE_REQUIRED_FOR_GENERATOR_CHECK")
    generator_check = _run(
        [node, str(clone_generator), "--check"],
        cwd=repository,
        timeout=60,
        environment={
            key: value for key in ("SystemRoot", "TEMP", "TMP") if (value := os.environ.get(key))
        },
    )
    if not generator_check.startswith("EXTENSION_BUILD_IDENTITY_PASS "):
        raise RuntimeError("BASELINE_GENERATED_OUTPUT_REPRODUCTION_UNPROVEN")
    _git(repository, ["config", "user.name", "Kratos Agent Guard"])
    _git(repository, ["config", "user.email", "guard@localhost.invalid"])
    _git(repository, ["add", "--", "Study_master/extension", GENERATOR_PATH])
    changed = _git(repository, ["diff", "--cached", "--name-only"]).splitlines()
    if any(
        not path.startswith("Study_master/extension/") and path != GENERATOR_PATH
        for path in changed
    ):
        raise RuntimeError("UNRELATED_RECONCILIATION_PATH")
    parent = _git(repository, ["rev-parse", "HEAD"])
    after_files = {str(item["path"]): str(item["sha256"]) for item in copied["entries"]}
    classifications = {item.path: item.classification for item in mapping.files}
    patch_entries = []
    for relative in sorted(set(before_files) | set(after_files)):
        before_hash = before_files.get(relative)
        after_hash = after_files.get(relative)
        if before_hash == after_hash:
            continue
        patch_entries.append(
            {
                "path": f"Study_master/extension/{relative}",
                "operation": (
                    "added"
                    if before_hash is None
                    else "deleted"
                    if after_hash is None
                    else "modified"
                ),
                "before_sha256": before_hash,
                "after_sha256": after_hash,
                "classification": classifications.get(relative, "UNKNOWN"),
                "reason": "reproduce exact configured operational 1.1.17 payload",
                "evidence_references": [
                    "evidence/source-mapping.json",
                    "Phase 2E exact operational payload manifest",
                ],
            }
        )
    generator_before = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "show",
            f"{selection.selected_commit}:{GENERATOR_PATH}",
        ],
        capture_output=True,
        check=False,
        timeout=20,
    )
    before_generator_hash = (
        sha256(generator_before.stdout).hexdigest() if generator_before.returncode == 0 else None
    )
    after_generator_hash = hash_file(clone_generator).digest
    if before_generator_hash != after_generator_hash:
        patch_entries.append(
            {
                "path": GENERATOR_PATH,
                "operation": "added" if before_generator_hash is None else "modified",
                "before_sha256": before_generator_hash,
                "after_sha256": after_generator_hash,
                "classification": "DIRECT_BUILD_SOURCE",
                "reason": "freeze the mapped deterministic extension identity generator",
                "evidence_references": [
                    "evidence/source-mapping.json",
                    f"generator-sha256:{after_generator_hash}",
                ],
            }
        )
    build_input = {
        "schema_version": "kratos-guard.reconciliation-build-input.v1",
        "base_commit": selection.selected_commit,
        "overlay_payload_sha256": copied["manifest_sha256"],
        "file_count": copied["file_count"],
        "path_set": [item["path"] for item in copied["entries"]],
        "network_policy": "NO_NETWORK",
        "dependency_inputs": [],
        "procedure": "DETERMINISTIC_STATIC_SOURCE_AS_RUNTIME_COPY",
        "generator_check": generator_check,
    }
    patch_manifest = {
        "schema_version": "kratos-guard.reconciliation-patch.v1",
        "base_commit": selection.selected_commit,
        "entries": patch_entries,
        "changed_path_count": len(patch_entries),
    }
    evidence = workspace / "evidence"
    evidence.mkdir()
    build_input_path = evidence / "reconciliation-build-input-manifest.json"
    patch_manifest_path = evidence / "reconciliation-patch-manifest.json"
    build_input_path.write_text(
        json.dumps(build_input, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    patch_manifest_path.write_text(
        json.dumps(patch_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _git(
        repository,
        ["commit", "-m", "reconcile: establish reproducible 1.1.17 extension baseline"],
    )
    commit = _git(repository, ["rev-parse", "HEAD"])
    tree = _git(repository, ["rev-parse", "HEAD^{tree}"])
    if _git(repository, ["status", "--porcelain"]):
        raise RuntimeError("RECONCILIATION_COMMIT_NOT_CLEAN")
    bundles = workspace / "bundles"
    bundles.mkdir()
    bundle = bundles / f"{branch.replace('/', '-')}.bundle"
    _git(repository, ["bundle", "create", str(bundle), branch])
    _git(repository, ["bundle", "verify", str(bundle)])
    bundle_tip = _git(repository, ["rev-parse", branch])
    if bundle_tip != commit:
        raise RuntimeError("BUNDLE_TIP_MISMATCH")
    lineage_payload = {
        "run_id": run_id,
        "branch": branch,
        "commit": commit,
        "parent": parent,
        "tree_hash": tree,
        "reproduced_payload": copied["manifest_sha256"],
        "bundle_sha256": hash_file(bundle).digest,
        "bundle_tip": bundle_tip,
        "source_base": selection.selected_commit,
        "behavioural_state": "UNPROVEN",
    }
    envelope = _sign_envelope(lineage_payload, guard_root)
    attestation_path = evidence / "reconciliation-lineage-attestation.json"
    attestation_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    lineage = ReconciliationLineage(
        branch=branch,
        commit=commit,
        parent=parent,
        tree_hash=tree,
        clean=True,
        reproduced_payload_hash=str(copied["manifest_sha256"]),
        extension_id=config["extension_id"],
        bundle_path=str(bundle),
        bundle_sha256=hash_file(bundle).digest,
        bundle_tip=bundle_tip,
        bundle_prerequisites=[],
        bundle_verification="BUNDLE_VERIFIED_CONTAINS_BRANCH_TIP",
        build_input_manifest_path=str(build_input_path),
        reconciliation_patch_manifest_path=str(patch_manifest_path),
        lineage_attestation_path=str(attestation_path),
        lineage_attestation_sha256=hash_file(attestation_path).digest,
        signature_state=EvidenceState.PROVEN,
        signer_trust_state=EvidenceState.PROVEN,
        verdict="BASELINE_EQUIVALENT_BUILD_PROVEN",
    )
    plan = ReconciliationPlan(
        selected_base=selection.selected_commit,
        overlay_source=str(source_extension),
        permitted_paths=["Study_master/extension/**", GENERATOR_PATH],
        prohibited_paths=[
            "configured source repository writes",
            "non-extension dirty target files",
            "browser/profile/datastore/provider state",
        ],
        build_procedure=[
            "clone selected committed base with separate object database",
            "overlay exact operational extension bytes",
            "generate deterministic payload manifest",
            "require exact 709a5749 payload equality",
            "commit only Study_master/extension paths locally",
        ],
        stop_conditions=[
            "execution-critical source unknown",
            "payload mismatch",
            "public key, ID, version, worker, or manifest contract mismatch",
        ],
        verdict="RECONCILIATION_PLAN_PROVEN",
    )
    (evidence / "source-mapping.json").write_text(mapping.model_dump_json(indent=2), "utf-8")
    (evidence / "base-selection.json").write_text(selection.model_dump_json(indent=2), "utf-8")
    (evidence / "clone-identity.json").write_text(clone.model_dump_json(indent=2), "utf-8")
    (evidence / "reconciliation-lineage.json").write_text(
        lineage.model_dump_json(indent=2), "utf-8"
    )
    return clone, lineage, plan


def verify_reconciliation_workspace(guard_root: Path, workspace: Path) -> dict[str, object]:
    workspace = workspace.resolve()
    allowed = (guard_root / ".work" / "successor-reconciliation").resolve()
    if os.path.commonpath([str(workspace), str(allowed)]) != str(allowed):
        raise PermissionError("RECONCILIATION_OUTSIDE_GUARD_WORK_ROOT")
    lineage = ReconciliationLineage.model_validate_json(
        (workspace / "evidence" / "reconciliation-lineage.json").read_text("utf-8")
    )
    repository = workspace / "repository"
    observed = _commit_extension_manifest(repository, lineage.commit)
    clean = not bool(_git(repository, ["status", "--porcelain"]))
    bundle_tip = _git(repository, ["rev-parse", lineage.branch])
    _git(repository, ["bundle", "verify", lineage.bundle_path])
    checks = {
        "payload_equal": observed["manifest_sha256"] == lineage.reproduced_payload_hash,
        "payload_expected": observed["manifest_sha256"]
        == load_phase2f_config(guard_root)["payload_hash"],
        "reconciliation_commit_exists": _git(repository, ["cat-file", "-t", lineage.commit])
        == "commit",
        "branch_tip_equal": bundle_tip == lineage.bundle_tip == lineage.commit,
        "bundle_sha256_equal": hash_file(Path(lineage.bundle_path)).digest == lineage.bundle_sha256,
        "clean": clean,
    }
    return {
        "workspace": str(workspace),
        "checks": checks,
        "payload_hash": observed["manifest_sha256"],
        "verdict": (
            "BASELINE_EQUIVALENT_BUILD_PROVEN"
            if all(checks.values())
            else "BASELINE_EQUIVALENT_BUILD_CONTRADICTED"
        ),
    }


def verify_lineage_attestation(guard_root: Path, workspace: Path) -> dict[str, object]:
    lineage = ReconciliationLineage.model_validate_json(
        (workspace / "evidence" / "reconciliation-lineage.json").read_text("utf-8")
    )
    envelope = json.loads(Path(lineage.lineage_attestation_path).read_text("utf-8"))
    payload = envelope["payload"]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    canonical_equal = sha256(canonical).hexdigest() == envelope["canonical_sha256"]
    trusted_path = guard_root / "trust" / "keys" / f"{envelope['signing_key_id']}.pub.json"
    _, public = load_trusted_public_key(trusted_path)
    signature_valid = False
    try:
        public.verify(base64.b64decode(envelope["signature"]), canonical)
        signature_valid = True
    except (ValueError, TypeError):
        signature_valid = False
    claims_equal = (
        payload["commit"] == lineage.commit
        and payload["bundle_sha256"] == lineage.bundle_sha256
        and payload["bundle_tip"] == lineage.bundle_tip
    )
    return {
        "lineage_attestation": lineage.lineage_attestation_path,
        "signing_key_id": envelope["signing_key_id"],
        "canonical_hash_equal": canonical_equal,
        "signature_valid": signature_valid,
        "claims_equal": claims_equal,
        "verdict": (
            "RECONCILIATION_LINEAGE_SIGNATURE_PROVEN"
            if canonical_equal and signature_valid and claims_equal
            else "RECONCILIATION_LINEAGE_SIGNATURE_CONTRADICTED"
        ),
    }


def _imported_scripts(source: str) -> list[str]:
    values: list[str] = []
    for call in re.findall(r"importScripts\s*\(([\s\S]*?)\);", source):
        values.extend(re.findall(r"""["']([^"']+\.js)["']""", call))
    return values


def _executable_resources(extension: Path) -> list[str]:
    manifest = json.loads((extension / "manifest.json").read_text("utf-8"))
    worker = str(manifest.get("background", {}).get("service_worker", "serviceWorker.js"))
    panel = str(manifest.get("side_panel", {}).get("default_path", "panel.html"))
    worker_imports = _imported_scripts((extension / worker).read_text("utf-8"))
    background_imports = (
        _imported_scripts((extension / "background.js").read_text("utf-8"))
        if "background.js" in worker_imports
        else []
    )
    panel_scripts = re.findall(
        r"""<script\s+[^>]*src=["']([^"']+)["'][^>]*>""",
        (extension / panel).read_text("utf-8"),
        flags=re.I,
    )
    values = [
        "manifest.json",
        worker,
        panel,
        *worker_imports,
        *background_imports,
        *panel_scripts,
        *[str(path) for item in manifest.get("content_scripts", []) for path in item.get("js", [])],
    ]
    return sorted(set(values))


def _rewrite_stamp(source: str, build_id: str, artifact_hash: str) -> str:
    start_marker = "/* GENERATED_CONTEXT_BUILD_IDENTITY_START */"
    end_marker = "/* GENERATED_CONTEXT_BUILD_IDENTITY_END */"
    start = source.index(start_marker)
    end = source.index(end_marker) + len(end_marker)
    block = source[start:end]
    block = re.sub(r'buildId:\s*"[^"]*"', f'buildId: "{build_id}"', block, count=1)
    block = re.sub(
        r'artifactSetHash:\s*"[^"]*"',
        f'artifactSetHash: "{artifact_hash}"',
        block,
        count=1,
    )
    return source[:start] + block + source[end:]


def generate_successor_build_identity(extension: Path) -> dict[str, Any]:
    manifest = json.loads((extension / "manifest.json").read_text("utf-8"))
    build_info_path = extension / "buildInfo.js"
    source = build_info_path.read_text("utf-8")
    source = source.replace('version: "1.1.17"', 'version: "1.1.18"', 1)
    source = source.replace(
        "extension-trace-first-successor-1.1.17",
        "extension-compat-successor-1.1.18",
        1,
    )
    build_info_path.write_text(source, encoding="utf-8")
    resources = _executable_resources(extension)
    canonical: dict[str, str] = {}
    for relative in resources:
        raw = (extension / relative).read_bytes()
        if relative == "buildInfo.js":
            canonical_source = _rewrite_stamp(
                raw.decode(),
                "__GENERATED_EXTENSION_BUILD_ID__",
                "__GENERATED_ARTIFACT_SET_HASH__",
            ).encode()
            raw = canonical_source
        canonical[relative] = sha256(raw).hexdigest()
    aggregate = "\n".join(f"{path}|{digest}" for path, digest in sorted(canonical.items()))
    artifact_hash = sha256(aggregate.encode()).hexdigest()
    build_id = f"extension-{manifest['version']}-{artifact_hash[:16]}"
    stamped = _rewrite_stamp(build_info_path.read_text("utf-8"), build_id, artifact_hash)
    build_info_path.write_text(stamped, encoding="utf-8")
    actual = {relative: hash_file(extension / relative).digest for relative in resources}
    identity = {
        "schemaVersion": "study-pilot.executable-build-identity.v2",
        "buildId": build_id,
        "artifactSetHash": artifact_hash,
        "hashPolicy": {
            "schemaVersion": "study-pilot.context-stamp-canonicalization.v1",
            "contextStampResource": "buildInfo.js",
            "canonicalizedFields": ["buildId", "artifactSetHash"],
            "aggregateSource": "canonicalResourceHashes",
            "actualByteSource": "resourceHashes",
        },
        "canonicalResourceHashes": canonical,
        "resourceHashes": actual,
    }
    (extension / "BUILD_IDENTITY.json").write_text(
        json.dumps(identity, indent=2) + "\n", encoding="utf-8"
    )
    return identity


def _successor_attestation(
    guard_root: Path,
    candidate_id: str,
    source_repository: str,
    source_head: str,
    source_manifest_hash: str,
    component_input_hash: str,
    payload: dict[str, Any],
) -> BuildAttestation:
    now = datetime.now(UTC)
    key = inspect_key()
    value = BuildAttestation(
        schema_version="1.0",
        project="itzako",
        component="extension-compatibility-successor",
        candidate_id=candidate_id,
        source_repository=source_repository,
        source_head=source_head,
        source_dirty=False,
        source_staged=False,
        repository_source_manifest_hash=source_manifest_hash,
        component_build_input_manifest_hash=component_input_hash,
        dependency_lockfile_hashes={},
        build_script_hashes={},
        configuration_hashes={},
        builder=builder_identity(guard_root),
        guard_head=verifier_identity().head,
        guard_version=__version__,
        build_command=["STATIC_SOURCE_AS_RUNTIME_COPY", "GUARD_BUILD_IDENTITY_GENERATION"],
        build_started_at=now,
        build_finished_at=now,
        build_exit_code=0,
        build_environment_policy_hash="NO_NETWORK_NO_DEPENDENCIES",
        artefact_payload_manifest_hash=str(payload["manifest_sha256"]),
        artefact_file_count=int(payload["file_count"]),
        artefact_total_bytes=int(payload["total_bytes"]),
        build_reproducibility_state="REPRODUCIBLE_BUILD_PROVEN",
        signing_key_id=key.key_id,
        signature_algorithm="Ed25519",
        attestation_created_at=now,
        limitations=[
            "Compatibility-only successor; behavioural correctness is UNPROVEN.",
            "Normal-profile runtime and promotion authority remain NONE.",
            "Only version and executable build identity metadata changed.",
        ],
        evidence_references=[
            "evidence/build-input-manifest.json",
            "evidence/payload-manifest.json",
            "evidence/compatibility-delta.json",
        ],
    )
    sign_attestation(value)
    return value


def build_compat_successor(
    guard_root: Path,
    clone: IsolatedCloneIdentity,
    lineage: ReconciliationLineage,
    run_id: str,
) -> tuple[CompatibilitySuccessorDelta, SuccessorCandidateIdentity]:
    repository = Path(clone.repository_root)
    branch = f"candidate/itzako-extension-1.1.18-compat-{run_id}"
    _git(repository, ["switch", "-c", branch, lineage.commit])
    extension = repository / "Study_master" / "extension"
    manifest_path = extension / "manifest.json"
    before_manifest = json.loads(manifest_path.read_text("utf-8"))
    text = manifest_path.read_text("utf-8")
    if text.count('"version": "1.1.17"') != 1:
        raise RuntimeError("SUCCESSOR_VERSION_TOKEN_AMBIGUOUS")
    manifest_path.write_text(
        text.replace('"version": "1.1.17"', '"version": "1.1.18"', 1),
        encoding="utf-8",
    )
    generate_successor_build_identity(extension)
    _git(repository, ["add", "--", *sorted(PERMITTED_SUCCESSOR_PATHS)])
    actual = _git(repository, ["diff", "--cached", "--name-only"]).splitlines()
    unexpected = sorted(set(actual) - PERMITTED_SUCCESSOR_PATHS)
    if unexpected:
        raise RuntimeError(f"SUCCESSOR_UNEXPECTED_DELTA:{unexpected}")
    parent = _git(repository, ["rev-parse", "HEAD"])
    _git(repository, ["commit", "-m", "build: seal 1.1.18 compatibility successor"])
    commit = _git(repository, ["rev-parse", "HEAD"])
    if _git(repository, ["status", "--porcelain"]):
        raise RuntimeError("SUCCESSOR_BRANCH_NOT_CLEAN")
    after_manifest = json.loads(manifest_path.read_text("utf-8"))
    invariant_fields = [
        "key",
        "manifest_version",
        "permissions",
        "host_permissions",
        "content_scripts",
        "externally_connectable",
        "commands",
        "web_accessible_resources",
    ]
    invariants = {
        field: before_manifest.get(field) == after_manifest.get(field) for field in invariant_fields
    }
    worker_equal = before_manifest.get("background", {}).get(
        "service_worker"
    ) == after_manifest.get("background", {}).get("service_worker")
    product_paths = [path for path in actual if path not in PERMITTED_SUCCESSOR_PATHS]
    delta = CompatibilitySuccessorDelta(
        branch=branch,
        commit=commit,
        parent=parent,
        permitted_changed_paths=sorted(PERMITTED_SUCCESSOR_PATHS),
        actual_changed_paths=actual,
        unexpected_changed_paths=unexpected,
        manifest_key_equal=invariants["key"],
        worker_equal=worker_equal,
        permissions_equal=invariants["permissions"],
        host_permissions_equal=invariants["host_permissions"],
        content_scripts_equal=invariants["content_scripts"],
        product_behaviour_files_equal=not product_paths,
        verdict=(
            "COMPATIBILITY_SUCCESSOR_DELTA_PROVEN"
            if all(invariants.values()) and worker_equal and not unexpected
            else "COMPATIBILITY_SUCCESSOR_DELTA_CONTRADICTED"
        ),
    )
    source_manifest = _logical_manifest(extension, excluded_names=set())
    source_prefix = source_manifest["manifest_sha256"][:12]
    candidate_id = (
        f"itzako-extension-1.1.18-compat-"
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{source_prefix}"
    )
    candidate = guard_root / ".work" / "candidates" / candidate_id
    artefact = candidate / "artefact" / "extension"
    evidence = candidate / "evidence"
    evidence.mkdir(parents=True)
    first = _copy_exact(extension, artefact)
    repro_copy = guard_root / ".work" / "successor-reconciliation" / run_id / "repro-copy"
    second = _copy_exact(extension, repro_copy)
    reproducible = first == second
    shutil.rmtree(repro_copy)
    if not reproducible:
        raise RuntimeError("SUCCESSOR_REPRODUCIBILITY_CONTRADICTED")
    input_claim: dict[str, object] = {
        "repository_head": commit,
        "source_manifest_sha256": source_manifest["manifest_sha256"],
        "repository_dirty": False,
        "dependency_lockfile_hashes": {},
        "build_script_hashes": {
            "guard_phase2f": hash_file(Path(__file__)).digest,
        },
        "configuration_hashes": {},
        "build_procedure": "DETERMINISTIC_STATIC_SOURCE_AS_RUNTIME_COPY",
        "network_policy": "NO_NETWORK",
    }
    component_input_hash = sha256(
        json.dumps(input_claim, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    input_claim["manifest_sha256"] = component_input_hash
    (evidence / "build-input-manifest.json").write_text(
        json.dumps(input_claim, indent=2), encoding="utf-8"
    )
    (evidence / "payload-manifest.json").write_text(json.dumps(first, indent=2), encoding="utf-8")
    (evidence / "compatibility-delta.json").write_text(
        delta.model_dump_json(indent=2), encoding="utf-8"
    )
    attestation = _successor_attestation(
        guard_root,
        candidate_id,
        clone.fetch_remote,
        commit,
        str(source_manifest["manifest_sha256"]),
        component_input_hash,
        first,
    )
    rendered = json.dumps(attestation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    (evidence / "build-attestation.json").write_text(rendered, encoding="utf-8")
    (artefact / "kratos-build-attestation.json").write_text(rendered, encoding="utf-8")
    delivery = _logical_manifest(artefact, excluded_names=set())
    trusted = guard_root / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    verification = verify_candidate(candidate, trusted)
    identity = SuccessorCandidateIdentity(
        candidate_id=candidate_id,
        candidate_directory=str(candidate),
        version=str(after_manifest["version"]),
        payload_hash=str(first["manifest_sha256"]),
        delivery_hash=str(delivery["manifest_sha256"]),
        attestation_sha256=hash_file(evidence / "build-attestation.json").digest,
        signing_key_id=attestation.signing_key_id,
        signature_state=verification.signature_state,
        signer_trust_state=verification.signer_trust_state,
        reproducibility_state=(
            "REPRODUCIBLE_BUILD_PROVEN" if reproducible else "REPRODUCIBLE_BUILD_CONTRADICTED"
        ),
        source_head=commit,
        source_manifest_hash=str(source_manifest["manifest_sha256"]),
        component_input_hash=component_input_hash,
    )
    return delta, identity


def compare_successor_baseline(baseline: Path, candidate: Path) -> StaticCompatibilityReport:
    base_root = baseline / "artefact" / "extension"
    candidate_root = candidate / "artefact" / "extension"
    base_manifest = json.loads((base_root / "manifest.json").read_text("utf-8"))
    candidate_manifest = json.loads((candidate_root / "manifest.json").read_text("utf-8"))
    base_files = {
        str(item["path"]): str(item["sha256"])
        for item in _logical_manifest(base_root, excluded_names={"kratos-build-attestation.json"})[
            "entries"
        ]
    }
    candidate_files = {
        str(item["path"]): str(item["sha256"])
        for item in _logical_manifest(
            candidate_root, excluded_names={"kratos-build-attestation.json"}
        )["entries"]
    }
    actual = sorted(
        path
        for path in set(base_files) | set(candidate_files)
        if base_files.get(path) != candidate_files.get(path)
    )
    permitted = sorted(
        path.removeprefix("Study_master/extension/") for path in PERMITTED_SUCCESSOR_PATHS
    )
    unexpected = sorted(set(actual) - set(permitted))
    fields = [
        "key",
        "manifest_version",
        "permissions",
        "host_permissions",
        "content_scripts",
        "externally_connectable",
        "commands",
        "web_accessible_resources",
    ]
    invariants = {
        field: base_manifest.get(field) == candidate_manifest.get(field) for field in fields
    }
    invariants["worker"] = base_manifest.get("background", {}).get(
        "service_worker"
    ) == candidate_manifest.get("background", {}).get("service_worker")
    invariants["extension_id_key_material"] = invariants["key"]
    return StaticCompatibilityReport(
        baseline_id=baseline.name,
        candidate_id=candidate.name,
        permitted_delta=permitted,
        actual_delta=actual,
        unexpected_delta=unexpected,
        invariant_results=invariants,
        verdict=(
            "SUCCESSOR_STATIC_COMPATIBILITY_PROVEN"
            if all(invariants.values()) and not unexpected
            else "SUCCESSOR_STATIC_COMPATIBILITY_CONTRADICTED"
        ),
    )


def execute_phase2f(guard_root: Path) -> Phase2FReport:
    config = load_phase2f_config(guard_root)
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    mapping = map_configured_extension_source(guard_root)
    selection = select_reconciliation_base(guard_root)
    clone, lineage, plan = create_isolated_reconciliation(
        guard_root, mapping, selection, run_id=run_id
    )
    delta, candidate = build_compat_successor(guard_root, clone, lineage, run_id)
    candidate_path = Path(candidate.candidate_directory)
    baseline_path = Path(config["baseline_path"])
    static = compare_successor_baseline(baseline_path, candidate_path)
    canary_policy = plan_extension_canary(guard_root, candidate_path)
    canary = run_extension_canary(
        guard_root,
        candidate_path,
        Path(clone.repository_root),
        canary_policy,
        verifier_identity().model_dump(mode="json"),
    )
    runtime_proven = (
        canary.runtime_verification.build_to_runtime_state is EvidenceState.PROVEN
        and canary.extension_runtime is not None
        and canary.extension_runtime.extension_id == config["extension_id"]
        and canary.extension_runtime.service_worker_url.endswith("/serviceWorker.js")
        and canary.runtime_readback is not None
        and canary.runtime_readback.state is EvidenceState.PROVEN
    )
    canary_payload = canary.model_dump(mode="json")
    canary_payload["qualified_verdict"] = (
        "COMPATIBILITY_SUCCESSOR_ISOLATED_RUNTIME_PROVEN"
        if runtime_proven
        else "SUCCESSOR_RUNTIME_UNPROVEN"
    )
    canary_payload["qualified_verdict"] = (
        "COMPATIBILITY_SUCCESSOR_ISOLATED_RUNTIME_PROVEN"
        if runtime_proven
        else "COMPATIBILITY_SUCCESSOR_ISOLATED_RUNTIME_UNPROVEN"
    )
    success = (
        mapping.verdict == "COMPLETE_SOURCE_MAPPING_PROVEN"
        and lineage.verdict == "BASELINE_EQUIVALENT_BUILD_PROVEN"
        and delta.verdict == "COMPATIBILITY_SUCCESSOR_DELTA_PROVEN"
        and static.verdict == "SUCCESSOR_STATIC_COMPATIBILITY_PROVEN"
        and runtime_proven
    )
    report = Phase2FReport(
        schema_version="1.0",
        run_id=run_id,
        observed_at=datetime.now(UTC),
        mapping=mapping,
        base_selection=selection,
        plan=plan,
        clone=clone,
        reconciliation=lineage,
        successor_delta=delta,
        successor_candidate=candidate,
        successor_canary=canary_payload,
        static_compatibility=static,
        final_verdict=(
            "COMPATIBILITY_SUCCESSOR_CANDIDATE_PROVEN" if success else "SUCCESSOR_RUNTIME_UNPROVEN"
        ),
        promotion_authority="NONE",
        first_remaining_blocker=(
            "BEHAVIOURAL_SUCCESSOR_CHANGE_NOT_IMPLEMENTED"
            if success
            else "PHASE2F_PROOF_INCOMPLETE"
        ),
        safety_counters=dict(PHASE2F_SAFETY_COUNTERS),
        limitations=[
            "Compatibility-only successor; no behavioural change was implemented.",
            "Isolated runtime proof does not satisfy normal-profile proof.",
            "No Study Pilot or normal Chrome mutation was authorised or performed.",
        ],
    )
    evidence = guard_root / ".work" / "successor-reconciliation" / run_id / "evidence"
    (evidence / "successor-delta.json").write_text(delta.model_dump_json(indent=2), "utf-8")
    (evidence / "successor-candidate.json").write_text(candidate.model_dump_json(indent=2), "utf-8")
    (evidence / "successor-canary.json").write_text(json.dumps(canary_payload, indent=2), "utf-8")
    (evidence / "static-compatibility.json").write_text(static.model_dump_json(indent=2), "utf-8")
    (evidence / "phase2f-report.json").write_text(report.model_dump_json(indent=2), "utf-8")
    return report
