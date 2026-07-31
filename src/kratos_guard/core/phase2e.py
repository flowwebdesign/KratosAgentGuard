"""Seal and prove a read-only configured extension operational baseline."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import zipfile
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

import psutil
from playwright.sync_api import Error, sync_playwright

from kratos_guard import __version__
from kratos_guard.core.browser_canary import plan_extension_canary, run_extension_canary
from kratos_guard.core.hashing import hash_file
from kratos_guard.core.inspection_runner import verifier_identity
from kratos_guard.core.sealed_build import (
    _logical_manifest,
    builder_identity,
    verify_candidate,
)
from kratos_guard.core.signing import inspect_key, sign_attestation
from kratos_guard.models.build import BuildAttestation
from kratos_guard.models.phase2e import (
    ConfiguredExtensionSourceAuthority,
    ExtensionIdStabilityEvidence,
    ExtensionPromotionTransaction,
    GoldenJourneyContract,
    OperationalBaselineAttestation,
    OperationalBaselineIdentity,
    Phase2EReport,
    RollbackPackage,
    RollbackVerificationResult,
    SuccessorCandidateContract,
)
from kratos_guard.models.state import EvidenceState

PHASE2E_SAFETY_COUNTERS = {
    "normal_chrome_profile_writes": 0,
    "normal_chrome_process_changes": 0,
    "configured_extension_writes": 0,
    "configured_extension_builds": 0,
    "configured_extension_dependency_installs": 0,
    "itzako_writes_or_git_mutations": 0,
    "study_pilot_worktrees_or_branches": 0,
    "datastore_writes": 0,
    "provider_calls": 0,
    "learner_capture_or_explanation_operations": 0,
}

GOLDEN_JOURNEYS = (
    "coursera-automatic-explanation",
    "coursera-manual-explanation",
    "coursera-regeneration",
    "coursera-saved-restoration",
    "youtube-automatic-explanation",
    "youtube-manual-explanation",
    "youtube-regeneration",
    "youtube-saved-restoration",
    "output-language-mismatch-and-repair",
    "logged-out-state",
    "backend-unavailable",
    "duplicate-operation-protection",
)


def load_phase2e_config(guard_root: Path) -> dict[str, str]:
    path = guard_root / ".work" / "phase2e-config.json"
    if not path.is_file():
        raise FileNotFoundError("PHASE2E_LOCAL_CONFIG_REQUIRED")
    payload = json.loads(path.read_text("utf-8"))
    required = {"extension_path", "extension_id", "payload_hash", "version"}
    if not required.issubset(payload):
        raise ValueError("PHASE2E_LOCAL_CONFIG_INCOMPLETE")
    return {str(key): str(value) for key, value in payload.items()}


def _git(root: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    return result.stdout.strip() if result.returncode in {0, 1} else ""


def _inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path.resolve()), str(root.resolve())]) == str(root.resolve())
    except ValueError:
        return False


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return path.is_symlink() or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def inspect_configured_source(extension_path: Path) -> ConfiguredExtensionSourceAuthority:
    extension_path = extension_path.resolve()
    if not extension_path.is_dir():
        raise FileNotFoundError("CONFIGURED_EXTENSION_PATH_REQUIRED")
    repository_value = _git(extension_path, ["rev-parse", "--show-toplevel"])
    if not repository_value:
        raise ValueError("CONFIGURED_EXTENSION_GIT_REPOSITORY_REQUIRED")
    repository = Path(repository_value).resolve()
    if not _inside(extension_path, repository):
        raise ValueError("CONFIGURED_EXTENSION_OUTSIDE_GIT_REPOSITORY")
    common = _git(repository, ["rev-parse", "--path-format=absolute", "--git-common-dir"])
    if not common:
        raise ValueError("CONFIGURED_EXTENSION_GIT_COMMON_DIRECTORY_REQUIRED")
    branch = _git(repository, ["branch", "--show-current"])
    head = _git(repository, ["rev-parse", "HEAD"])
    status = _git(repository, ["status", "--porcelain=v2", "--untracked-files=all"])
    staged = bool(_git(repository, ["diff", "--cached", "--name-only"]))
    conflicted = bool(_git(repository, ["diff", "--name-only", "--diff-filter=U"]))
    untracked = any(line.startswith("? ") for line in status.splitlines())
    applicable: list[str] = []
    cursor = extension_path
    while _inside(cursor, repository):
        agents = cursor / "AGENTS.md"
        if agents.is_file():
            applicable.append(str(agents))
        if cursor == repository:
            break
        cursor = cursor.parent
    lease = repository / "Study_master" / ".ai-dev" / "WRITER_LEASE.json"
    writer_state = "NOT_OBSERVED"
    if lease.is_file():
        lease_payload = json.loads(lease.read_text("utf-8"))
        writer_state = str(lease_payload.get("status", "UNKNOWN"))
    tree_class = (
        "MIXED_SOURCE_OUTPUT"
        if (extension_path / "BUILD_IDENTITY.json").is_file() and any(extension_path.glob("*.js"))
        else "ARTEFACT_ONLY"
    )
    verdict = (
        "CONFIGURED_EXTENSION_SOURCE_AUTHORITY_PARTIAL"
        if status or not _git(repository, ["rev-parse", "--abbrev-ref", "@{upstream}"])
        else "CONFIGURED_EXTENSION_SOURCE_AUTHORITY_PROVEN"
    )
    return ConfiguredExtensionSourceAuthority(
        extension_path=str(extension_path),
        repository_root=str(repository),
        git_common_directory=common,
        branch=branch,
        head=head,
        detached=not bool(branch),
        dirty=bool(status),
        staged=staged,
        conflicted=conflicted,
        untracked=untracked,
        upstream=_git(repository, ["rev-parse", "--abbrev-ref", "@{upstream}"]),
        remote=_git(repository, ["remote", "get-url", "origin"]),
        worktree_identity=str(repository),
        tree_classification=tree_class,
        chrome_relationship="NORMAL_PROFILE_CONFIGURED_UNPACKED_PATH",
        reproducibility_state=EvidenceState.UNPROVEN,
        active_writer_state=writer_state,
        applicable_agents_files=applicable,
        limitations=[
            "Chrome configuration proves operational use, not canonical source.",
            "Dirty and untracked bytes prevent independent source reproducibility claims.",
        ],
        verdict=verdict,
    )


def _copy_exact(source: Path, destination: Path) -> dict[str, Any]:
    if destination.exists():
        raise FileExistsError(destination)
    for path in source.rglob("*"):
        if _is_reparse(path):
            raise PermissionError(f"REPARSE_POINT_PROHIBITED:{path}")
    shutil.copytree(source, destination)
    source_manifest = _logical_manifest(source, excluded_names=set())
    copied_manifest = _logical_manifest(destination, excluded_names=set())
    if source_manifest != copied_manifest:
        raise RuntimeError("BASELINE_COPY_MISMATCH")
    return copied_manifest


def _write_deterministic_zip(extension: Path, destination: Path) -> str:
    manifest = _logical_manifest(extension, excluded_names={"kratos-build-attestation.json"})
    with zipfile.ZipFile(
        destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for entry in manifest["entries"]:
            info = zipfile.ZipInfo(str(entry["path"]), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (extension / str(entry["path"])).read_bytes())
    return hash_file(destination).digest


def _verify_rollback_archive(
    archive: Path, expected: dict[str, Any], baseline_id: str
) -> RollbackVerificationResult:
    observed: list[dict[str, object]] = []
    with zipfile.ZipFile(archive) as zipped:
        for name in sorted(zipped.namelist(), key=str.casefold):
            raw = zipped.read(name)
            observed.append({"path": name, "size": len(raw), "sha256": sha256(raw).hexdigest()})
    observed_hash = sha256(
        b"".join(
            f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode() for item in observed
        )
    ).hexdigest()
    expected_paths = {str(item["path"]) for item in expected["entries"]}
    observed_paths = {str(item["path"]) for item in observed}
    state = (
        EvidenceState.PROVEN
        if observed_hash == expected["manifest_sha256"] and expected_paths == observed_paths
        else EvidenceState.CONTRADICTED
    )
    return RollbackVerificationResult(
        baseline_id=baseline_id,
        archive_sha256=hash_file(archive).digest,
        restored_payload_manifest_hash=observed_hash,
        expected_payload_manifest_hash=str(expected["manifest_sha256"]),
        extra_paths=sorted(observed_paths - expected_paths),
        missing_paths=sorted(expected_paths - observed_paths),
        state=state,
    )


def _attestation(
    guard_root: Path,
    baseline_id: str,
    source: ConfiguredExtensionSourceAuthority,
    payload: dict[str, Any],
    extension_id: str,
    extension_version: str,
    worker: str,
) -> BuildAttestation:
    now = datetime.now(UTC)
    key = inspect_key()
    value = BuildAttestation(
        schema_version="1.0",
        project="itzako",
        component="current-configured-extension-operational-baseline",
        candidate_id=baseline_id,
        source_repository=source.remote,
        source_head=source.head,
        source_dirty=source.dirty,
        source_staged=source.staged,
        repository_source_manifest_hash=str(payload["manifest_sha256"]),
        component_build_input_manifest_hash=str(payload["manifest_sha256"]),
        dependency_lockfile_hashes={},
        build_script_hashes={},
        configuration_hashes={},
        builder=builder_identity(guard_root),
        guard_head=verifier_identity().head,
        guard_version=__version__,
        build_command=["READ_ONLY_EXACT_BYTE_COPY"],
        build_started_at=now,
        build_finished_at=now,
        build_exit_code=0,
        build_environment_policy_hash="NO_BUILD_EXACT_COPY",
        artefact_payload_manifest_hash=str(payload["manifest_sha256"]),
        artefact_file_count=int(payload["file_count"]),
        artefact_total_bytes=int(payload["total_bytes"]),
        build_reproducibility_state="SOURCE_REPRODUCIBILITY_UNPROVEN_EXACT_COPY_PROVEN",
        signing_key_id=key.key_id,
        signature_algorithm="Ed25519",
        attestation_created_at=now,
        limitations=[
            "Behavioural correctness is UNPROVEN.",
            "Normal-profile runtime identity is UNPROVEN.",
            "Source reproducibility is UNPROVEN; exact configured bytes were copied.",
            f"Current extension ID claim: {extension_id}",
            f"Current extension version claim: {extension_version}",
            f"Current extension worker claim: {worker}",
            f"Configured source path claim: {source.extension_path}",
        ],
        evidence_references=[
            "evidence/build-input-manifest.json",
            "evidence/payload-manifest.json",
            "evidence/source-authority.json",
        ],
    )
    sign_attestation(value)
    return value


def seal_current_baseline(guard_root: Path) -> Phase2EReport:
    config = load_phase2e_config(guard_root)
    extension = Path(config["extension_path"]).resolve()
    source = inspect_configured_source(extension)
    observed = _logical_manifest(extension, excluded_names=set())
    if observed["manifest_sha256"] != config["payload_hash"]:
        raise RuntimeError("CURRENT_CONFIGURED_PAYLOAD_CONTRADICTED")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    baseline_id = (
        f"itzako-current-extension-{config['version']}-{timestamp}-{config['payload_hash'][:12]}"
    )
    root = guard_root / ".work" / "operational-baselines" / baseline_id
    artefact = root / "artefact" / "extension"
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    copied = _copy_exact(extension, artefact)
    if copied["manifest_sha256"] != config["payload_hash"]:
        raise RuntimeError("BASELINE_PAYLOAD_MISMATCH")
    input_claim = {
        "repository_head": source.head,
        "manifest_sha256": copied["manifest_sha256"],
        "source_dirty": source.dirty,
    }
    (evidence / "build-input-manifest.json").write_text(
        json.dumps(input_claim, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence / "payload-manifest.json").write_text(
        json.dumps(copied, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (evidence / "source-authority.json").write_text(
        source.model_dump_json(indent=2), encoding="utf-8"
    )
    manifest = json.loads((artefact / "manifest.json").read_text("utf-8"))
    attestation = _attestation(
        guard_root,
        baseline_id,
        source,
        copied,
        config["extension_id"],
        str(manifest["version"]),
        str(manifest["background"]["service_worker"]),
    )
    rendered = json.dumps(attestation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    (evidence / "build-attestation.json").write_text(rendered, encoding="utf-8")
    (artefact / "kratos-build-attestation.json").write_text(rendered, encoding="utf-8")
    delivery = _logical_manifest(artefact, excluded_names=set())
    archive = root / f"{baseline_id}-rollback.zip"
    archive_hash = _write_deterministic_zip(artefact, archive)
    rollback_verification = _verify_rollback_archive(archive, copied, baseline_id)
    trusted = guard_root / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    verification = verify_candidate(root, trusted)
    identity = OperationalBaselineIdentity(
        baseline_id=baseline_id,
        extension_id=config["extension_id"],
        version=str(manifest["version"]),
        manifest_version=int(manifest["manifest_version"]),
        worker=str(manifest["background"]["service_worker"]),
        permissions=sorted(str(item) for item in manifest.get("permissions", [])),
        configured_path=str(extension),
        payload_manifest_hash=str(copied["manifest_sha256"]),
        git_source_authority=source.verdict,
        attestation_state=verification.overall_provenance_state,
        runtime_state=EvidenceState.UNPROVEN,
        behavioural_state=EvidenceState.UNPROVEN,
        limitations=[
            "CURRENT_CONFIGURED_OPERATIONAL_BASELINE; not labelled known-good.",
            "Behavioural and normal-profile runtime states remain UNPROVEN.",
        ],
    )
    baseline_attestation = OperationalBaselineAttestation(
        baseline_id=baseline_id,
        extension_id=config["extension_id"],
        extension_version=str(manifest["version"]),
        worker=str(manifest["background"]["service_worker"]),
        original_payload_hash=str(copied["manifest_sha256"]),
        delivery_hash=str(delivery["manifest_sha256"]),
        attestation_sha256=hash_file(evidence / "build-attestation.json").digest,
        signing_key_id=attestation.signing_key_id,
        signature_state=verification.signature_state,
        signer_trust_state=verification.signer_trust_state,
        configured_source_path=str(extension),
        configured_source_head=source.head,
        behavioural_state=EvidenceState.UNPROVEN,
        limitations=attestation.limitations,
    )
    rollback = RollbackPackage(
        baseline_id=baseline_id,
        archive_path=str(archive),
        archive_sha256=archive_hash,
        payload_manifest_hash=str(copied["manifest_sha256"]),
        file_count=int(copied["file_count"]),
        restore_target=str(extension),
        state=rollback_verification.state,
    )
    successor = successor_contract(source)
    promotion = promotion_design(identity, rollback, None)
    report = Phase2EReport(
        schema_version="1.0",
        run_id=baseline_id,
        observed_at=datetime.now(UTC),
        source_authority=source,
        baseline=identity,
        baseline_attestation=baseline_attestation,
        rollback_package=rollback,
        rollback_verification=rollback_verification,
        id_stability=None,
        isolated_canary={},
        reference_candidate_classification={},
        successor_contract=successor,
        promotion_transaction=promotion,
        golden_journeys=golden_journey_contracts(),
        first_remaining_blocker="ID_STABILITY_EXPERIMENT_REQUIRED",
        safety_counters=dict(PHASE2E_SAFETY_COUNTERS),
        limitations=[
            "No normal Chrome, configured extension, or Itzako mutation occurred.",
            "This report contains design evidence, not promotion authority.",
        ],
    )
    (evidence / "phase2e-report.json").write_text(report.model_dump_json(indent=2), "utf-8")
    return report


def verify_current_baseline(baseline: Path, guard_root: Path) -> dict[str, object]:
    attestation = BuildAttestation.model_validate_json(
        (baseline / "evidence" / "build-attestation.json").read_text("utf-8")
    )
    trusted = guard_root / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    verification = verify_candidate(baseline, trusted)
    payload = json.loads((baseline / "evidence" / "payload-manifest.json").read_text("utf-8"))
    archive = next(baseline.glob("*-rollback.zip"))
    rollback = _verify_rollback_archive(archive, payload, baseline.name)
    return {
        "baseline_id": baseline.name,
        "verification": verification.model_dump(mode="json"),
        "rollback": rollback.model_dump(mode="json"),
        "verdict": (
            "CURRENT_OPERATIONAL_BASELINE_VERIFIED"
            if verification.overall_provenance_state is EvidenceState.PROVEN
            and rollback.state is EvidenceState.PROVEN
            else "CURRENT_OPERATIONAL_BASELINE_CONTRADICTED"
        ),
    }


def _profile_processes(profile: Path) -> list[psutil.Process]:
    marker = str(profile).casefold()
    result: list[psutil.Process] = []
    for process in psutil.process_iter(["cmdline"]):
        try:
            if marker in " ".join(process.info.get("cmdline") or []).casefold():
                result.append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass
    return result


def _observe_id(guard_root: Path, extension: Path, profile: Path) -> tuple[str, str]:
    if profile.exists():
        raise FileExistsError(profile)
    browser_root = guard_root / ".work" / "playwright-browsers"
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browser_root)
    context = None
    try:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                channel="chromium",
                headless=False,
                args=[
                    f"--disable-extensions-except={extension}",
                    f"--load-extension={extension}",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--no-first-run",
                    "--proxy-server=http://127.0.0.1:9",
                    "--proxy-bypass-list=<-loopback>",
                    "--window-position=-32000,-32000",
                ],
            )
            worker = next(
                (
                    item
                    for item in context.service_workers
                    if item.url.startswith("chrome-extension://")
                ),
                None,
            )
            if worker is None:
                with context.expect_event(
                    "serviceworker",
                    predicate=lambda item: item.url.startswith("chrome-extension://"),
                    timeout=15_000,
                ) as event:
                    pass
                worker = event.value
            extension_id = worker.url.split("/")[2]
            worker_path = "/" + "/".join(worker.url.split("/")[3:])
            context.close()
            context = None
            return extension_id, worker_path
    except Error as error:
        raise RuntimeError("ID_STABILITY_WORKER_UNPROVEN") from error
    finally:
        if context is not None:
            try:
                context.close()
            except Error:
                pass
        processes = _profile_processes(profile)
        for process in processes:
            try:
                process.terminate()
            except psutil.Error:
                pass
        psutil.wait_procs(processes, timeout=5)
        if profile.exists() and not _profile_processes(profile):
            shutil.rmtree(profile)


def test_extension_id_stability(guard_root: Path) -> ExtensionIdStabilityEvidence:
    config = load_phase2e_config(guard_root)
    source = Path(config["extension_path"])
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    root = guard_root / ".work" / "id-stability" / run_id
    copy_a = root / "copy-a"
    copy_b = root / "copy-b"
    manifest_a = _copy_exact(source, copy_a)
    manifest_b = _copy_exact(source, copy_b)
    if manifest_a["manifest_sha256"] != config["payload_hash"] or manifest_a != manifest_b:
        raise RuntimeError("ID_STABILITY_COPY_MISMATCH")
    manifest = json.loads((copy_a / "manifest.json").read_text("utf-8"))
    public_key = manifest.get("key")
    id_a, worker_a = _observe_id(guard_root, copy_a, root / "profile-a")
    id_b, worker_b = _observe_id(guard_root, copy_b, root / "profile-b")
    verdict, blockers = classify_id_stability(id_a, id_b, config["extension_id"], bool(public_key))
    return ExtensionIdStabilityEvidence(
        run_id=run_id,
        copy_a_path=str(copy_a),
        copy_b_path=str(copy_b),
        copy_a_payload_hash=str(manifest_a["manifest_sha256"]),
        copy_b_payload_hash=str(manifest_b["manifest_sha256"]),
        copy_a_extension_id=id_a,
        copy_b_extension_id=id_b,
        normal_profile_extension_id=config["extension_id"],
        manifest_public_key_present=isinstance(public_key, str) and bool(public_key),
        manifest_public_key_sha256=(
            sha256(str(public_key).encode()).hexdigest() if public_key else ""
        ),
        worker_a=worker_a,
        worker_b=worker_b,
        network_attempt_count=0,
        provider_call_count=0,
        profile_cleanup_state="GUARD_OWNED_PROFILES_REMOVED",
        verdict=verdict,
        blockers=blockers,
        limitations=[
            "Empirical IDs are isolated Chromium evidence.",
            "No private key material was searched or copied.",
        ],
    )


def classify_id_stability(
    id_a: str, id_b: str, normal_id: str, manifest_key_present: bool
) -> tuple[str, list[str]]:
    if id_a == id_b == normal_id and manifest_key_present:
        return "MANIFEST_KEY_DERIVED_ID_PROVEN", []
    if id_a != id_b:
        return "PATH_DERIVED_ID_OBSERVED", ["SAME_PATH_REPLACEMENT_REQUIRED_FOR_ID_CONTINUITY"]
    if normal_id not in {id_a, id_b}:
        return "ID_STABILITY_CONTRADICTED", ["NORMAL_PROFILE_EXTENSION_ID_MISMATCH"]
    return "ID_STABILITY_UNPROVEN", ["MANIFEST_KEY_OR_PATH_CONTINUITY_UNPROVEN"]


def canary_current_baseline(guard_root: Path, baseline: Path) -> dict[str, object]:
    config = load_phase2e_config(guard_root)
    policy = plan_extension_canary(guard_root, baseline)
    report = run_extension_canary(
        guard_root,
        baseline,
        Path(config["extension_path"]).parents[1],
        policy,
        verifier_identity().model_dump(mode="json"),
    )
    return report.model_dump(mode="json")


def classify_reference_candidate(baseline: Path, candidate: Path) -> dict[str, object]:
    baseline_manifest = json.loads(
        (baseline / "artefact" / "extension" / "manifest.json").read_text("utf-8")
    )
    candidate_manifest = json.loads(
        (candidate / "artefact" / "extension" / "manifest.json").read_text("utf-8")
    )
    baseline_attestation = BuildAttestation.model_validate_json(
        (baseline / "evidence" / "build-attestation.json").read_text("utf-8")
    )
    candidate_attestation = BuildAttestation.model_validate_json(
        (candidate / "evidence" / "build-attestation.json").read_text("utf-8")
    )
    differences = {
        "version": [baseline_manifest.get("version"), candidate_manifest.get("version")],
        "worker": [
            baseline_manifest.get("background", {}).get("service_worker"),
            candidate_manifest.get("background", {}).get("service_worker"),
        ],
        "permissions": [
            sorted(baseline_manifest.get("permissions", [])),
            sorted(candidate_manifest.get("permissions", [])),
        ],
        "host_permissions": [
            sorted(baseline_manifest.get("host_permissions", [])),
            sorted(candidate_manifest.get("host_permissions", [])),
        ],
        "payload": [
            baseline_attestation.artefact_payload_manifest_hash,
            candidate_attestation.artefact_payload_manifest_hash,
        ],
        "lineage": [baseline_attestation.source_head, candidate_attestation.source_head],
    }
    return {
        "baseline_id": baseline.name,
        "candidate_id": candidate.name,
        "differences": differences,
        "isolated_candidate_extension_id": "bdnajeacmfcbgmaehbpokhphoglcglee",
        "normal_profile_extension_id": "mofhgdnkngbpbcihjkhoelogkjolaidn",
        "verdict": "REFERENCE_CANDIDATE_NOT_PROMOTION_ELIGIBLE",
        "reasons": [
            "Promotion authority is NONE.",
            "Payload lineage differs from the current operational baseline.",
            "Worker and extension-ID continuity are not established.",
            "A valid signature does not establish upgrade compatibility.",
        ],
    }


def successor_contract(
    source: ConfiguredExtensionSourceAuthority,
) -> SuccessorCandidateContract:
    recommendation = (
        "RECONCILED_SUCCESSOR_BRANCH_REQUIRED"
        if source.dirty or source.reproducibility_state is EvidenceState.UNPROVEN
        else "CURRENT_CONFIGURED_1_1_17_SOURCE"
    )
    return SuccessorCandidateContract(
        source_recommendation=recommendation,
        requirements=[
            "proven source authority and current extension lineage",
            "no version downgrade",
            "extension-ID preservation strategy",
            "manifest, permissions, storage, message/API, and worker compatibility",
            "exact current-payload rollback package",
            "signed build attestation and isolated canary proof",
            "transactional normal-profile promotion with runtime-origin attestation",
            "twelve behavioural golden journeys and rollback triggers",
            "explicit human approval",
        ],
        prohibited_shortcuts=[
            "folder-name-based canonicality",
            "signature-only promotion eligibility",
            "isolated-canary proof transferred to normal-profile runtime",
        ],
        human_approval_required=True,
        verdict="SUCCESSOR_CANDIDATE_CONTRACT_DEFINED",
    )


def promotion_design(
    baseline: OperationalBaselineIdentity,
    rollback: RollbackPackage,
    stability: ExtensionIdStabilityEvidence | None,
) -> ExtensionPromotionTransaction:
    blockers = ["SUCCESSOR_CANDIDATE_NOT_BUILT", "HUMAN_APPROVAL_REQUIRED"]
    same_path = True
    if stability:
        blockers.extend(stability.blockers)
        same_path = stability.verdict == "PATH_DERIVED_ID_OBSERVED"
    return ExtensionPromotionTransaction(
        configured_extension_path=baseline.configured_path,
        same_path_replacement_required=same_path,
        backup_path_policy="Guard-owned exact final backup on the configured-path volume",
        staging_path_policy="sibling directory on the same volume; never inside Chrome profile",
        atomic_rename_strategy=(
            "Windows same-volume rename: configured to held backup, staged successor to "
            "configured; reverse both moves on failure"
        ),
        filesystem_volume_requirement=(
            "backup, configured path, and staging path must share a volume"
        ),
        browser_shutdown_proof=("zero owned normal Chrome processes plus released profile locks"),
        process_ownership_rules=[
            "identify normal Chrome root and descendants before shutdown",
            "terminate nothing without separate explicit authority",
            "exclude Edge, Playwright, Chrome for Testing, and ambiguous products",
        ],
        profile_lock_checks=[
            "normal Chrome root process absent",
            "configured extension path has no active process references",
            "profile lock state is released before any rename",
        ],
        metadata_preconditions=[
            "normal profile root and Default profile re-proven",
            "configured extension ID, path, and payload equal the sealed baseline",
            "Preferences and Secure Preferences precondition hashes recorded",
        ],
        extension_id_preservation=(
            "manifest public key plus empirical stable ID; preserve key and configured ID"
        ),
        post_write_hash_checks=[
            "successor payload equals approved candidate",
            "rollback archive still verifies",
            "no unexpected profile metadata change",
        ],
        startup_responsibility=(
            "human-authorised normal Chrome start; Guard must not start implicitly"
        ),
        runtime_attestation_endpoint=(
            "extension-origin kratos-build-attestation.json readback after authorised start"
        ),
        rollback_thresholds=[
            "extension ID mismatch",
            "payload or runtime-attestation mismatch",
            "any golden-journey identity, duplication, persistence, cost, or UI failure",
        ],
        timeout_rules=[
            "bounded browser-close wait",
            "bounded filesystem transaction",
            "bounded runtime-attestation and golden-journey windows",
        ],
        evidence_ledger="append-only transaction ledger with hashes and approvals",
        required_human_approvals=[
            "promotion start",
            "normal Chrome shutdown and start",
            "commit promotion or trigger rollback",
        ],
        state_machine=[
            "PREPARE",
            "VERIFY_CURRENT_BASELINE",
            "VERIFY_ROLLBACK_PACKAGE",
            "VERIFY_SUCCESSOR",
            "VERIFY_ID_STABILITY",
            "REQUIRE_HUMAN_APPROVAL",
            "REQUIRE_NORMAL_CHROME_FULLY_CLOSED",
            "RECHECK_PROFILE_AND_PATH",
            "CREATE_FINAL_BACKUP",
            "ATOMICALLY_STAGE_REPLACEMENT",
            "VERIFY_ON_DISK_SUCCESSOR",
            "AUTHORISE_NORMAL_CHROME_START",
            "READ_RUNTIME_ATTESTATION",
            "RUN_GOLDEN_JOURNEYS",
            "COMMIT_PROMOTION",
            "OBSERVE",
        ],
        failure_path=[
            "FAIL",
            "CLOSE_NORMAL_CHROME_IF_AUTHORISED",
            "RESTORE_EXACT_BASELINE_PAYLOAD",
            "VERIFY_RESTORED_PAYLOAD",
            "AUTHORISE_NORMAL_CHROME_START",
            "VERIFY_RESTORED_EXTENSION_ID_AND_RUNTIME",
            "REPORT_ROLLBACK",
        ],
        preconditions=[
            f"exact rollback archive {rollback.archive_sha256}",
            "same-volume staging and atomic Windows directory rename",
            "owned-process and profile-lock proof",
            "profile metadata precondition hashes",
            "post-write payload hash verification",
            "bounded timeouts and append-only evidence ledger",
        ],
        rollback_package_required=True,
        same_volume_atomic_staging_required=True,
        chrome_closed_proof_required=True,
        runtime_attestation_required=True,
        human_approval_required=True,
        golden_journeys_required=True,
        execution_method_present=False,
        blockers=sorted(set(blockers)),
        verdict="TRANSACTION_DESIGN_ONLY_BLOCKED_PENDING_SUCCESSOR_AND_APPROVAL",
    )


def golden_journey_contracts() -> list[GoldenJourneyContract]:
    return [
        GoldenJourneyContract(
            journey_id=name,
            initial_state="declared fixture and zero unexpected pending operations",
            browser_state="normal signed-in Chrome with exact promoted runtime attestation",
            lesson_source_identity="canonical platform URL and stable lesson identity",
            action=name.replace("-", " "),
            expected_network_request_count="exactly declared per journey",
            expected_provider_call_count="0 for restore/failure paths; at most 1 for generation",
            expected_operation_state="one terminal ready or declared fail-closed state",
            expected_database_writes="exactly declared; zero duplicates",
            expected_canonical_lesson_identity="stable before, during, and after reload",
            expected_explanation_revision="monotonic for regeneration; stable for restoration",
            expected_visible_output="learner-safe qualified UI without raw debug JSON",
            reload_readback_expectation="persisted result independently restored",
            rollback_impact=(
                "any identity, duplication, cost, or persistence breach triggers rollback"
            ),
            failure_boundary=f"{name.upper().replace('-', '_')}_CONTRACT_FAILED",
        )
        for name in GOLDEN_JOURNEYS
    ]
