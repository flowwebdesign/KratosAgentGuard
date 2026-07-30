"""Passive, privacy-bounded inspection of the normal Chrome profile."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import UTC, datetime
from pathlib import Path, PurePath
from typing import Any
from uuid import uuid4

import psutil

from kratos_guard.core.hashing import hash_file
from kratos_guard.core.sealed_build import _logical_manifest, verify_candidate
from kratos_guard.models.build import BuildAttestation
from kratos_guard.models.current_profile import (
    BrowserProcessGroup,
    BrowserProductIdentity,
    BrowserProfileReference,
    ConfiguredExtensionArtifact,
    ConfiguredExtensionIdentity,
    CurrentProfileIdentityReport,
    ExtensionInstallRecord,
    KnownExternalResidue,
    PromotionReadinessPlan,
    ResidueOwnershipState,
    ResiduePolicyState,
    SnapshotFileEvidence,
)
from kratos_guard.models.state import EvidenceState

RESIDUE_RELATIVE_PATH = Path("Google") / "Chrome for Testing" / "User Data"
SENSITIVE_NAMES = {
    "history",
    "cookies",
    "login data",
    "web data",
    "favicons",
    "sessions",
    "local storage",
    "indexeddb",
    "service worker",
    "cache",
    "code cache",
    "extension state",
}
STATIC_METADATA_NAMES = {
    "manifest.json",
    "buildinfo.js",
    "buildinfo.json",
    "build-attestation.json",
    "messages.json",
}
SAFETY_COUNTERS = {
    "browser_profile_writes": 0,
    "browser_processes_launched": 0,
    "browser_processes_terminated": 0,
    "tabs_opened_or_navigated": 0,
    "remote_debugging_changes": 0,
    "sensitive_browser_databases_read": 0,
    "itzako_writes_or_git_mutations": 0,
    "datastore_writes": 0,
    "provider_calls": 0,
}


def _canonical(path: Path) -> str:
    return str(path.resolve(strict=False))


def default_residue_path(local_app_data: Path | None = None) -> Path:
    base = local_app_data or Path(os.environ.get("LOCALAPPDATA", ""))
    return base / RESIDUE_RELATIVE_PATH


def load_residue_identity(guard_root: Path) -> tuple[Path, str]:
    path = guard_root / ".work" / "known-residue-exceptions" / "phase2c.json"
    if not path.is_file():
        return default_residue_path(), "UNRECORDED"
    payload = json.loads(path.read_text("utf-8"))
    return Path(str(payload["exact_path"])), str(payload["recorded_manifest_hash"])


def _same_path(left: Path | str, right: Path | str) -> bool:
    return os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(
        os.path.abspath(str(right))
    )


def _argument(command: list[str], name: str) -> str:
    prefix = f"--{name}="
    for index, value in enumerate(command):
        if value.startswith(prefix):
            return value[len(prefix) :].strip('"')
        if value == f"--{name}" and index + 1 < len(command):
            return command[index + 1].strip('"')
    return ""


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    secret = re.compile(r"(token|password|cookie|auth|secret)", re.I)
    for value in command:
        redacted.append("<redacted>" if secret.search(value) else value)
    return redacted


def classify_browser(executable: PurePath, command: list[str]) -> BrowserProductIdentity:
    lowered = str(executable).replace("\\", "/").casefold()
    executable_name = lowered.rsplit("/", 1)[-1]
    joined = " ".join(command).casefold()
    if "chrome for testing" in lowered:
        return BrowserProductIdentity.CHROME_FOR_TESTING
    if (
        "playwright" in lowered
        or ".work/playwright-browsers" in lowered
        or "playwright_chromiumdev_profile-" in joined
        or ("--remote-debugging-pipe" in command and "--headless" in command)
    ):
        return BrowserProductIdentity.PLAYWRIGHT_CHROMIUM
    if "microsoft/edge" in lowered or executable_name == "msedge.exe":
        return BrowserProductIdentity.MICROSOFT_EDGE
    if "google/chrome/application" in lowered and executable_name == "chrome.exe":
        return BrowserProductIdentity.GOOGLE_CHROME
    if "chromium" in lowered or "--type=" in joined:
        return BrowserProductIdentity.OTHER_CHROMIUM
    return BrowserProductIdentity.AMBIGUOUS


def _safe_executable_hash(path: Path) -> str:
    try:
        return hash_file(path).digest if path.is_file() else ""
    except OSError:
        return ""


def discover_browser_processes(residue_path: Path | None = None) -> list[BrowserProcessGroup]:
    residue_path = residue_path or default_residue_path()
    processes: dict[int, psutil.Process] = {}
    for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
        if str(process.info.get("name", "")).casefold() in {
            "chrome.exe",
            "msedge.exe",
            "chromium.exe",
        }:
            processes[process.pid] = process
    groups: list[BrowserProcessGroup] = []
    for pid, process in sorted(processes.items()):
        parent = int(process.info.get("ppid") or 0)
        if parent in processes:
            continue
        command = [str(item) for item in (process.info.get("cmdline") or [])]
        executable = Path(str(process.info.get("exe") or ""))
        product = classify_browser(executable, command)
        children = sorted(
            child_pid
            for child_pid, child in processes.items()
            if _descends_from(child, pid, processes)
        )
        user_data = _argument(command, "user-data-dir")
        exclusion = ""
        if user_data and _same_path(user_data, residue_path):
            exclusion = "KNOWN_EXTERNAL_RESIDUE"
        elif product is not BrowserProductIdentity.GOOGLE_CHROME:
            exclusion = "NON_NORMAL_CHROME_PRODUCT"
        created = process.info.get("create_time")
        groups.append(
            BrowserProcessGroup(
                root_pid=pid,
                parent_pid=parent,
                executable_path=_canonical(executable),
                executable_sha256=_safe_executable_hash(executable),
                product=product,
                creation_time=datetime.fromtimestamp(float(created), UTC) if created else None,
                redacted_command_line=redact_command(command),
                explicit_user_data_dir=user_data,
                explicit_profile_directory=_argument(command, "profile-directory"),
                owned_child_count=len(children),
                child_pids=children,
                state=EvidenceState.PROVEN
                if product is not BrowserProductIdentity.AMBIGUOUS
                else EvidenceState.UNPROVEN,
                exclusion_reason=exclusion,
            )
        )
    return groups


def _descends_from(
    process: psutil.Process, ancestor: int, processes: dict[int, psutil.Process]
) -> bool:
    seen: set[int] = set()
    parent = int(process.info.get("ppid") or 0)
    while parent in processes and parent not in seen:
        if parent == ancestor:
            return True
        seen.add(parent)
        parent = int(processes[parent].info.get("ppid") or 0)
    return False


def known_residue(
    groups: list[BrowserProcessGroup],
    residue_path: Path | None = None,
    recorded_manifest: str = "UNRECORDED",
) -> KnownExternalResidue:
    residue_path = residue_path or default_residue_path()
    references = sum(
        1
        for group in groups
        if group.explicit_user_data_dir and _same_path(group.explicit_user_data_dir, residue_path)
    )
    return KnownExternalResidue(
        residue_id="phase2c-chrome-for-testing-profile",
        exact_path=str(residue_path),
        canonical_path=_canonical(residue_path),
        recorded_manifest_hash=recorded_manifest,
        ownership_state=ResidueOwnershipState.OWNERSHIP_UNPROVEN,
        policy_state=(
            ResiduePolicyState.BLOCKED_ACTIVE_USE
            if references
            else ResiduePolicyState.PRESERVE_AND_EXCLUDE
        ),
        deletion_authority="NONE",
        inspection_authority="EXISTENCE_AND_PROCESS_REFERENCE_ONLY",
        allowed_operations=["path existence", "process-reference count", "exclude"],
        prohibited_operations=["delete", "cleanup", "profile evidence", "content inspection"],
        process_reference_count=references,
        current_path_state="PRESENT" if residue_path.exists() else "ABSENT",
        last_verified_at=datetime.now(UTC),
        limitations=["Ownership remains unproven; the recorded manifest is not recomputed."],
    )


def discover_browser_profiles(
    groups: list[BrowserProcessGroup],
    local_app_data: Path | None = None,
    residue_path: Path | None = None,
) -> list[BrowserProfileReference]:
    residue_path = residue_path or default_residue_path(local_app_data)
    base = local_app_data or Path(os.environ.get("LOCALAPPDATA", ""))
    default = base / "Google" / "Chrome" / "User Data"
    candidates: dict[str, tuple[Path, str, list[int]]] = {}
    for group in groups:
        if group.product is not BrowserProductIdentity.GOOGLE_CHROME or group.exclusion_reason:
            continue
        if group.explicit_user_data_dir:
            path = Path(group.explicit_user_data_dir)
            if not _same_path(path, residue_path):
                candidates[os.path.normcase(_canonical(path))] = (
                    path,
                    "explicit --user-data-dir",
                    [group.root_pid],
                )
    key = os.path.normcase(_canonical(default))
    if key not in candidates:
        refs = [
            g.root_pid
            for g in groups
            if g.product is BrowserProductIdentity.GOOGLE_CHROME
            and not g.explicit_user_data_dir
            and not g.exclusion_reason
        ]
        candidates[key] = (default, "product-specific default hypothesis", refs)
    result: list[BrowserProfileReference] = []
    for path, method, refs in candidates.values():
        if _same_path(path, residue_path):
            continue
        local_state = path / "Local State"
        profile_names: list[str] = []
        if local_state.is_file():
            try:
                data = json.loads(local_state.read_text(encoding="utf-8"))
                cache = data.get("profile", {}).get("info_cache", {})
                profile_names = sorted(str(value) for value in cache if isinstance(value, str))
                last = data.get("profile", {}).get("last_used")
                if isinstance(last, str) and last not in profile_names:
                    profile_names.append(last)
            except (OSError, json.JSONDecodeError):
                pass
        confidence = (
            "CORROBORATED_RUNNING_AND_LOCAL_STATE"
            if refs and local_state.is_file()
            else "HYPOTHESIS"
        )
        result.append(
            BrowserProfileReference(
                canonical_path=_canonical(path),
                product=BrowserProductIdentity.GOOGLE_CHROME,
                discovery_method=method,
                running_process_references=sorted(set(refs)),
                local_state_exists=local_state.is_file(),
                profile_directory_candidates=profile_names,
                current_profile_confidence=confidence,
                contradictions=[],
                uncertainties=[]
                if confidence.startswith("CORROBORATED")
                else ["Folder existence alone does not prove current use."],
            )
        )
    return result


def select_profile(references: list[BrowserProfileReference]) -> tuple[Path, str, list[str]]:
    proven = [
        item
        for item in references
        if item.current_profile_confidence == "CORROBORATED_RUNNING_AND_LOCAL_STATE"
    ]
    if len(proven) != 1:
        raise RuntimeError("NORMAL_PROFILE_PATH_AMBIGUOUS")
    reference = proven[0]
    local_state = json.loads((Path(reference.canonical_path) / "Local State").read_text("utf-8"))
    profile = local_state.get("profile", {}).get("last_used")
    if not isinstance(profile, str) or profile not in reference.profile_directory_candidates:
        raise RuntimeError("NORMAL_PROFILE_PATH_AMBIGUOUS")
    return (
        Path(reference.canonical_path),
        profile,
        [
            reference.discovery_method,
            "running Google Chrome root process",
            "Local State profile.last_used",
            "Local State profile.info_cache",
        ],
    )


def _copy_verified(source: Path, destination: Path) -> SnapshotFileEvidence:
    lowered = source.name.casefold()
    if lowered in SENSITIVE_NAMES:
        raise PermissionError(f"SENSITIVE_BROWSER_METADATA_PROHIBITED:{source.name}")
    before_stat = source.stat()
    before_hash = hash_file(source).digest
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    after_hash = hash_file(source).digest
    copied_hash = hash_file(destination).digest
    if before_hash != after_hash or before_hash != copied_hash:
        destination.unlink(missing_ok=True)
        raise RuntimeError("PROFILE_METADATA_CHANGED_DURING_COPY")
    return SnapshotFileEvidence(
        original_path=str(source),
        copied_path=str(destination),
        original_size=before_stat.st_size,
        original_sha256=before_hash,
        copied_sha256=copied_hash,
        original_modified_at=datetime.fromtimestamp(before_stat.st_mtime, UTC),
        snapshot_at=datetime.now(UTC),
        equal=True,
    )


def snapshot_profile_metadata(
    guard_root: Path, user_data: Path, profile: str, run_id: str
) -> tuple[Path, list[SnapshotFileEvidence]]:
    snapshot = guard_root / ".work" / "current-profile-snapshots" / run_id
    evidence: list[SnapshotFileEvidence] = []
    for relative in (
        Path("Local State"),
        Path(profile) / "Preferences",
        Path(profile) / "Secure Preferences",
    ):
        source = user_data / relative
        if source.is_file():
            evidence.append(_copy_verified(source, snapshot / relative))
    return snapshot, evidence


def _extension_settings(snapshot: Path, profile: str) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for name in ("Preferences", "Secure Preferences"):
        path = snapshot / profile / name
        if not path.is_file():
            continue
        data = json.loads(path.read_text("utf-8"))
        settings = data.get("extensions", {}).get("settings", {})
        if isinstance(settings, dict):
            for extension_id, value in settings.items():
                if isinstance(value, dict):
                    merged[str(extension_id)] = value
    return merged


def _reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return path.is_symlink() or bool(
            attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        )
    except OSError:
        return False


def _resolve_name(extension: Path, manifest_name: str, locale: str = "en") -> str:
    match = re.fullmatch(r"__MSG_([A-Za-z0-9_]+)__", manifest_name)
    if not match:
        return manifest_name
    for selected in (locale, "en", "en_GB", "en_US"):
        messages = extension / "_locales" / selected / "messages.json"
        if messages.is_file():
            payload = json.loads(messages.read_text("utf-8"))
            value = payload.get(match.group(1), {}).get("message")
            if isinstance(value, str):
                return value
    return manifest_name


def _configured_path(
    user_data: Path, profile: str, extension_id: str, value: dict[str, Any]
) -> Path | None:
    explicit = value.get("path")
    if isinstance(explicit, str) and explicit:
        path = Path(explicit)
        return path if path.is_absolute() else user_data / profile / path
    version = value.get("manifest", {}).get("version")
    root = user_data / profile / "Extensions" / extension_id
    if isinstance(version, str):
        exact = root / version
        if exact.is_dir():
            return exact
    if root.is_dir():
        versions = sorted((item for item in root.iterdir() if item.is_dir()), reverse=True)
        return versions[0] if versions else None
    return None


def inspect_configured_extensions(
    guard_root: Path, user_data: Path, profile: str, snapshot: Path, candidate: Path
) -> list[ConfiguredExtensionIdentity]:
    settings = _extension_settings(snapshot, profile)
    candidate_attestation = BuildAttestation.model_validate_json(
        (candidate / "evidence" / "build-attestation.json").read_text("utf-8")
    )
    candidate_payload = candidate_attestation.artefact_payload_manifest_hash
    candidate_attestation_hash = hash_file(candidate / "evidence" / "build-attestation.json").digest
    results: list[ConfiguredExtensionIdentity] = []
    for extension_id, value in settings.items():
        path = _configured_path(user_data, profile, extension_id, value)
        if path is None or not path.is_dir() or _reparse(path):
            continue
        manifest_path = path / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        resolved_name = _resolve_name(path, str(manifest.get("name", "")))
        marker_names = {item.name.casefold() for item in path.glob("*") if item.is_file()}
        worker = str(manifest.get("background", {}).get("service_worker", ""))
        plausible = (
            "study copilot" in resolved_name.casefold()
            or "itzako" in resolved_name.casefold()
            or "buildinfo.js" in marker_names
            or "build-attestation.json" in marker_names
            or worker.casefold().endswith("background.js")
        )
        if not plausible:
            continue
        logical = _logical_manifest(path, excluded_names=set())
        payload_hash = str(logical["manifest_sha256"])
        attestation_path = next(
            (
                item
                for item in (
                    path / "build-attestation.json",
                    path / "evidence" / "build-attestation.json",
                )
                if item.is_file()
            ),
            None,
        )
        attestation_hash = hash_file(attestation_path).digest if attestation_path else ""
        signing_key = ""
        source_head = ""
        component_hash = ""
        signature_state = EvidenceState.UNPROVEN
        trust_state = EvidenceState.UNPROVEN
        if attestation_path:
            try:
                attestation = BuildAttestation.model_validate_json(
                    attestation_path.read_text("utf-8")
                )
                signing_key = attestation.signing_key_id
                source_head = attestation.source_head
                component_hash = attestation.component_build_input_manifest_hash
                trusted = guard_root / "trust" / "keys" / f"{signing_key}.pub.json"
                if _same_path(path, candidate / "artefact" / "extension"):
                    verification = verify_candidate(candidate, trusted)
                    signature_state = verification.signature_state
                    trust_state = verification.signer_trust_state
            except (OSError, ValueError):
                pass
        matches = (
            payload_hash == candidate_payload or attestation_hash == candidate_attestation_hash
        )
        details = []
        if payload_hash != candidate_payload:
            details.append("payload-manifest hash differs")
        if attestation_hash != candidate_attestation_hash:
            details.append("attestation hash differs")
        if source_head.startswith("950e204"):
            details.append("historical 950e204 source-to-build claim remains CONTRADICTED")
            matches = False
        install_type = "UNPACKED_EXTERNAL_PATH" if value.get("location") == 4 else "PROFILE_MANAGED"
        results.append(
            ConfiguredExtensionIdentity(
                installation=ExtensionInstallRecord(
                    extension_id=extension_id,
                    enabled_state="ENABLED" if value.get("state") == 1 else "DISABLED_OR_UNKNOWN",
                    install_type=install_type,
                    configured_path=_canonical(path),
                    installed_version=str(
                        manifest.get("version", value.get("manifest", {}).get("version", ""))
                    ),
                    manifest_name=str(manifest.get("name", "")),
                    resolved_name=resolved_name,
                    manifest_version=int(manifest.get("manifest_version", 0)),
                    background_service_worker=worker,
                    permissions=sorted(str(item) for item in manifest.get("permissions", [])),
                    update_url_present=bool(manifest.get("update_url")),
                    evidence_source=(
                        "allowlisted Preferences/Secure Preferences and static manifest"
                    ),
                    state=EvidenceState.PROVEN,
                ),
                artifact=ConfiguredExtensionArtifact(
                    canonical_path=_canonical(path),
                    payload_manifest_hash=payload_hash,
                    attestation_sha256=attestation_hash,
                    signing_key_id=signing_key,
                    signature_state=signature_state,
                    signer_trust_state=trust_state,
                    source_head=source_head,
                    component_input_manifest_hash=component_hash,
                    files=list(logical["entries"]),
                    state=EvidenceState.PROVEN,
                ),
                comparison_verdict=(
                    "CURRENT_CONFIGURED_EXTENSION_MATCHES_SEALED_CANDIDATE"
                    if matches
                    else "CURRENT_CONFIGURED_EXTENSION_DIFFERS_FROM_SEALED_CANDIDATE"
                ),
                comparison_details=details,
            )
        )
    return results


def inspect_current_profile(guard_root: Path, candidate: Path) -> CurrentProfileIdentityReport:
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    residue_path, residue_manifest = load_residue_identity(guard_root)
    groups = discover_browser_processes(residue_path)
    residue = known_residue(groups, residue_path, residue_manifest)
    references = discover_browser_profiles(groups, residue_path=residue_path)
    user_data, profile, selection = select_profile(references)
    snapshot, copied = snapshot_profile_metadata(guard_root, user_data, profile, run_id)
    extensions = inspect_configured_extensions(guard_root, user_data, profile, snapshot, candidate)
    if not extensions:
        configured_verdict = "CURRENT_CONFIGURED_EXTENSION_NOT_FOUND"
        first_boundary = "CONFIGURED_EXTENSION_NOT_FOUND"
    elif len(extensions) > 1:
        configured_verdict = "MULTIPLE_CURRENT_EXTENSION_CANDIDATES"
        first_boundary = "MULTIPLE_EXTENSION_CANDIDATES"
    else:
        configured_verdict = extensions[0].comparison_verdict
        first_boundary = (
            "CURRENT_RUNTIME_ATTESTATION_UNAVAILABLE"
            if configured_verdict.endswith("MATCHES_SEALED_CANDIDATE")
            else "CONFIGURED_EXTENSION_PAYLOAD_MISMATCH"
        )
    current = extensions[0] if len(extensions) == 1 else None
    differences = current.comparison_details if current else [configured_verdict]
    promotion = PromotionReadinessPlan(
        current_extension_id=current.installation.extension_id if current else "",
        current_extension_path=current.installation.configured_path if current else "",
        current_payload_hash=current.artifact.payload_manifest_hash if current else "",
        current_attestation_state=current.artifact.signature_state
        if current
        else EvidenceState.UNPROVEN,
        sealed_candidate_id=candidate.name,
        exact_differences=differences,
        normal_profile_process_state="PASSIVE_RUNNING_PROCESS_OBSERVED",
        rollback_requirements=["human-approved backup of allowlisted extension package metadata"],
        extension_id_stability_considerations=[
            "preserve configured extension ID and installation semantics"
        ],
        profile_restart_required="TO_BE_DESIGNED_NOT_EXECUTED",
        developer_mode_involved="TO_BE_DESIGNED_NOT_EXECUTED",
        required_human_approval=True,
        required_pre_promotion_backup=[
            "configured extension path",
            "allowlisted configuration metadata",
        ],
        required_post_promotion_runtime_attestation=True,
        required_rollback_verification=True,
        required_behavioural_golden_journeys=["capture", "explanation", "reload/readback"],
        blockers=[first_boundary],
        verdict=(
            "NOT_REQUIRED_ALREADY_MATCHES"
            if current and current.comparison_verdict.endswith("MATCHES_SEALED_CANDIDATE")
            else "READY_FOR_TRANSACTIONAL_PROMOTION_DESIGN"
            if current
            else "BLOCKED_CURRENT_IDENTITY_AMBIGUOUS"
        ),
    )
    report = CurrentProfileIdentityReport(
        schema_version="1.0",
        run_id=run_id,
        observed_at=datetime.now(UTC),
        residues=[residue],
        process_groups=groups,
        profile_references=references,
        selected_user_data_root=str(user_data),
        selected_profile=profile,
        profile_selection_evidence=selection,
        snapshot_files=copied,
        configured_extensions=extensions,
        configured_extension_verdict=configured_verdict,
        existing_devtools_endpoint_verdict="CURRENT_LIVE_RUNTIME_OBSERVATION_UNAVAILABLE",
        passive_worker_observation="CURRENT_WORKER_UNOBSERVABLE",
        current_runtime_attestation_verdict="CURRENT_LIVE_RUNTIME_ATTESTATION_UNPROVEN",
        current_loaded_client_verdict=(
            "CURRENT_CONFIGURED_EXTENSION_MATCHES_SEALED_CANDIDATE_RUNTIME_UNPROVEN"
            if configured_verdict.endswith("MATCHES_SEALED_CANDIDATE")
            else configured_verdict
        ),
        promotion_readiness=promotion,
        first_failing_boundary=first_boundary,
        safety_counters=dict(SAFETY_COUNTERS),
        limitations=[
            "Configured state does not prove an active service worker.",
            "No DevTools endpoint was enabled or queried.",
            "No extension JavaScript or application storage was read.",
        ],
    )
    output = guard_root / "evidence" / "inspections" / f"current-profile-{run_id}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return report
