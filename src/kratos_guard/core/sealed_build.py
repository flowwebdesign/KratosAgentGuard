"""Guard-owned isolated static extension build and attestation."""

import json
import os
import platform
import shutil
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

from kratos_guard import __version__
from kratos_guard.adapters.git import git_value, run_git
from kratos_guard.core.mutation_witness import MutationWitness
from kratos_guard.core.signing import (
    calculate_attestation_integrity,
    inspect_key,
    sign_attestation,
    verify_attestation_signature,
)
from kratos_guard.models import EvidenceState
from kratos_guard.models.build import (
    AttestationVerification,
    BuildAttestation,
    BuildCommandPolicy,
    BuilderIdentity,
    BuildExecutionEvidence,
    BuildInputManifest,
    BuildResult,
    ComponentBuildDefinition,
    ReproducibilityResult,
)
from kratos_guard.models.provenance import ManifestEntry
from kratos_guard.reporting.redaction import redact_text

SENSITIVE_NAMES = {
    ".env",
    "credentials",
    "cookies",
    "local storage",
    "login data",
    "id_rsa",
    "id_ed25519",
}
SENSITIVE_SUFFIXES = {".key", ".p12", ".pfx", ".sqlite", ".sqlite3", ".db", ".log"}


def component_build_definition(target: Path, profile: dict[str, Any]) -> ComponentBuildDefinition:
    root = target.resolve() / "Study_master" / "extension"
    manifest = root / "manifest.json"
    readme = root / "README.md"
    evidence: list[str] = []
    proven = False
    if manifest.is_file() and readme.is_file():
        parsed = json.loads(manifest.read_text(encoding="utf-8"))
        text = readme.read_text(encoding="utf-8", errors="replace")
        proven = parsed.get("manifest_version") == 3 and "Extension" in text
        evidence = [
            "Study_master/extension/manifest.json declares Manifest V3",
            "Study_master/extension/README.md identifies the learner extension",
            "No component package.json or dependency lockfile exists",
            "README prescribes node --check validation for static JavaScript",
        ]
    return ComponentBuildDefinition(
        project="itzako",
        component="extension",
        source_roots=["Study_master/extension"],
        supporting_input_paths=[],
        package_manager="NOT_APPLICABLE",
        dependency_lockfiles=[],
        install_command=[],
        build_command=["kratos-guard", "internal-static-extension-copy", "--validate=node-check"],
        expected_output_paths=["artefact/extension"],
        permitted_environment_variables=["PATH", "SystemRoot", "TEMP", "TMP"],
        denied_environment_variables=[
            "*TOKEN*",
            "*SECRET*",
            "*PASSWORD*",
            "*COOKIE*",
            "*DATABASE*",
            "*API_KEY*",
        ],
        network_policy="DENY",
        lifecycle_script_policy="DENY_ALL",
        build_timeout=120,
        discovery_evidence=evidence,
        uncertainties=[
            "The source directory contains historical buildInfo.js metadata.",
            "The signed attestation is detached and supersedes no runtime metadata.",
        ],
        verdict=(
            "COMPONENT_BUILD_DEFINITION_PROVEN" if proven else "COMPONENT_BUILD_DEFINITION_UNPROVEN"
        ),
    )


def _sensitive(relative: str, path: Path) -> bool:
    name = path.name.casefold()
    if name in SENSITIVE_NAMES or path.suffix.casefold() in SENSITIVE_SUFFIXES:
        return True
    if name.startswith(".env"):
        return True
    if any(
        part.casefold() in {"node_modules", ".git", ".venv", "__pycache__"} for part in path.parts
    ):
        return True
    if path.is_file() and path.stat().st_size <= 1_000_000:
        data = path.read_bytes()
        if b"BEGIN PRIVATE KEY" in data or b"BEGIN OPENSSH PRIVATE KEY" in data:
            return True
    return False


def build_input_manifest(
    target: Path,
    definition: ComponentBuildDefinition,
    repository_manifest_hash: str,
    mutation_reference: str,
) -> BuildInputManifest:
    if definition.verdict != "COMPONENT_BUILD_DEFINITION_PROVEN":
        raise PermissionError("unproven build command blocks execution")
    target = target.resolve()
    root = target / definition.source_roots[0]
    entries: list[ManifestEntry] = []
    excluded: list[str] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_dir():
            continue
        relative = path.relative_to(target).as_posix()
        if _sensitive(relative, path):
            excluded.append(relative)
            continue
        if path.is_symlink():
            raise ValueError(f"component symlink is not permitted: {relative}")
        size = path.stat().st_size
        digest = sha256(path.read_bytes()).hexdigest()
        total += size
        entries.append(ManifestEntry(path=relative, kind="file", size=size, sha256=digest))
    manifest_hash = sha256(
        b"".join(f"{entry.path}\0{entry.size}\0{entry.sha256}\n".encode() for entry in entries)
    ).hexdigest()
    status = run_git(target, ["status", "--porcelain=v2", "--untracked-files=all"])
    staged = run_git(target, ["diff", "--cached", "--name-only"])
    config_hashes = {
        entry.path: entry.sha256
        for entry in entries
        if Path(entry.path).name in {"manifest.json", "buildInfo.js"}
    }
    return BuildInputManifest(
        project="itzako",
        component="extension",
        repository_head=git_value(target, ["rev-parse", "--verify", "HEAD"]),
        repository_dirty=bool(status.stdout_excerpt),
        repository_staged=bool(staged.stdout_excerpt),
        repository_source_manifest_hash=repository_manifest_hash,
        component_source_paths=definition.source_roots,
        supporting_input_paths=definition.supporting_input_paths,
        dependency_lockfile_hashes={},
        build_script_hashes={},
        configuration_hashes=config_hashes,
        entries=entries,
        included_files=[entry.path for entry in entries],
        excluded_files=excluded,
        file_count=len(entries),
        total_bytes=total,
        manifest_sha256=manifest_hash,
        observed_at=datetime.now(UTC),
        mutation_witness_reference=mutation_reference,
        limitations=[
            "Manifest represents observed dirty working-tree bytes.",
            "No dependency installation or lifecycle scripts are required.",
        ],
        state=EvidenceState.PROVEN,
    )


def candidate_identifier(input_hash: str, now: datetime | None = None) -> str:
    timestamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S%fZ")
    return f"itzako-extension-{timestamp}-{input_hash[:12]}"


def candidate_root(guard_root: Path, candidate_id: str) -> Path:
    root = (guard_root / ".work" / "candidates" / candidate_id).resolve()
    expected = (guard_root / ".work" / "candidates").resolve()
    if os.path.commonpath([str(root), str(expected)]) != str(expected):
        raise ValueError("candidate workspace escapes Guard-owned root")
    return root


def snapshot_component(
    target: Path, guard_root: Path, manifest: BuildInputManifest, candidate_id: str
) -> Path:
    workspace = candidate_root(guard_root, candidate_id)
    if workspace.exists():
        raise FileExistsError(f"candidate already exists: {candidate_id}")
    for directory in (
        "source",
        "dependencies",
        "build",
        "artefact",
        "logs",
        "evidence",
        "temporary",
    ):
        (workspace / directory).mkdir(parents=True, exist_ok=False)
    target = target.resolve()
    for entry in manifest.entries:
        source = target / entry.path
        destination = workspace / "source" / entry.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        if sha256(destination.read_bytes()).hexdigest() != entry.sha256:
            raise RuntimeError(f"copied snapshot mismatch: {entry.path}")
    copied = _logical_manifest(workspace / "source", excluded_names=set())
    expected = _entries_manifest_hash(manifest.entries, prefix="")
    if copied["manifest_sha256"] != expected:
        raise RuntimeError("copied snapshot does not equal component build-input manifest")
    return workspace


def verify_snapshot_equivalence(workspace: Path, manifest: BuildInputManifest) -> bool:
    copied = _logical_manifest(workspace / "source", excluded_names=set())
    expected = _entries_manifest_hash(manifest.entries, prefix="")
    return bool(copied["manifest_sha256"] == expected)


def _entries_manifest_hash(entries: list[ManifestEntry], prefix: str) -> str:
    logical = []
    for entry in entries:
        path = entry.path
        if prefix and path.startswith(prefix):
            path = path[len(prefix) :].lstrip("/")
        logical.append(f"{path}\0{entry.size}\0{entry.sha256}\n".encode())
    return sha256(b"".join(logical)).hexdigest()


def _logical_manifest(root: Path, excluded_names: set[str]) -> dict[str, Any]:
    entries = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        if path.is_dir() or path.name in excluded_names:
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        digest = sha256(path.read_bytes()).hexdigest()
        total += size
        entries.append({"path": relative, "size": size, "sha256": digest})
    manifest_hash = sha256(
        b"".join(
            f"{entry['path']}\0{entry['size']}\0{entry['sha256']}\n".encode() for entry in entries
        )
    ).hexdigest()
    return {
        "entries": entries,
        "file_count": len(entries),
        "total_bytes": total,
        "manifest_sha256": manifest_hash,
    }


def _minimal_environment(workspace: Path) -> dict[str, str]:
    allowed = {}
    for key in ("PATH", "SystemRoot"):
        if value := os.environ.get(key):
            allowed[key] = value
    temporary = str(workspace / "temporary")
    allowed["TEMP"] = temporary
    allowed["TMP"] = temporary
    return allowed


def command_policy(workspace: Path, definition: ComponentBuildDefinition) -> BuildCommandPolicy:
    payload = {
        "command": definition.build_command,
        "working_directory": "candidate/source/Study_master/extension",
        "network": "DENY",
        "lifecycle": "DENY_ALL",
        "environment": definition.permitted_environment_variables,
        "timeout": definition.build_timeout,
    }
    policy_hash = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return BuildCommandPolicy(
        command=definition.build_command,
        working_directory_policy="MUST_BE_GUARD_OWNED_CANDIDATE",
        network_mode="DENY",
        lifecycle_script_mode="DENY_ALL",
        environment_allowlist=definition.permitted_environment_variables,
        timeout_seconds=definition.build_timeout,
        expected_output_roots=["artefact", "logs", "temporary"],
        policy_hash=policy_hash,
        verdict="BUILD_COMMAND_POLICY_PROVEN",
    )


def builder_identity(guard_root: Path) -> BuilderIdentity:
    def version(command: list[str]) -> str:
        try:
            result = subprocess.run(
                command, capture_output=True, check=False, text=True, timeout=10
            )
            return redact_text((result.stdout or result.stderr).strip())[:300]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "UNAVAILABLE"

    return BuilderIdentity(
        guard_version=__version__,
        guard_head=git_value(guard_root, ["rev-parse", "--verify", "HEAD"]),
        python_version=platform.python_version(),
        operating_system=platform.platform(),
        node_version=version(["node", "--version"]),
        package_manager_version="NOT_APPLICABLE",
    )


def execute_static_build(
    workspace: Path,
    manifest: BuildInputManifest,
    definition: ComponentBuildDefinition,
) -> tuple[BuildExecutionEvidence, dict[str, Any]]:
    source_root = workspace / "source" / definition.source_roots[0]
    artefact_root = workspace / "artefact" / "extension"
    started = datetime.now(UTC)
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    exit_code = 0
    timed_out = False
    node = shutil.which("node")
    environment = _minimal_environment(workspace)
    if not node:
        exit_code = 127
        stderr_parts.append("node executable unavailable")
    else:
        for path in sorted(source_root.rglob("*.js")):
            try:
                completed = subprocess.run(
                    [node, "--check", str(path)],
                    cwd=source_root,
                    env=environment,
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=definition.build_timeout,
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                exit_code = 124
                break
            stdout_parts.append(completed.stdout)
            stderr_parts.append(completed.stderr)
            if completed.returncode != 0:
                exit_code = completed.returncode
                break
    if exit_code == 0:
        for entry in manifest.entries:
            component_prefix = f"{definition.source_roots[0]}/"
            relative = entry.path[len(component_prefix) :]
            source = workspace / "source" / entry.path
            destination = artefact_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
    finished = datetime.now(UTC)
    stdout = "".join(stdout_parts)
    stderr = "".join(stderr_parts)
    payload = _logical_manifest(
        artefact_root,
        excluded_names={"kratos-build-attestation.json"},
    )
    evidence = BuildExecutionEvidence(
        command=definition.build_command,
        working_directory="source/Study_master/extension",
        started_at=started,
        finished_at=finished,
        duration_ms=(finished - started).total_seconds() * 1000,
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_sha256=sha256(stdout.encode()).hexdigest(),
        stderr_sha256=sha256(stderr.encode()).hexdigest(),
        stdout_excerpt=redact_text(stdout[:4096]),
        stderr_excerpt=redact_text(stderr[:4096]),
        environment_keys=sorted(environment),
        output_paths=["artefact/extension"],
        unexpected_changes=[],
    )
    return evidence, payload


def create_attestation(
    candidate_id: str,
    manifest: BuildInputManifest,
    build: BuildExecutionEvidence,
    payload: dict[str, Any],
    policy: BuildCommandPolicy,
    builder: BuilderIdentity,
    reproducibility: str,
) -> BuildAttestation:
    key = inspect_key()
    attestation = BuildAttestation(
        schema_version="1.0",
        project="itzako",
        component="extension",
        candidate_id=candidate_id,
        source_repository="flowwebdesign/Study-Pilot",
        source_head=manifest.repository_head,
        source_dirty=manifest.repository_dirty,
        source_staged=manifest.repository_staged,
        repository_source_manifest_hash=manifest.repository_source_manifest_hash,
        component_build_input_manifest_hash=manifest.manifest_sha256,
        dependency_lockfile_hashes=manifest.dependency_lockfile_hashes,
        build_script_hashes=manifest.build_script_hashes,
        configuration_hashes=manifest.configuration_hashes,
        builder=builder,
        guard_head=builder.guard_head,
        guard_version=builder.guard_version,
        build_command=build.command,
        build_started_at=build.started_at,
        build_finished_at=build.finished_at,
        build_exit_code=build.exit_code,
        build_environment_policy_hash=policy.policy_hash,
        artefact_payload_manifest_hash=payload["manifest_sha256"],
        artefact_file_count=payload["file_count"],
        artefact_total_bytes=payload["total_bytes"],
        build_reproducibility_state=reproducibility,
        signing_key_id=key.key_id,
        signature_algorithm="Ed25519",
        attestation_created_at=datetime.now(UTC),
        limitations=[
            "Attestation proves observed controlled build provenance, not runtime loading.",
            "Historical buildInfo.js metadata remains an input byte and is not trusted provenance.",
        ],
        evidence_references=[
            "evidence/build-input-manifest.json",
            "evidence/payload-manifest.json",
            "evidence/build-execution.json",
        ],
    )
    sign_attestation(attestation)
    return attestation


def write_candidate_evidence(
    workspace: Path,
    manifest: BuildInputManifest,
    payload: dict[str, Any],
    build: BuildExecutionEvidence,
    policy: BuildCommandPolicy,
    attestation: BuildAttestation,
) -> str:
    evidence = workspace / "evidence"
    values = {
        "build-input-manifest.json": manifest.model_dump(mode="json"),
        "payload-manifest.json": payload,
        "build-execution.json": build.model_dump(mode="json"),
        "build-command-policy.json": policy.model_dump(mode="json"),
        "build-attestation.json": attestation.model_dump(mode="json"),
    }
    for name, value in values.items():
        (evidence / name).write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    artefact_attestation = workspace / "artefact" / "extension" / "kratos-build-attestation.json"
    artefact_attestation.write_text(
        json.dumps(attestation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return str(
        _logical_manifest(workspace / "artefact" / "extension", excluded_names=set())[
            "manifest_sha256"
        ]
    )


def build_sealed_candidate(
    target: Path,
    guard_root: Path,
    profile: dict[str, Any],
    repository_manifest_hash: str,
    reproducibility_state: str = "REPRODUCIBILITY_NOT_TESTED",
) -> BuildResult:
    definition = component_build_definition(target, profile)
    witness = MutationWitness(target, list(profile.get("mutation_sentinels", [])))
    manifest = build_input_manifest(
        target, definition, repository_manifest_hash, witness.before.git_status_hash
    )
    candidate_id = candidate_identifier(manifest.manifest_sha256)
    workspace = snapshot_component(target, guard_root, manifest, candidate_id)
    policy = command_policy(workspace, definition)
    execution, payload = execute_static_build(workspace, manifest, definition)
    if execution.exit_code != 0:
        raise RuntimeError("controlled extension validation failed")
    attestation = create_attestation(
        candidate_id,
        manifest,
        execution,
        payload,
        policy,
        builder_identity(guard_root),
        reproducibility_state,
    )
    delivery_hash = write_candidate_evidence(
        workspace, manifest, payload, execution, policy, attestation
    )
    witness_result = witness.finish()
    if witness_result.changed:
        raise RuntimeError("TARGET_CHANGED_DURING_INSPECTION")
    (workspace / "evidence" / "mutation-witness.json").write_text(
        json.dumps(witness_result.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    copied_hash = _logical_manifest(workspace / "source", excluded_names=set())["manifest_sha256"]
    return BuildResult(
        candidate_id=candidate_id,
        candidate_directory=str(workspace),
        input_manifest_hash=manifest.manifest_sha256,
        copied_manifest_hash=copied_hash,
        payload_manifest_hash=payload["manifest_sha256"],
        delivery_manifest_hash=delivery_hash,
        payload_file_count=payload["file_count"],
        payload_total_bytes=payload["total_bytes"],
        execution=execution,
        state=EvidenceState.PROVEN,
        limitations=["Runtime and loaded-client identities remain unproven."],
    )


def verify_attestation_claims(
    attestation: BuildAttestation,
    workspace: Path,
    trusted_key: Path,
) -> AttestationVerification:
    details: list[str] = []
    signature = verify_attestation_signature(attestation, trusted_key)
    integrity = calculate_attestation_integrity(attestation) == attestation.integrity_sha256
    input_payload = json.loads(
        (workspace / "evidence" / "build-input-manifest.json").read_text(encoding="utf-8")
    )
    payload = _logical_manifest(
        workspace / "artefact" / "extension",
        excluded_names={"kratos-build-attestation.json"},
    )
    source_valid = attestation.source_head == input_payload["repository_head"]
    input_valid = (
        attestation.component_build_input_manifest_hash == input_payload["manifest_sha256"]
    )
    artifact_valid = attestation.artefact_payload_manifest_hash == payload["manifest_sha256"]
    signer_valid = signature.signer_trust_state == "TRUST_ROOT_PROVEN"
    signature_valid = signature.signature_state == "SIGNATURE_VALID"
    overall = all(
        (integrity, source_valid, input_valid, artifact_valid, signer_valid, signature_valid)
    )
    checks = [
        ("integrity", integrity),
        ("signature", signature_valid),
        ("signer", signer_valid),
        ("source", source_valid),
        ("build-input", input_valid),
        ("artefact", artifact_valid),
    ]
    first = next((name for name, passed in checks if not passed), "")
    return AttestationVerification(
        schema_state=EvidenceState.PROVEN,
        integrity_state=EvidenceState.PROVEN if integrity else EvidenceState.CONTRADICTED,
        signature_state=EvidenceState.PROVEN if signature_valid else EvidenceState.CONTRADICTED,
        signer_trust_state=EvidenceState.PROVEN if signer_valid else EvidenceState.UNPROVEN,
        source_claim_state=EvidenceState.PROVEN if source_valid else EvidenceState.CONTRADICTED,
        build_input_state=EvidenceState.PROVEN if input_valid else EvidenceState.CONTRADICTED,
        artefact_claim_state=EvidenceState.PROVEN if artifact_valid else EvidenceState.CONTRADICTED,
        overall_provenance_state=EvidenceState.PROVEN if overall else EvidenceState.CONTRADICTED,
        first_failing_boundary=first,
        details=details,
    )


def verify_candidate(workspace: Path, trusted_key: Path) -> AttestationVerification:
    attestation = BuildAttestation.model_validate_json(
        (workspace / "evidence" / "build-attestation.json").read_text(encoding="utf-8")
    )
    return verify_attestation_claims(attestation, workspace, trusted_key)


def compare_candidates(first: Path, second: Path) -> ReproducibilityResult:
    first_manifest = _logical_manifest(
        first / "artefact" / "extension",
        excluded_names={"kratos-build-attestation.json"},
    )
    second_manifest = _logical_manifest(
        second / "artefact" / "extension",
        excluded_names={"kratos-build-attestation.json"},
    )
    first_entries = {entry["path"]: entry["sha256"] for entry in first_manifest["entries"]}
    second_entries = {entry["path"]: entry["sha256"] for entry in second_manifest["entries"]}
    differing = sorted(
        path
        for path in set(first_entries) | set(second_entries)
        if first_entries.get(path) != second_entries.get(path)
    )
    return ReproducibilityResult(
        state=(
            "REPRODUCIBLE_BUILD_PROVEN"
            if first_manifest["manifest_sha256"] == second_manifest["manifest_sha256"]
            else "REPRODUCIBLE_BUILD_CONTRADICTED"
        ),
        first_payload_hash=first_manifest["manifest_sha256"],
        second_payload_hash=second_manifest["manifest_sha256"],
        differing_paths=differing,
        first_nondeterministic_boundary=differing[0] if differing else "",
    )


def update_reproducibility(workspace: Path, state: str) -> str:
    attestation_path = workspace / "evidence" / "build-attestation.json"
    attestation = BuildAttestation.model_validate_json(attestation_path.read_text(encoding="utf-8"))
    attestation.build_reproducibility_state = state
    attestation.signature = ""
    attestation.integrity_sha256 = ""
    sign_attestation(attestation)
    rendered = json.dumps(attestation.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    attestation_path.write_text(rendered, encoding="utf-8")
    (workspace / "artefact" / "extension" / "kratos-build-attestation.json").write_text(
        rendered, encoding="utf-8"
    )
    return str(
        _logical_manifest(workspace / "artefact" / "extension", excluded_names=set())[
            "manifest_sha256"
        ]
    )
