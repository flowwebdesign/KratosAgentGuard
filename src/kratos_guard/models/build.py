"""Controlled build and signed-attestation models."""

from datetime import datetime

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.provenance import ManifestEntry
from kratos_guard.models.state import EvidenceState


class ComponentBuildDefinition(StrictModel):
    project: str
    component: str
    source_roots: list[str]
    supporting_input_paths: list[str]
    package_manager: str
    dependency_lockfiles: list[str]
    install_command: list[str]
    build_command: list[str]
    expected_output_paths: list[str]
    permitted_environment_variables: list[str]
    denied_environment_variables: list[str]
    network_policy: str
    lifecycle_script_policy: str
    build_timeout: int
    discovery_evidence: list[str]
    uncertainties: list[str]
    verdict: str


class BuildInputManifest(StrictModel):
    project: str
    component: str
    repository_head: str
    repository_dirty: bool
    repository_staged: bool
    repository_source_manifest_hash: str
    component_source_paths: list[str]
    supporting_input_paths: list[str]
    dependency_lockfile_hashes: dict[str, str]
    build_script_hashes: dict[str, str]
    configuration_hashes: dict[str, str]
    entries: list[ManifestEntry]
    included_files: list[str]
    excluded_files: list[str]
    file_count: int
    total_bytes: int
    manifest_sha256: str
    observed_at: datetime
    mutation_witness_reference: str
    limitations: list[str]
    state: EvidenceState


class BuilderIdentity(StrictModel):
    guard_version: str
    guard_head: str
    python_version: str
    operating_system: str
    node_version: str
    package_manager_version: str


class BuildCommandPolicy(StrictModel):
    command: list[str]
    working_directory_policy: str
    network_mode: str
    lifecycle_script_mode: str
    environment_allowlist: list[str]
    timeout_seconds: int
    expected_output_roots: list[str]
    policy_hash: str
    verdict: str


class BuildExecutionEvidence(StrictModel):
    command: list[str]
    working_directory: str
    started_at: datetime
    finished_at: datetime
    duration_ms: float
    exit_code: int
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    stdout_excerpt: str
    stderr_excerpt: str
    environment_keys: list[str]
    output_paths: list[str]
    unexpected_changes: list[str]


class BuildResult(StrictModel):
    candidate_id: str
    candidate_directory: str
    input_manifest_hash: str
    copied_manifest_hash: str
    payload_manifest_hash: str
    delivery_manifest_hash: str
    payload_file_count: int
    payload_total_bytes: int
    execution: BuildExecutionEvidence
    state: EvidenceState
    limitations: list[str]


class KeyStorageAssessment(StrictModel):
    path: str
    exists: bool
    restrictive_acl: bool
    broadly_writable: bool
    state: str
    details: list[str]


class SigningKeyIdentity(StrictModel):
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    private_key_path: str
    public_key_path: str
    storage: KeyStorageAssessment


class TrustRoot(StrictModel):
    key_id: str
    public_key_fingerprint: str
    trusted_public_key_path: str
    state: str


class SignatureEvidence(StrictModel):
    algorithm: str
    key_id: str
    payload_sha256: str
    signature: str
    signature_state: str
    signer_trust_state: str


class BuildAttestation(StrictModel):
    schema_version: str
    project: str
    component: str
    candidate_id: str
    source_repository: str
    source_head: str
    source_dirty: bool
    source_staged: bool
    repository_source_manifest_hash: str
    component_build_input_manifest_hash: str
    dependency_lockfile_hashes: dict[str, str]
    build_script_hashes: dict[str, str]
    configuration_hashes: dict[str, str]
    builder: BuilderIdentity
    guard_head: str
    guard_version: str
    build_command: list[str]
    build_started_at: datetime
    build_finished_at: datetime
    build_exit_code: int
    build_environment_policy_hash: str
    artefact_payload_manifest_hash: str
    artefact_file_count: int
    artefact_total_bytes: int
    build_reproducibility_state: str
    signing_key_id: str
    signature_algorithm: str
    signature: str = ""
    attestation_created_at: datetime
    limitations: list[str]
    evidence_references: list[str]
    integrity_sha256: str = ""


class AttestationVerification(StrictModel):
    schema_state: EvidenceState
    integrity_state: EvidenceState
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    source_claim_state: EvidenceState
    build_input_state: EvidenceState
    artefact_claim_state: EvidenceState
    overall_provenance_state: EvidenceState
    first_failing_boundary: str
    details: list[str]


class ReproducibilityResult(StrictModel):
    state: str
    first_payload_hash: str
    second_payload_hash: str
    differing_paths: list[str]
    first_nondeterministic_boundary: str
