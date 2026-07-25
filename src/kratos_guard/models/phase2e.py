"""Phase 2E operational-baseline and promotion-design evidence models."""

from datetime import datetime

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.state import EvidenceState


class ConfiguredExtensionSourceAuthority(StrictModel):
    extension_path: str
    repository_root: str
    git_common_directory: str
    branch: str
    head: str
    detached: bool
    dirty: bool
    staged: bool
    conflicted: bool
    untracked: bool
    upstream: str
    remote: str
    worktree_identity: str
    tree_classification: str
    chrome_relationship: str
    reproducibility_state: EvidenceState
    active_writer_state: str
    applicable_agents_files: list[str]
    limitations: list[str]
    verdict: str


class OperationalBaselineIdentity(StrictModel):
    baseline_id: str
    extension_id: str
    version: str
    manifest_version: int
    worker: str
    permissions: list[str]
    configured_path: str
    payload_manifest_hash: str
    git_source_authority: str
    attestation_state: EvidenceState
    runtime_state: EvidenceState
    behavioural_state: EvidenceState
    limitations: list[str]


class ExtensionIdStabilityEvidence(StrictModel):
    run_id: str
    copy_a_path: str
    copy_b_path: str
    copy_a_payload_hash: str
    copy_b_payload_hash: str
    copy_a_extension_id: str
    copy_b_extension_id: str
    normal_profile_extension_id: str
    manifest_public_key_present: bool
    manifest_public_key_sha256: str
    worker_a: str
    worker_b: str
    network_attempt_count: int
    provider_call_count: int
    profile_cleanup_state: str
    verdict: str
    blockers: list[str]
    limitations: list[str]


class OperationalBaselineAttestation(StrictModel):
    baseline_id: str
    extension_id: str
    extension_version: str
    worker: str
    original_payload_hash: str
    delivery_hash: str
    attestation_sha256: str
    signing_key_id: str
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    configured_source_path: str
    configured_source_head: str
    behavioural_state: EvidenceState
    limitations: list[str]


class RollbackPackage(StrictModel):
    baseline_id: str
    archive_path: str
    archive_sha256: str
    payload_manifest_hash: str
    file_count: int
    restore_target: str
    state: EvidenceState


class RollbackVerificationResult(StrictModel):
    baseline_id: str
    archive_sha256: str
    restored_payload_manifest_hash: str
    expected_payload_manifest_hash: str
    extra_paths: list[str]
    missing_paths: list[str]
    state: EvidenceState


class SuccessorCandidateContract(StrictModel):
    source_recommendation: str
    requirements: list[str]
    prohibited_shortcuts: list[str]
    human_approval_required: bool
    verdict: str


class ExtensionPromotionTransaction(StrictModel):
    configured_extension_path: str
    same_path_replacement_required: bool
    backup_path_policy: str
    staging_path_policy: str
    atomic_rename_strategy: str
    filesystem_volume_requirement: str
    browser_shutdown_proof: str
    process_ownership_rules: list[str]
    profile_lock_checks: list[str]
    metadata_preconditions: list[str]
    extension_id_preservation: str
    post_write_hash_checks: list[str]
    startup_responsibility: str
    runtime_attestation_endpoint: str
    rollback_thresholds: list[str]
    timeout_rules: list[str]
    evidence_ledger: str
    required_human_approvals: list[str]
    state_machine: list[str]
    failure_path: list[str]
    preconditions: list[str]
    rollback_package_required: bool
    same_volume_atomic_staging_required: bool
    chrome_closed_proof_required: bool
    runtime_attestation_required: bool
    human_approval_required: bool
    golden_journeys_required: bool
    execution_method_present: bool
    blockers: list[str]
    verdict: str


class GoldenJourneyContract(StrictModel):
    journey_id: str
    initial_state: str
    browser_state: str
    lesson_source_identity: str
    action: str
    expected_network_request_count: str
    expected_provider_call_count: str
    expected_operation_state: str
    expected_database_writes: str
    expected_canonical_lesson_identity: str
    expected_explanation_revision: str
    expected_visible_output: str
    reload_readback_expectation: str
    rollback_impact: str
    failure_boundary: str


class Phase2EReport(StrictModel):
    schema_version: str
    run_id: str
    observed_at: datetime
    source_authority: ConfiguredExtensionSourceAuthority
    baseline: OperationalBaselineIdentity
    baseline_attestation: OperationalBaselineAttestation
    rollback_package: RollbackPackage
    rollback_verification: RollbackVerificationResult
    id_stability: ExtensionIdStabilityEvidence | None
    isolated_canary: dict[str, object]
    reference_candidate_classification: dict[str, object]
    successor_contract: SuccessorCandidateContract
    promotion_transaction: ExtensionPromotionTransaction
    golden_journeys: list[GoldenJourneyContract]
    first_remaining_blocker: str
    safety_counters: dict[str, int]
    limitations: list[str]
