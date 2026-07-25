"""Phase 2F source reconciliation and compatibility-successor evidence."""

from datetime import datetime

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.state import EvidenceState


class SourceFileClassification(StrictModel):
    path: str
    classification: str
    sha256: str
    size: int
    execution_critical: bool
    evidence_references: list[str]
    uncertainty: str


class GeneratedFileClaim(StrictModel):
    output_path: str
    claimed_source_paths: list[str]
    generator: str
    generator_configuration: list[str]
    dependency_inputs: list[str]
    deterministic_reproduction_state: EvidenceState
    evidence_references: list[str]
    uncertainty: str


class ReconciliationBlocker(StrictModel):
    blocker_id: str
    path: str
    reason: str
    state: EvidenceState


class SourceArtifactMapping(StrictModel):
    configured_extension_path: str
    payload_manifest_hash: str
    files: list[SourceFileClassification]
    generated_claims: list[GeneratedFileClaim]
    blockers: list[ReconciliationBlocker]
    execution_critical_unknown_count: int
    verdict: str
    limitations: list[str]


class ReconciliationPlan(StrictModel):
    selected_base: str
    overlay_source: str
    permitted_paths: list[str]
    prohibited_paths: list[str]
    build_procedure: list[str]
    stop_conditions: list[str]
    verdict: str


class ReconciliationBaseCandidate(StrictModel):
    commit: str
    ancestry_relationship: str
    extension_tree_hash: str
    exact_file_count: int
    file_overlap_count: int
    changed_paths: list[str]
    missing_paths: list[str]
    extra_paths: list[str]
    manifest_compatibility: str
    public_key_compatibility: str
    worker_compatibility: str
    score_rationale: list[str]
    contradictions: list[str]


class ReconciliationBaseSelection(StrictModel):
    selected_commit: str
    candidates: list[ReconciliationBaseCandidate]
    rationale: list[str]
    verdict: str


class IsolatedCloneIdentity(StrictModel):
    workspace: str
    repository_root: str
    git_directory: str
    git_common_directory: str
    target_git_common_directory: str
    object_database_independent: bool
    hardlinked_objects_found: int
    linked_worktree: bool
    fetch_remote: str
    push_remote: str
    clean_at_base: bool
    verdict: str


class ReconciliationLineage(StrictModel):
    branch: str
    commit: str
    parent: str
    tree_hash: str
    clean: bool
    reproduced_payload_hash: str
    extension_id: str
    bundle_path: str
    bundle_sha256: str
    bundle_tip: str
    bundle_prerequisites: list[str]
    bundle_verification: str
    build_input_manifest_path: str
    reconciliation_patch_manifest_path: str
    lineage_attestation_path: str
    lineage_attestation_sha256: str
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    verdict: str


class CompatibilitySuccessorDelta(StrictModel):
    branch: str
    commit: str
    parent: str
    permitted_changed_paths: list[str]
    actual_changed_paths: list[str]
    unexpected_changed_paths: list[str]
    manifest_key_equal: bool
    worker_equal: bool
    permissions_equal: bool
    host_permissions_equal: bool
    content_scripts_equal: bool
    product_behaviour_files_equal: bool
    verdict: str


class SuccessorCandidateIdentity(StrictModel):
    candidate_id: str
    candidate_directory: str
    version: str
    payload_hash: str
    delivery_hash: str
    attestation_sha256: str
    signing_key_id: str
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    reproducibility_state: str
    source_head: str
    source_manifest_hash: str
    component_input_hash: str


class StaticCompatibilityReport(StrictModel):
    baseline_id: str
    candidate_id: str
    permitted_delta: list[str]
    actual_delta: list[str]
    unexpected_delta: list[str]
    invariant_results: dict[str, bool]
    verdict: str


class Phase2FReport(StrictModel):
    schema_version: str
    run_id: str
    observed_at: datetime
    mapping: SourceArtifactMapping
    base_selection: ReconciliationBaseSelection
    plan: ReconciliationPlan
    clone: IsolatedCloneIdentity
    reconciliation: ReconciliationLineage
    successor_delta: CompatibilitySuccessorDelta
    successor_candidate: SuccessorCandidateIdentity
    successor_canary: dict[str, object]
    static_compatibility: StaticCompatibilityReport
    final_verdict: str
    promotion_authority: str
    first_remaining_blocker: str
    safety_counters: dict[str, int]
    limitations: list[str]
