"""Privacy-bounded evidence models for a currently configured browser extension."""

from datetime import datetime
from enum import StrEnum

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.state import EvidenceState


class ResidueOwnershipState(StrEnum):
    OWNERSHIP_PROVEN = "OWNERSHIP_PROVEN"
    OWNERSHIP_UNPROVEN = "OWNERSHIP_UNPROVEN"
    OWNERSHIP_CONTRADICTED = "OWNERSHIP_CONTRADICTED"


class ResiduePolicyState(StrEnum):
    PRESERVE_AND_EXCLUDE = "PRESERVE_AND_EXCLUDE"
    AUTHORISED_FOR_CLEANUP = "AUTHORISED_FOR_CLEANUP"
    BLOCKED_ACTIVE_USE = "BLOCKED_ACTIVE_USE"


class BrowserProductIdentity(StrEnum):
    GOOGLE_CHROME = "GOOGLE_CHROME"
    CHROME_FOR_TESTING = "CHROME_FOR_TESTING"
    PLAYWRIGHT_CHROMIUM = "PLAYWRIGHT_CHROMIUM"
    MICROSOFT_EDGE = "MICROSOFT_EDGE"
    OTHER_CHROMIUM = "OTHER_CHROMIUM"
    AMBIGUOUS = "AMBIGUOUS"


class KnownExternalResidue(StrictModel):
    residue_id: str
    exact_path: str
    canonical_path: str
    recorded_manifest_hash: str
    ownership_state: ResidueOwnershipState
    policy_state: ResiduePolicyState
    deletion_authority: str
    inspection_authority: str
    allowed_operations: list[str]
    prohibited_operations: list[str]
    process_reference_count: int
    current_path_state: str
    last_verified_at: datetime
    limitations: list[str]


class BrowserProfileReference(StrictModel):
    canonical_path: str
    product: BrowserProductIdentity
    discovery_method: str
    running_process_references: list[int]
    local_state_exists: bool
    profile_directory_candidates: list[str]
    current_profile_confidence: str
    contradictions: list[str]
    uncertainties: list[str]


class BrowserProcessGroup(StrictModel):
    root_pid: int
    parent_pid: int
    executable_path: str
    executable_sha256: str
    product: BrowserProductIdentity
    creation_time: datetime | None
    redacted_command_line: list[str]
    explicit_user_data_dir: str
    explicit_profile_directory: str
    owned_child_count: int
    child_pids: list[int]
    state: EvidenceState
    exclusion_reason: str = ""


class SnapshotFileEvidence(StrictModel):
    original_path: str
    copied_path: str
    original_size: int
    original_sha256: str
    copied_sha256: str
    original_modified_at: datetime
    snapshot_at: datetime
    equal: bool


class ExtensionInstallRecord(StrictModel):
    extension_id: str
    enabled_state: str
    install_type: str
    configured_path: str
    installed_version: str
    manifest_name: str
    resolved_name: str
    manifest_version: int
    background_service_worker: str
    permissions: list[str]
    update_url_present: bool
    evidence_source: str
    state: EvidenceState


class ConfiguredExtensionArtifact(StrictModel):
    canonical_path: str
    payload_manifest_hash: str
    attestation_sha256: str
    signing_key_id: str
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    source_head: str
    component_input_manifest_hash: str
    files: list[dict[str, object]]
    state: EvidenceState


class ConfiguredExtensionIdentity(StrictModel):
    installation: ExtensionInstallRecord
    artifact: ConfiguredExtensionArtifact
    comparison_verdict: str
    comparison_details: list[str]


class PromotionReadinessPlan(StrictModel):
    current_extension_id: str
    current_extension_path: str
    current_payload_hash: str
    current_attestation_state: EvidenceState
    sealed_candidate_id: str
    exact_differences: list[str]
    normal_profile_process_state: str
    rollback_requirements: list[str]
    extension_id_stability_considerations: list[str]
    profile_restart_required: str
    developer_mode_involved: str
    required_human_approval: bool
    required_pre_promotion_backup: list[str]
    required_post_promotion_runtime_attestation: bool
    required_rollback_verification: bool
    required_behavioural_golden_journeys: list[str]
    blockers: list[str]
    verdict: str


class CurrentProfileIdentityReport(StrictModel):
    schema_version: str
    run_id: str
    observed_at: datetime
    residues: list[KnownExternalResidue]
    process_groups: list[BrowserProcessGroup]
    profile_references: list[BrowserProfileReference]
    selected_user_data_root: str
    selected_profile: str
    profile_selection_evidence: list[str]
    snapshot_files: list[SnapshotFileEvidence]
    configured_extensions: list[ConfiguredExtensionIdentity]
    configured_extension_verdict: str
    existing_devtools_endpoint_verdict: str
    passive_worker_observation: str
    current_runtime_attestation_verdict: str
    current_loaded_client_verdict: str
    promotion_readiness: PromotionReadinessPlan
    first_failing_boundary: str
    safety_counters: dict[str, int]
    limitations: list[str]
