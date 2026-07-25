"""Evidence models for isolated extension runtime canaries."""

from datetime import datetime
from enum import StrEnum

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.state import EvidenceState


class RuntimeProofScope(StrEnum):
    SEALED_CANDIDATE_ON_DISK = "SEALED_CANDIDATE_ON_DISK"
    GUARD_LAUNCHED_BROWSER_PROCESS = "GUARD_LAUNCHED_BROWSER_PROCESS"
    ISOLATED_CANARY_LOADED_EXTENSION = "ISOLATED_CANARY_LOADED_EXTENSION"
    CURRENT_USER_LOADED_EXTENSION = "CURRENT_USER_LOADED_EXTENSION"
    PROMOTED_EXTENSION = "PROMOTED_EXTENSION"
    PRODUCT_BEHAVIOUR = "PRODUCT_BEHAVIOUR"


class BrowserExecutableIdentity(StrictModel):
    product: str
    executable_path: str
    executable_sha256: str
    file_version: str
    architecture: str
    discovery_method: str
    state: EvidenceState
    uncertainties: list[str]
    channel: str = ""
    playwright_version: str = ""
    browser_revision: str = ""
    installation_root: str = ""
    lockfile_sha256: str = ""
    provenance_state: EvidenceState = EvidenceState.UNPROVEN
    sideload_capability: str = "UNPROVEN"


class BrowserProcessIdentity(StrictModel):
    pid: int
    parent_pid: int
    child_pids: list[int]
    executable_path: str
    executable_sha256: str
    command_line: list[str]
    command_line_sha256: str
    state: EvidenceState
    created_at: datetime | None = None


class BrowserProfileIdentity(StrictModel):
    user_data_directory: str
    profile_directory: str
    fresh: bool
    guard_owned: bool
    cleanup_state: EvidenceState
    state: EvidenceState


class BrowserLaunchPolicy(StrictModel):
    executable_path: str
    executable_sha256: str
    candidate_directory: str
    candidate_manifest_sha256: str
    extension_path: str
    user_data_directory: str
    profile_directory: str
    debugging_host: str
    debugging_port: int
    startup_timeout_seconds: int
    lifetime_timeout_seconds: int
    allowed_navigation_schemes: list[str]
    network_policy: str
    command_line: list[str]
    command_line_sha256: str
    state: EvidenceState


class ExtensionRuntimeIdentity(StrictModel):
    extension_id: str
    extension_origin: str
    manifest_version: int
    extension_name: str
    extension_version: str
    service_worker_url: str
    service_worker_target_id: str
    extension_page_target_ids: list[str]
    browser_pid: int
    profile_path: str
    observed_at: datetime
    state: EvidenceState


class RuntimeAttestationReadback(StrictModel):
    source: str
    extension_url: str
    candidate_id: str
    source_head: str
    repository_source_manifest_hash: str
    component_input_manifest_hash: str
    payload_manifest_hash: str
    signing_key_id: str
    signature_algorithm: str
    canonical_integrity_hash: str
    attestation_file_sha256: str
    signature_state: EvidenceState
    signer_trust_state: EvidenceState
    state: EvidenceState


class NetworkAttempt(StrictModel):
    url: str
    resource_type: str
    decision: str
    observed_at: datetime


class NetworkIsolationEvidence(StrictModel):
    policy: str
    attempted_requests: list[NetworkAttempt]
    blocked_request_count: int
    provider_request_count: int
    itzako_api_request_count: int
    third_party_request_count: int
    lesson_operation_count: int
    explanation_operation_count: int
    state: EvidenceState


class CanaryLifecycleEvidence(StrictModel):
    preexisting_browser_pids: list[int]
    owned_browser_pids: list[int]
    observed_child_pids: list[int]
    graceful_close: bool
    forced_close_required: bool
    surviving_owned_pids: list[int]
    profile_cleanup: str
    state: EvidenceState


class CandidateRuntimeWitness(StrictModel):
    candidate_directory: str
    before_manifest_sha256: str
    after_manifest_sha256: str
    changed: bool
    state: EvidenceState


class CurrentUserRuntimeObservation(StrictModel):
    preexisting_browser_pids: list[int]
    post_canary_browser_pids: list[int]
    overlapping_canary_pids: list[int]
    loaded_extension_state: EvidenceState
    reason: str
    state: EvidenceState


class RuntimeChainVerification(StrictModel):
    scope_states: dict[RuntimeProofScope, EvidenceState]
    source_to_build_state: EvidenceState
    build_to_runtime_state: EvidenceState
    loaded_client_state: EvidenceState
    current_user_loaded_client_state: EvidenceState
    first_failing_boundary: str
    contradictions: list[str]
    uncertainties: list[str]
    verdict: str
    browser_capability_state: str = "UNPROVEN"
    service_worker_state: str = "UNPROVEN"
    runtime_readback_state: str = "UNPROVEN"


class CanaryReport(StrictModel):
    schema_version: str
    run_id: str
    observed_at: datetime
    verifier_identity: dict[str, object]
    candidate_identity: dict[str, object]
    provenance_verification: dict[str, object]
    browser_executable: BrowserExecutableIdentity
    launch_policy: BrowserLaunchPolicy
    profile_identity: BrowserProfileIdentity
    browser_process: BrowserProcessIdentity
    extension_runtime: ExtensionRuntimeIdentity | None
    runtime_readback: RuntimeAttestationReadback | None
    runtime_verification: RuntimeChainVerification
    network_isolation: NetworkIsolationEvidence
    lifecycle: CanaryLifecycleEvidence
    candidate_witness: CandidateRuntimeWitness
    target_witness: dict[str, object]
    current_user_runtime: CurrentUserRuntimeObservation
    exact_extension_load_path: str
    non_guarantees: list[str]
    next_required_evidence: str
    learning_summary: str
