"""Phase 2H capped real-backend evidence models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from kratos_guard.models.evidence import StrictModel


class BackendContractIdentity(StrictModel):
    endpoint: str
    process_identity: dict[str, object]
    container_identity: dict[str, object] | None
    contract_schema_hash: str
    relevant_route_hashes: dict[str, str]
    operation_state_contract: list[str]
    authentication_contract: dict[str, object]
    regeneration_contract: dict[str, object]
    persistence_readback_contract: dict[str, object]
    migration_head: str
    provider_boundary: dict[str, object]
    auto_reload: bool
    observed_at: datetime
    pre_contract_hash: str
    post_contract_hash: str
    limitations: list[str]
    verdict: str


class ProtectedTargetDriftPath(StrictModel):
    path: str
    classification: str
    active_runtime_overlap: bool
    configured_extension_overlap: bool
    attribution: str = "UNPROVEN"


class ProtectedTargetDriftClassification(StrictModel):
    baseline: str
    current: str
    target_root: str
    paths: list[ProtectedTargetDriftPath]
    active_runtime_roots: list[str]
    configured_extension_root: str
    execution_critical_unknowns: list[str]
    runtime_overlap_paths: list[str]
    attribution: str
    verdict: str


class SyntheticAuditIdentity(StrictModel):
    profile: str
    subject_id_hash: str
    tenant: str
    authentication_method: str
    token_scope: list[str]
    synthetic_ownership_proof: list[str]
    pre_existing: bool
    namespace_isolation: str
    normal_user_credentials_used: Literal[False]
    blocker: str
    verdict: str


class ProviderTestSeamEvidence(StrictModel):
    profile: str
    provider_mode: str
    generation_provider: str
    embedding_provider: str
    external_provider_enabled: bool
    pre_existing: bool
    runtime_restart_required: bool
    scenario_support: dict[str, bool]
    synthetic_isolation_proven: bool
    external_provider_call_cap: int
    limitations: list[str]
    verdict: str


class RealBackendBudget(StrictModel):
    maximum_synthetic_sessions_created: int = 1
    maximum_canonical_coursera_lessons_created: int = 1
    maximum_canonical_youtube_lessons_created: int = 1
    maximum_total_backend_operations_accepted: int = 12
    maximum_automatic_repair_operations: int = 2
    maximum_regeneration_operations: int = 2
    maximum_duplicate_request_attempts: int = 2
    maximum_external_provider_calls: Literal[0] = 0
    maximum_real_provider_cost_usd: float = Field(default=0.0, ge=0, le=0)
    maximum_polling_seconds_per_journey: int = 30
    maximum_suite_seconds: int = 600
    maximum_unexpected_database_row_delta: int = 0
    synthetic_sessions_created: int = 0
    coursera_lessons_created: int = 0
    youtube_lessons_created: int = 0
    backend_operations_accepted: int = 0
    automatic_repair_operations: int = 0
    regeneration_operations: int = 0
    duplicate_request_attempts: int = 0
    external_provider_calls: int = 0
    real_provider_cost_usd: float = 0.0
    unexpected_database_row_delta: int = 0
    immutable_caps: Literal[True] = True
    verdict: str = "REAL_BACKEND_BUDGET_PROVEN"

    def dispatch_allowed(self, counter: str, increment: int = 1) -> bool:
        limits = {
            "synthetic_sessions_created": self.maximum_synthetic_sessions_created,
            "coursera_lessons_created": self.maximum_canonical_coursera_lessons_created,
            "youtube_lessons_created": self.maximum_canonical_youtube_lessons_created,
            "backend_operations_accepted": self.maximum_total_backend_operations_accepted,
            "automatic_repair_operations": self.maximum_automatic_repair_operations,
            "regeneration_operations": self.maximum_regeneration_operations,
            "duplicate_request_attempts": self.maximum_duplicate_request_attempts,
            "external_provider_calls": self.maximum_external_provider_calls,
            "unexpected_database_row_delta": self.maximum_unexpected_database_row_delta,
        }
        if counter not in limits:
            raise ValueError("UNKNOWN_BUDGET_COUNTER")
        return int(getattr(self, counter)) + increment <= limits[counter]


class RealBackendJourney(StrictModel):
    journey_id: str
    platform: str
    run_marker: str = Field(pattern=r"^KAG-2H-")
    action: str
    operation_ids: list[str]
    accepted_operation_count: int
    repair_operation_count: int
    provider_attempt_count: int
    lesson_ids: list[str]
    artefact_ids: list[str]
    initial_state: str
    terminal_state: str
    visible_result: str
    database_readback_state: str
    first_failing_boundary: str
    verdict: str


class RealBackendOperationEvidence(StrictModel):
    operation_id: str
    run_marker: str = Field(pattern=r"^KAG-2H-")
    owner_id_hash: str
    idempotency_key_hash: str
    states: list[str]
    lesson_id: str
    artefact_id: str
    provider_attempt_count: int
    stranded: bool
    verdict: str


class DatabaseReadbackEvidence(StrictModel):
    database: str
    schema_name: str
    database_user_hash: str
    transaction_read_only: bool
    default_transaction_read_only: bool
    migration_heads: list[str]
    relevant_tables: list[str]
    table_column_contract_hash: str
    baseline_counts: dict[str, int]
    run_marker_counts: dict[str, int]
    retained_record_ids: list[str]
    credentials_redacted: bool
    write_queries_executed: int
    limitations: list[str]
    verdict: str


class ConcurrentActivityEvidence(StrictModel):
    run_marker: str = Field(pattern=r"^KAG-2H-")
    synthetic_owner_hash: str
    marker_scoped_counts: dict[str, int]
    global_counts_context: dict[str, int]
    unrelated_activity_observed: bool
    synthetic_namespace_contaminated: bool
    operation_attribution_state: str
    verdict: str


class RealBackendJourneyPlan(StrictModel):
    schema_version: str
    run_id: str
    run_marker: str = Field(pattern=r"^KAG-2H-")
    candidate: str
    candidate_id: str
    candidate_payload_hash: str
    backend_endpoint: str
    app_bridge_endpoint: str
    network_allowlist: list[str]
    journey_ids: list[str]
    budget: RealBackendBudget
    backend_contract_verdict: str
    synthetic_identity_verdict: str
    provider_seam_verdict: str
    database_readback_verdict: str
    active_writer_lease: str
    blockers: list[str]
    dispatch_authorised: bool
    promotion_authority: str
    plan_path: str
    observed_at: datetime
    verdict: str


class RealBackendSuiteReport(StrictModel):
    schema_version: str
    phase: str
    run_id: str
    run_marker: str = Field(pattern=r"^KAG-2H-")
    candidate_id: str
    candidate_before_hash: str
    candidate_after_hash: str
    backend_contract: BackendContractIdentity
    synthetic_identity: SyntheticAuditIdentity
    provider_seam: ProviderTestSeamEvidence
    database_readback: DatabaseReadbackEvidence
    budget: RealBackendBudget
    journeys: list[RealBackendJourney]
    operations: list[RealBackendOperationEvidence]
    concurrency: ConcurrentActivityEvidence
    allowed_requests: list[str]
    blocked_requests: list[str]
    browser_profile: str
    browser_cleanup_state: str
    normal_chrome_mutations: int = Field(ge=0)
    study_pilot_source_writes: int = Field(ge=0)
    study_pilot_git_mutations: int = Field(ge=0)
    authorised_synthetic_backend_writes: int = Field(ge=0)
    unauthorised_database_writes: int = Field(ge=0)
    real_provider_calls: int = Field(ge=0)
    real_provider_cost_usd: float = Field(ge=0)
    promotion_authority: str
    final_verdict: str
    first_remaining_blocker: str
