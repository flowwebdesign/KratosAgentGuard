"""Phase 2I isolated backend audit authority and journey evidence models."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from kratos_guard.models.evidence import StrictModel


class BackendAuditAuthority(StrictModel):
    repository_path: str
    git_common_directory: str
    branch: str
    head: str = Field(pattern=r"^[a-f0-9]{40}$")
    baseline_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    baseline_present: bool
    separate_git_directory: bool
    separate_object_database: bool
    linked_worktree: bool
    alternates: list[str]
    hardlinked_object_files: list[str]
    push_urls: list[str]
    dirty_paths: list[str]
    normal_runtime_unchanged: bool
    mutation_authority: Literal["AUTHORISED_ISOLATED_ONLY"]
    promotion_authority: Literal["NONE"] = "NONE"
    verdict: str


class AuditDatabaseIdentity(StrictModel):
    container_id: str
    container_state: str
    endpoint: str
    database: str
    application_schema: str
    application_migration_head: str
    application_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    application_table_count: int = Field(ge=0)
    audit_schema: str
    audit_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    audit_tables: list[str]
    external_database_access: bool
    canonical_database_writes: Literal[0] = 0
    verdict: str


class AuditRoleIdentity(StrictModel):
    role: str
    login: bool
    superuser: bool
    create_database: bool
    create_role: bool
    replication: bool
    audit_database_connect: bool
    other_database_connect: bool
    transaction_read_only_default: bool
    application_select: bool
    application_insert: bool
    application_update: bool
    application_delete: bool
    audit_select: bool
    audit_insert: bool
    audit_update: bool
    audit_delete: bool
    verdict: str


class SyntheticAuditTokenIdentity(StrictModel):
    classification: Literal["SYNTHETIC_AUDIT_IDENTITY"]
    subject: Literal["kag-phase2i"]
    tenant: Literal["kag-audit"]
    issuer: Literal["kratos-agent-guard-phase2i"]
    audience: Literal["itzako-kag-audit"]
    scope: list[str]
    token_fingerprint_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    issued_at: datetime
    expires_at: datetime
    database: Literal["studypilot_kag_audit"]
    secret_protection: Literal["WINDOWS_DPAPI_CURRENT_USER"]
    normal_user_association: Literal[False]
    email_delivery: Literal[False]
    billing: Literal[False]
    invitation: Literal[False]
    production_membership: Literal[False]
    verdict: str


class AuditScenarioDefinition(StrictModel):
    name: Literal[
        "same_language_success",
        "wrong_then_correct",
        "wrong_then_wrong",
        "terminal_timeout",
        "terminal_failure",
    ]
    scenario_version: str
    maximum_provider_attempts: int = Field(ge=1, le=2)
    output_sequence: list[str]
    terminal_state: str
    external_provider_calls: Literal[0] = 0
    requires_audit_mode: Literal[True] = True
    requires_synthetic_token: Literal[True] = True
    requires_active_lease: Literal[True] = True


class AuditScenarioEvidence(StrictModel):
    run_marker: str = Field(pattern=r"^KAG-2I-")
    operation_id: str
    scenario: str
    attempt_count: int = Field(ge=0, le=2)
    event_states: list[str]
    output_languages: list[str]
    external_provider_calls: Literal[0] = 0
    bounded: bool
    verdict: str


class AuditWriterLease(StrictModel):
    lease_id: str
    run_marker: str = Field(pattern=r"^KAG-2I-")
    candidate_id: str
    backend_build_id: str
    database: Literal["studypilot_kag_audit"]
    synthetic_subject: Literal["kag-phase2i"]
    acquired_at: datetime
    expires_at: datetime
    status: Literal["ACTIVE", "RELEASED", "EXPIRED"]
    released_at: datetime | None
    terminal_outcome: str
    valid_at_observation: bool
    verdict: str


class BackendAuditBuildIdentity(StrictModel):
    build_id: str
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    source_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    build_input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    audit_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    attestation_path: str
    attestation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    signing_key_id: str
    signature_state: str
    signer_trust_state: str
    reproducibility: str
    lineage_bundle_path: str
    lineage_bundle_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    promotion_authority: Literal["NONE"] = "NONE"
    verdict: str


class BackendAuditRuntimeIdentity(StrictModel):
    endpoint: Literal["http://127.0.0.1:18000"]
    process_id: int = Field(gt=0)
    executable: str
    command: list[str]
    working_directory: str
    backend_build_id: str
    source_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    source_manifest_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    build_input_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    database: Literal["studypilot_kag_audit"]
    migration_head: Literal["017"]
    audit_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    audit_mode: bool
    external_providers_disabled: bool
    auto_reload: bool
    observed_at: datetime
    verdict: str


class NetworkTranslationEvidence(StrictModel):
    request_id: str
    original_url: str
    translated_url: str
    method: str
    path_and_query_preserved: bool
    body_sha256_before: str
    body_sha256_after: str
    normal_headers_preserved: bool
    audit_headers_added: list[str]
    candidate_bytes_modified: Literal[False]
    normal_chrome_storage_used: Literal[False]
    verdict: str


class Phase2IRealBackendBudget(StrictModel):
    sessions: int = Field(default=0, ge=0, le=1)
    coursera_lessons: int = Field(default=0, ge=0, le=1)
    youtube_lessons: int = Field(default=0, ge=0, le=1)
    accepted_operations: int = Field(default=0, ge=0, le=12)
    automatic_repairs: int = Field(default=0, ge=0, le=2)
    regenerations: int = Field(default=0, ge=0, le=2)
    duplicate_attempts: int = Field(default=0, ge=0, le=2)
    external_provider_calls: Literal[0] = 0
    provider_cost_usd: float = Field(default=0.0, ge=0, le=0)
    polling_timeout_seconds: Literal[30] = 30
    suite_timeout_seconds: Literal[600] = 600
    unexpected_database_row_delta: Literal[0] = 0


class Phase2IJourneyEvidence(StrictModel):
    journey_number: int = Field(ge=1, le=12)
    journey_id: str
    scenario: str
    operation_ids: list[str]
    lesson_ids: list[str]
    artefact_ids: list[str]
    revision_ids: list[str]
    # Journey 9 contains two independently capped mismatch lineages (A and B).
    provider_attempts: int = Field(ge=0, le=4)
    generation_operations: int = Field(ge=0)
    visible_state: str
    persistence_state: str
    first_failing_boundary: str
    verdict: str


class Phase2IJourneyPlan(StrictModel):
    schema_version: Literal["kratos-guard.phase2i-plan.v1"]
    run_id: str
    run_marker: str = Field(pattern=r"^KAG-2I-")
    candidate_path: str
    candidate_id: Literal["itzako-extension-1.1.19-language-repair-20260725T115732Z-5feba5dc7f1a"]
    backend_attestation_path: str
    backend_lineage_attestation_path: str
    backend_build_id: str
    runtime_owner_path: str
    audit_runtime_endpoint: Literal["http://127.0.0.1:18000"]
    sealed_backend_origin: Literal["http://127.0.0.1:8000"]
    synthetic_user_id: str
    journey_ids: list[str] = Field(min_length=12, max_length=12)
    budget: Phase2IRealBackendBudget
    dispatch_authorised: bool
    blockers: list[str]
    plan_path: str
    promotion_authority: Literal["NONE"] = "NONE"
    created_at: datetime
    verdict: str


class Phase2IDatabaseReadback(StrictModel):
    run_marker: str = Field(pattern=r"^KAG-2I-")
    database: Literal["studypilot_kag_audit"]
    database_role: Literal["kag_audit_readonly"]
    transaction_read_only: Literal[True]
    synthetic_user_id: str
    session_ids: list[str]
    operation_ids: list[str]
    lesson_keys: list[str]
    artefact_ids: list[str]
    revision_ids: list[str]
    scenario_event_ids: list[str]
    accepted_operation_count: int = Field(ge=0, le=12)
    canonical_lesson_count: int = Field(ge=0, le=12)
    explanation_revision_count: int = Field(ge=0, le=12)
    provider_attempt_count: int = Field(ge=0)
    external_provider_calls: Literal[0] = 0
    running_operation_count: Literal[0] = 0
    unrelated_marker_record_count: Literal[0] = 0
    write_queries_executed: Literal[0] = 0
    expert_material_relationships_preserved: bool
    verdict: str


class IsolatedRealBackendSuiteReport(StrictModel):
    schema_version: Literal["kratos-guard.phase2i-report.v1"]
    run_id: str
    run_marker: str = Field(pattern=r"^KAG-2I-")
    candidate_id: str
    candidate_before_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_after_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    backend_build: BackendAuditBuildIdentity
    runtime: BackendAuditRuntimeIdentity
    database: AuditDatabaseIdentity
    backend_role: AuditRoleIdentity
    readonly_role: AuditRoleIdentity
    synthetic_identity: SyntheticAuditTokenIdentity
    lease: AuditWriterLease
    scenarios: list[AuditScenarioEvidence]
    translations: list[NetworkTranslationEvidence]
    budget: Phase2IRealBackendBudget
    journeys: list[Phase2IJourneyEvidence]
    database_readback: Phase2IDatabaseReadback
    retained_record_ids: list[str]
    stranded_operation_count: int = Field(ge=0)
    canonical_backend_writes: Literal[0] = 0
    canonical_database_writes: Literal[0] = 0
    normal_chrome_mutations: Literal[0] = 0
    study_pilot_source_git_mutations: Literal[0] = 0
    external_provider_calls: Literal[0] = 0
    provider_cost_usd: float = Field(default=0.0, ge=0, le=0)
    browser_cleanup_state: str
    audit_runtime_shutdown_state: str
    promotion_authority: Literal["NONE"] = "NONE"
    final_verdict: str
    first_remaining_blocker: str
