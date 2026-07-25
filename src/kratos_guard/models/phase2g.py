"""Phase 2G behavioural-successor evidence models."""

from kratos_guard.models.evidence import StrictModel


class BehaviouralChangeImpact(StrictModel):
    fix: str
    repository: str
    affected_paths: list[dict[str, object]]
    backend_contract: str
    backend_mutation_required: bool
    persistence_mutation_required: bool
    verdict: str


class OfflineGoldenJourneyResult(StrictModel):
    journey_id: str
    platform: str
    requested_language: str
    detected_language: str
    repair_request_count: int
    simulated_provider_count: int
    lesson_identity_preserved: bool
    terminal_state: str
    visible_result: str
    verdict: str


class OfflineGoldenJourneyReport(StrictModel):
    suite: str
    candidate: str
    journeys: list[OfflineGoldenJourneyResult]
    fixture_request_count: int
    external_network_attempts: list[str]
    real_provider_calls: int
    real_backend_operations: int
    normal_profile_state: str
    real_backend_state: str
    verdict: str


class BehaviouralSuccessorDelta(StrictModel):
    base_candidate: str
    candidate: str
    authorised_runtime_delta: list[str]
    actual_runtime_delta: list[str]
    unexpected_runtime_delta: list[str]
    invariant_results: dict[str, bool]
    verdict: str
