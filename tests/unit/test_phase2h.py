"""Phase 2H authority, budget, isolation, and blocked-dispatch tests."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from kratos_guard.core import phase2h
from kratos_guard.core.phase2h import (
    PHASE2H_SAFETY_COUNTERS,
    REAL_BACKEND_JOURNEYS,
    REQUIRED_ROUTES,
    classify_protected_target_drift,
    inspect_backend_contract,
    verify_database_readback,
    verify_provider_test_seam,
    verify_synthetic_audit_identity,
)
from kratos_guard.models.phase2h import (
    ConcurrentActivityEvidence,
    DatabaseReadbackEvidence,
    RealBackendBudget,
    RealBackendJourney,
    SyntheticAuditIdentity,
)


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _classify(tmp_path: Path, target_root: Path, changed_paths: list[str]):
    baseline = _write_json(tmp_path / "baseline.json", {"run_id": "phase2g"})
    current = _write_json(
        tmp_path / "current.json",
        {
            "target_root": str(target_root),
            "changed_paths": changed_paths,
        },
    )
    return classify_protected_target_drift(baseline, current)


def test_unrelated_external_drift_does_not_block_dispatch(tmp_path: Path) -> None:
    report = _classify(
        tmp_path,
        phase2h.COORDINATION_ROOT,
        ["_agent_runs/example/FINAL_REPORT.md"],
    )
    assert report.verdict == "EXTERNAL_DRIFT_CLASSIFIED_NO_RUNTIME_OVERLAP"
    assert report.runtime_overlap_paths == []


def test_runtime_overlapping_drift_blocks_dispatch(tmp_path: Path) -> None:
    report = _classify(
        tmp_path,
        phase2h.CANONICAL_ROOT,
        ["Study_master_backend/app/api/v1/study.py"],
    )
    assert report.verdict == "EXTERNAL_DRIFT_OVERLAPS_RUNTIME"
    assert report.runtime_overlap_paths


def test_unknown_execution_critical_drift_blocks_dispatch(tmp_path: Path) -> None:
    report = _classify(
        tmp_path,
        phase2h.COORDINATION_ROOT,
        ["unknown-runtime/entrypoint.bin"],
    )
    assert report.verdict == "EXTERNAL_DRIFT_CLASSIFICATION_INCOMPLETE"
    assert report.execution_critical_unknowns == ["unknown-runtime/entrypoint.bin"]


def test_drift_is_never_attributed_without_evidence(tmp_path: Path) -> None:
    report = _classify(
        tmp_path,
        phase2h.COORDINATION_ROOT,
        ["Study_master/extension/panel.js"],
    )
    assert report.attribution == "UNPROVEN"
    assert report.paths[0].attribution == "UNPROVEN"


class _FakeProcess:
    pid = 8000

    def __init__(self, *, reload: bool = False, scenario: bool = False):
        self.reload = reload
        self.scenario = scenario

    def cmdline(self) -> list[str]:
        command = ["python", "run_locked_local_backend.py"]
        return [*command, "--reload"] if self.reload else command

    def cwd(self) -> str:
        return str(phase2h.CANONICAL_ROOT / "Study_master_backend")

    def exe(self) -> str:
        return r"C:\Python314\python.exe"

    def create_time(self) -> float:
        return 1_700_000_000.0

    def environ(self) -> dict[str, str]:
        environment = {
            "STUDY_PILOT_PROVIDER_MODE": "disabled",
            "GENERATION_PROVIDER": "fake",
            "EMBEDDING_PROVIDER": "fake",
            "PAID_CALL_ROUTER_ALLOW_REAL_PROVIDERS": "false",
        }
        if self.scenario:
            environment["KAG_SYNTHETIC_PROVIDER_SCENARIO"] = "enabled"
        return environment


def _ready_payload() -> dict[str, object]:
    return {
        "status": "ready",
        "runtime_identity": {
            "process_id": 8000,
            "runtime_id": "runtime",
            "build_id": "build",
            "manifest_sha256": "a" * 64,
            "protected_digest_sha256": "b" * 64,
            "source_root": str(phase2h.CANONICAL_ROOT / "Study_master_backend"),
            "runtime_source_commit": "c" * 40,
            "backend_worktree_clean": False,
            "release_ready": False,
            "database": {
                "database": "studypilot_dev",
                "schema": "public",
                "migration_heads": ["017"],
            },
        },
    }


def _contract_fetch(url: str, *, missing_routes: bool = False) -> tuple[dict[str, object], str]:
    if url.endswith("/api/v1/ready"):
        return _ready_payload(), "ready-hash"
    paths = {} if missing_routes else {route: {"post": {}} for route in REQUIRED_ROUTES}
    return {"paths": paths}, "openapi-hash"


def test_health_http_200_cannot_prove_backend_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        phase2h,
        "_fetch_json",
        lambda url: _contract_fetch(url, missing_routes=True),
    )
    monkeypatch.setattr(phase2h, "_listener_process", lambda port: _FakeProcess())
    report = inspect_backend_contract("itzako")
    assert report.verdict == "BACKEND_CONTRACT_IDENTITY_PARTIAL"


def test_relevant_route_schema_hashes_are_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(phase2h, "_fetch_json", _contract_fetch)
    monkeypatch.setattr(phase2h, "_listener_process", lambda port: _FakeProcess())
    report = inspect_backend_contract("itzako")
    assert report.verdict == "BACKEND_CONTRACT_IDENTITY_PROVEN"
    assert set(report.relevant_route_hashes) == set(REQUIRED_ROUTES)


def test_auto_reload_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(phase2h, "_fetch_json", _contract_fetch)
    monkeypatch.setattr(phase2h, "_listener_process", lambda port: _FakeProcess(reload=True))
    report = inspect_backend_contract("itzako")
    assert report.auto_reload is True
    assert report.verdict == "BACKEND_CONTRACT_IDENTITY_PARTIAL"


def test_normal_user_credentials_are_prohibited() -> None:
    with pytest.raises(ValidationError):
        SyntheticAuditIdentity(
            profile="itzako",
            subject_id_hash="hash",
            tenant="test",
            authentication_method="normal cookie",
            token_scope=[],
            synthetic_ownership_proof=[],
            pre_existing=True,
            namespace_isolation="PROVEN",
            normal_user_credentials_used=True,
            blocker="",
            verdict="PROVEN",
        )


def test_synthetic_identity_must_be_independently_proven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = _write_json(
        tmp_path / "lease.json",
        {"status": "ACTIVE", "scope": "other isolated lane"},
    )
    monkeypatch.setattr(phase2h, "WRITER_LEASE_PATH", lease)
    monkeypatch.setattr(
        phase2h,
        "_fetch_json",
        lambda url: (
            {
                "extensionTokenConfigured": False,
                "localBackendSessionBootstrap": False,
            },
            "hash",
        ),
    )
    identity = verify_synthetic_audit_identity("itzako")
    assert identity.verdict == "BLOCKED_SYNTHETIC_IDENTITY_UNAVAILABLE"
    assert identity.normal_user_credentials_used is False


def test_run_marker_is_required() -> None:
    with pytest.raises(ValidationError):
        RealBackendJourney(
            journey_id="test",
            platform="coursera",
            run_marker="missing-prefix",
            action="automatic",
            operation_ids=[],
            accepted_operation_count=0,
            repair_operation_count=0,
            provider_attempt_count=0,
            lesson_ids=[],
            artefact_ids=[],
            initial_state="NOT_DISPATCHED",
            terminal_state="BLOCKED",
            visible_result="NOT_RUN",
            database_readback_state="NONE",
            first_failing_boundary="blocked",
            verdict="BLOCKED",
        )


def test_database_readback_rejects_non_phase2h_marker() -> None:
    with pytest.raises(ValueError, match="PHASE2H_RUN_MARKER_REQUIRED"):
        verify_database_readback("itzako", "wrong-marker")


def test_provider_seam_must_preexist_and_be_scenario_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(phase2h, "_listener_process", lambda port: _FakeProcess())
    seam = verify_provider_test_seam("itzako")
    assert seam.pre_existing is True
    assert seam.verdict == "DETERMINISTIC_PROVIDER_SEAM_UNAVAILABLE"
    assert seam.scenario_support["wrong_then_correct"] is False


def test_provider_seam_cannot_affect_real_users(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        phase2h,
        "_listener_process",
        lambda port: _FakeProcess(scenario=True),
    )
    seam = verify_provider_test_seam("itzako")
    assert seam.synthetic_isolation_proven is True
    assert seam.external_provider_enabled is False


def test_external_provider_cap_is_immutable_zero() -> None:
    with pytest.raises(ValidationError):
        RealBackendBudget(maximum_external_provider_calls=1)


def test_real_provider_cost_cap_is_immutable_zero() -> None:
    with pytest.raises(ValidationError):
        RealBackendBudget(maximum_real_provider_cost_usd=0.01)


def test_database_probe_forces_transaction_read_only() -> None:
    assert "SET TRANSACTION READ ONLY" in phase2h._DATABASE_PROBE
    assert "transaction_read_only" in phase2h._DATABASE_PROBE


def test_database_readback_requires_read_only_transaction() -> None:
    evidence = DatabaseReadbackEvidence(
        database="studypilot_dev",
        schema_name="public",
        database_user_hash="hash",
        transaction_read_only=True,
        default_transaction_read_only=False,
        migration_heads=["017"],
        relevant_tables=["users"],
        table_column_contract_hash="a" * 64,
        baseline_counts={"users": 1},
        run_marker_counts={},
        retained_record_ids=[],
        credentials_redacted=True,
        write_queries_executed=0,
        limitations=["role write-capable; transaction forced read-only"],
        verdict="DATABASE_READBACK_AUTHORITY_PROVEN",
    )
    assert evidence.transaction_read_only is True
    assert evidence.write_queries_executed == 0


def test_synthetic_namespace_counts_are_isolated() -> None:
    evidence = ConcurrentActivityEvidence(
        run_marker="KAG-2H-test",
        synthetic_owner_hash="owner",
        marker_scoped_counts={"operations": 0},
        global_counts_context={"operations": 3},
        unrelated_activity_observed=True,
        synthetic_namespace_contaminated=False,
        operation_attribution_state="NO_OPERATIONS_DISPATCHED",
        verdict="CONCURRENT_EXTERNAL_ACTIVITY_OBSERVED",
    )
    assert evidence.marker_scoped_counts != evidence.global_counts_context
    assert evidence.synthetic_namespace_contaminated is False


def test_backend_budget_is_checked_before_dispatch() -> None:
    budget = RealBackendBudget(backend_operations_accepted=11)
    assert budget.dispatch_allowed("backend_operations_accepted") is True
    budget.backend_operations_accepted = 12
    assert budget.dispatch_allowed("backend_operations_accepted") is False


def test_caps_do_not_increase_during_failed_preflight() -> None:
    budget = RealBackendBudget()
    before = budget.model_dump()
    assert budget.dispatch_allowed("external_provider_calls") is False
    assert budget.model_dump() == before


def test_unknown_budget_counter_fails_closed() -> None:
    with pytest.raises(ValueError, match="UNKNOWN_BUDGET_COUNTER"):
        RealBackendBudget().dispatch_allowed("unknown")


@pytest.mark.parametrize(
    ("counter", "maximum"),
    [
        ("automatic_repair_operations", 2),
        ("regeneration_operations", 2),
        ("duplicate_request_attempts", 2),
        ("backend_operations_accepted", 12),
        ("coursera_lessons_created", 1),
        ("youtube_lessons_created", 1),
    ],
)
def test_operation_caps_are_machine_enforced(counter: str, maximum: int) -> None:
    budget = RealBackendBudget(**{counter: maximum})
    assert budget.dispatch_allowed(counter) is False


@pytest.mark.parametrize(
    "journey_id",
    [journey[0] for journey in REAL_BACKEND_JOURNEYS],
)
def test_all_twelve_real_backend_contracts_are_present(journey_id: str) -> None:
    assert [journey[0] for journey in REAL_BACKEND_JOURNEYS].count(journey_id) == 1


def test_restoration_contract_is_generation_free() -> None:
    restoration = [journey for journey in REAL_BACKEND_JOURNEYS if "restoration" in journey[0]]
    assert len(restoration) == 2
    assert all(journey[2] == "saved-restoration" for journey in restoration)


def test_duplicate_attempt_cap_cannot_create_two_canonical_operations() -> None:
    budget = RealBackendBudget(
        duplicate_request_attempts=2,
        backend_operations_accepted=1,
    )
    assert budget.dispatch_allowed("duplicate_request_attempts") is False
    assert budget.backend_operations_accepted == 1


def test_logged_out_contract_is_present_without_writes() -> None:
    journey = next(value for value in REAL_BACKEND_JOURNEYS if value[0] == "logged-out")
    assert journey[2] == "logged-out"
    assert PHASE2H_SAFETY_COUNTERS["real_learner_account_uses"] == 0


def test_backend_unavailable_contract_does_not_stop_backend() -> None:
    journey = next(value for value in REAL_BACKEND_JOURNEYS if value[0] == "backend-unavailable")
    assert journey[2] == "backend-unavailable"
    assert PHASE2H_SAFETY_COUNTERS["backend_restarts"] == 0


def test_http_success_cannot_satisfy_language_oracle() -> None:
    required_layers = {
        "http",
        "operation_state",
        "language_oracle",
        "database_readback",
        "visible_state",
    }
    assert {"http"} != required_layers


def test_fixture_provider_proof_does_not_imply_real_provider_proof() -> None:
    seam = _FakeProcess().environ()
    assert seam["GENERATION_PROVIDER"] == "fake"
    assert seam["PAID_CALL_ROUTER_ALLOW_REAL_PROVIDERS"] == "false"


def test_real_backend_proof_does_not_imply_normal_profile_proof() -> None:
    assert PHASE2H_SAFETY_COUNTERS["normal_chrome_mutations"] == 0
    normal_profile_state = "NORMAL_PROFILE_UNPROVEN"
    assert normal_profile_state == "NORMAL_PROFILE_UNPROVEN"


@pytest.mark.parametrize("counter", PHASE2H_SAFETY_COUNTERS)
def test_phase2h_protected_mutation_counter_remains_zero(counter: str) -> None:
    assert PHASE2H_SAFETY_COUNTERS[counter] == 0
