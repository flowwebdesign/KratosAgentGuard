"""Phase 2I authority, lease, runtime, and evidence boundary tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from kratos_guard.core import phase2i, phase2i_journeys
from kratos_guard.models.phase2i import (
    AuditRoleIdentity,
    AuditScenarioEvidence,
    AuditWriterLease,
    BackendAuditRuntimeIdentity,
    IsolatedRealBackendSuiteReport,
    NetworkTranslationEvidence,
    Phase2IRealBackendBudget,
    SyntheticAuditTokenIdentity,
)


def _synthetic_identity(**overrides: object) -> SyntheticAuditTokenIdentity:
    values: dict[str, object] = {
        "classification": "SYNTHETIC_AUDIT_IDENTITY",
        "subject": "kag-phase2i",
        "tenant": "kag-audit",
        "issuer": "kratos-agent-guard-phase2i",
        "audience": "itzako-kag-audit",
        "scope": ["audit:golden-journeys"],
        "token_fingerprint_sha256": "a" * 64,
        "issued_at": datetime.now(UTC),
        "expires_at": datetime.now(UTC) + timedelta(hours=1),
        "database": "studypilot_kag_audit",
        "secret_protection": "WINDOWS_DPAPI_CURRENT_USER",
        "normal_user_association": False,
        "email_delivery": False,
        "billing": False,
        "invitation": False,
        "production_membership": False,
        "verdict": "SYNTHETIC_AUDIT_IDENTITY_PROVEN",
    }
    values.update(overrides)
    return SyntheticAuditTokenIdentity.model_validate(values)


def _role(name: str, *, readonly: bool) -> AuditRoleIdentity:
    return AuditRoleIdentity(
        role=name,
        login=True,
        superuser=False,
        create_database=False,
        create_role=False,
        replication=False,
        audit_database_connect=True,
        other_database_connect=False,
        transaction_read_only_default=readonly,
        application_select=True,
        application_insert=not readonly,
        application_update=not readonly,
        application_delete=False,
        audit_select=True,
        audit_insert=not readonly,
        audit_update=not readonly,
        audit_delete=False,
        verdict=("AUDIT_READONLY_ROLE_PROVEN" if readonly else "AUDIT_BACKEND_ROLE_PROVEN"),
    )


def test_exact_baseline_commit_is_mandatory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="EXACT_CANONICAL_SOURCE_COMMIT_REQUIRED"):
        phase2i.inspect_backend_audit_authority(tmp_path, "0" * 40)


def test_independent_clean_remote_free_repository_is_proven(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git" / "objects" / "info").mkdir(parents=True)

    def fake_git(repository: Path, *arguments: str) -> str:
        command = arguments[0]
        if arguments[:2] == ("rev-parse", "--show-toplevel"):
            return str(tmp_path)
        if arguments[:2] == ("rev-parse", "--git-common-dir"):
            return ".git"
        if arguments[:2] == ("branch", "--show-current"):
            return "audit/phase2i-test"
        if arguments[:2] == ("rev-parse", "HEAD"):
            return "b" * 40
        if command == "cat-file":
            return "commit"
        if command == "worktree":
            return f"worktree {tmp_path}\nHEAD {'b' * 40}\nbranch refs/heads/audit"
        return ""

    monkeypatch.setattr(phase2i, "_git", fake_git)
    authority = phase2i.inspect_backend_audit_authority(tmp_path)
    assert authority.verdict == "BACKEND_AUDIT_SOURCE_AUTHORITY_PROVEN"
    assert authority.separate_object_database is True
    assert authority.push_urls == []


def test_linked_worktree_blocks_repository_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git" / "objects" / "info").mkdir(parents=True)

    def fake_git(repository: Path, *arguments: str) -> str:
        if arguments[:2] == ("rev-parse", "--show-toplevel"):
            return str(tmp_path)
        if arguments[:2] == ("rev-parse", "--git-common-dir"):
            return ".git"
        if arguments[:2] == ("branch", "--show-current"):
            return "audit"
        if arguments[:2] == ("rev-parse", "HEAD"):
            return "b" * 40
        if arguments[0] == "cat-file":
            return "commit"
        if arguments[0] == "worktree":
            return "worktree one\nworktree two"
        return ""

    monkeypatch.setattr(phase2i, "_git", fake_git)
    authority = phase2i.inspect_backend_audit_authority(tmp_path)
    assert authority.linked_worktree is True
    assert authority.verdict == "BACKEND_AUDIT_SOURCE_AUTHORITY_UNPROVEN"


def test_all_five_scenario_definitions_are_bounded() -> None:
    assert [item.name for item in phase2i.SCENARIO_DEFINITIONS] == [
        "same_language_success",
        "wrong_then_correct",
        "wrong_then_wrong",
        "terminal_timeout",
        "terminal_failure",
    ]
    assert all(item.maximum_provider_attempts <= 2 for item in phase2i.SCENARIO_DEFINITIONS)
    assert all(item.external_provider_calls == 0 for item in phase2i.SCENARIO_DEFINITIONS)


def test_wrong_then_wrong_has_no_third_attempt() -> None:
    definition = next(
        item for item in phase2i.SCENARIO_DEFINITIONS if item.name == "wrong_then_wrong"
    )
    assert definition.output_sequence == ["german", "german"]
    assert definition.maximum_provider_attempts == 2


def test_wrong_then_correct_repairs_once() -> None:
    definition = next(
        item for item in phase2i.SCENARIO_DEFINITIONS if item.name == "wrong_then_correct"
    )
    assert definition.output_sequence == ["german", "english"]
    assert definition.maximum_provider_attempts == 2


def test_provider_scenario_source_requires_every_authority_name(tmp_path: Path) -> None:
    audit = tmp_path / "Study_master_backend" / "app" / "audit"
    audit.mkdir(parents=True)
    (audit / "provider.py").write_text("provider unavailable", encoding="utf-8")
    (audit / "authority.py").write_text("authority unavailable", encoding="utf-8")
    with pytest.raises(RuntimeError, match="AUDIT_SCENARIO_MISSING"):
        phase2i.verify_audit_provider_scenarios(tmp_path)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("subject", "normal-user"),
        ("tenant", "production"),
        ("audience", "canonical"),
        ("database", "studypilot_dev"),
        ("classification", "NORMAL_USER"),
        ("normal_user_association", True),
        ("email_delivery", True),
        ("billing", True),
        ("invitation", True),
        ("production_membership", True),
    ],
)
def test_synthetic_identity_literals_reject_normal_authority(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        _synthetic_identity(**{field: value})


def test_synthetic_token_fingerprint_is_sha256() -> None:
    with pytest.raises(ValidationError):
        _synthetic_identity(token_fingerprint_sha256="short")


def test_readonly_role_has_no_mutation_privileges() -> None:
    role = _role("kag_audit_readonly", readonly=True)
    assert role.transaction_read_only_default is True
    assert role.application_insert is False
    assert role.application_update is False
    assert role.audit_insert is False
    assert role.audit_update is False


def test_backend_role_has_no_delete_or_other_database_access() -> None:
    role = _role("kag_audit_backend", readonly=False)
    assert role.other_database_connect is False
    assert role.application_delete is False
    assert role.audit_delete is False
    assert role.superuser is False


def test_lease_requires_phase2i_marker() -> None:
    with pytest.raises(ValidationError):
        AuditWriterLease(
            lease_id="lease",
            run_marker="wrong-marker",
            candidate_id="candidate",
            backend_build_id="build",
            database="studypilot_kag_audit",
            synthetic_subject="kag-phase2i",
            acquired_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
            status="ACTIVE",
            released_at=None,
            terminal_outcome="",
            valid_at_observation=True,
            verdict="AUDIT_WRITER_LEASE_PROVEN",
        )


@pytest.mark.parametrize("ttl", [0, 599, 3601, 7200])
def test_lease_acquisition_rejects_unbounded_ttl(ttl: int) -> None:
    with pytest.raises(ValueError, match="AUDIT_LEASE_TTL_OUT_OF_RANGE"):
        phase2i.acquire_audit_writer_lease(
            phase2i.EXPECTED_CANDIDATE_ID,
            "KAG-2I-test-marker",
            "backend-audit-build",
            ttl_seconds=ttl,
        )


def test_lease_acquisition_requires_exact_candidate() -> None:
    with pytest.raises(ValueError, match="EXACT_CANDIDATE_ID_REQUIRED"):
        phase2i.acquire_audit_writer_lease("latest", "KAG-2I-test-marker", "backend-audit-build")


def test_lease_acquisition_requires_exact_marker_prefix() -> None:
    with pytest.raises(ValueError, match="PHASE2I_RUN_MARKER_REQUIRED"):
        phase2i.acquire_audit_writer_lease(
            phase2i.EXPECTED_CANDIDATE_ID,
            "KAG-2H-wrong",
            "backend-audit-build",
        )


def test_lease_acquisition_requires_backend_audit_build() -> None:
    with pytest.raises(ValueError, match="BACKEND_AUDIT_BUILD_ID_REQUIRED"):
        phase2i.acquire_audit_writer_lease(
            phase2i.EXPECTED_CANDIDATE_ID,
            "KAG-2I-test-marker",
            "latest",
        )


def test_lease_release_requires_terminal_outcome() -> None:
    with pytest.raises(ValueError, match="LEASE_ID_AND_TERMINAL_OUTCOME_REQUIRED"):
        phase2i.release_audit_writer_lease("lease", "")


def test_budget_rejects_thirteenth_operation() -> None:
    with pytest.raises(ValidationError):
        Phase2IRealBackendBudget(accepted_operations=13)


def test_budget_rejects_external_provider_call() -> None:
    with pytest.raises(ValidationError):
        Phase2IRealBackendBudget(external_provider_calls=1)


def test_budget_rejects_provider_cost() -> None:
    with pytest.raises(ValidationError):
        Phase2IRealBackendBudget(provider_cost_usd=0.01)


def test_scenario_evidence_rejects_third_provider_attempt() -> None:
    with pytest.raises(ValidationError):
        AuditScenarioEvidence(
            run_marker="KAG-2I-test",
            operation_id="operation",
            scenario="wrong_then_wrong",
            attempt_count=3,
            event_states=[],
            output_languages=[],
            bounded=False,
            verdict="CONTRADICTED",
        )


def test_translation_cannot_claim_candidate_mutation() -> None:
    with pytest.raises(ValidationError):
        NetworkTranslationEvidence(
            request_id="request",
            original_url="http://127.0.0.1:8000/api/v1/captures",
            translated_url="http://127.0.0.1:18000/api/v1/captures",
            method="POST",
            path_and_query_preserved=True,
            body_sha256_before="a" * 64,
            body_sha256_after="a" * 64,
            normal_headers_preserved=True,
            audit_headers_added=[],
            candidate_bytes_modified=True,
            normal_chrome_storage_used=False,
            verdict="PROVEN",
        )


def test_translation_cannot_use_normal_chrome_storage() -> None:
    with pytest.raises(ValidationError):
        NetworkTranslationEvidence(
            request_id="request",
            original_url="http://127.0.0.1:8000/api/v1/captures",
            translated_url="http://127.0.0.1:18000/api/v1/captures",
            method="POST",
            path_and_query_preserved=True,
            body_sha256_before="a" * 64,
            body_sha256_after="a" * 64,
            normal_headers_preserved=True,
            audit_headers_added=[],
            candidate_bytes_modified=False,
            normal_chrome_storage_used=True,
            verdict="PROVEN",
        )


def test_runtime_identity_rejects_canonical_endpoint() -> None:
    with pytest.raises(ValidationError):
        BackendAuditRuntimeIdentity(
            endpoint="http://127.0.0.1:8000",
            process_id=1,
            executable="python",
            command=["python"],
            working_directory="runtime",
            backend_build_id="build",
            source_commit="a" * 40,
            source_manifest_sha256="a" * 64,
            build_input_sha256="a" * 64,
            contract_sha256="a" * 64,
            database="studypilot_kag_audit",
            migration_head="017",
            audit_schema_sha256="a" * 64,
            audit_mode=True,
            external_providers_disabled=True,
            auto_reload=False,
            observed_at=datetime.now(UTC),
            verdict="PROVEN",
        )


def test_stop_runtime_refuses_canonical_backend_pid(tmp_path: Path) -> None:
    owner = tmp_path / "owner.json"
    owner.write_text(
        json.dumps(
            {
                "schema_version": "kratos-guard.phase2i-runtime-owner.v1",
                "pid": 47612,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="CANONICAL_BACKEND_PROCESS_PROTECTED"):
        phase2i.stop_backend_audit_runtime(owner)


def test_runtime_creationflags_are_zero_outside_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(phase2i.sys, "platform", "linux")
    assert phase2i._runtime_creationflags() == 0


def test_suite_report_requires_phase2i_marker() -> None:
    with pytest.raises(ValidationError):
        IsolatedRealBackendSuiteReport.model_validate(
            {"schema_version": "kratos-guard.phase2i-report.v1", "run_marker": "KAG-2H"}
        )


class _IdentityWorker:
    def __init__(self, *, corrupt_fingerprint: bool = False) -> None:
        self.corrupt_fingerprint = corrupt_fingerprint

    def evaluate(self, _expression: str, values: list[str]) -> dict[str, object]:
        _token, user_id, token_hash = values
        if self.corrupt_fingerprint:
            token_hash = "0" * 64
        return {
            "identity": {
                "userId": user_id,
                "tokenRefOrHash": f"sha256:{token_hash}",
                "backendIssuer": phase2i_journeys.SEALED_BACKEND_ORIGIN,
                "extensionId": phase2i_journeys.EXTENSION_ID,
                "extensionVersion": "1.1.19",
                "buildHash": phase2i_journeys.RUNTIME_BUILD_HASH,
            },
            "changed": True,
            "previousRevision": None,
        }


def test_synthetic_runtime_identity_accepts_sealed_writer_contract() -> None:
    phase2i_journeys._seed_identity(  # noqa: SLF001
        _IdentityWorker(),  # type: ignore[arg-type]
        "synthetic-token",
        "synthetic-user",
    )


def test_synthetic_runtime_identity_rejects_wrong_token_fingerprint() -> None:
    with pytest.raises(RuntimeError, match="SYNTHETIC_RUNTIME_IDENTITY_WRITE_FAILED"):
        phase2i_journeys._seed_identity(  # noqa: SLF001
            _IdentityWorker(corrupt_fingerprint=True),  # type: ignore[arg-type]
            "synthetic-token",
            "synthetic-user",
        )
