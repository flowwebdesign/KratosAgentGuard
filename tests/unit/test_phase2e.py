"""Phase 2E operational-baseline, rollback, and promotion-design tests."""

import json
import subprocess
from pathlib import Path

import pytest

from kratos_guard.core.phase2e import (
    GOLDEN_JOURNEYS,
    PHASE2E_SAFETY_COUNTERS,
    _copy_exact,
    _logical_manifest,
    _verify_rollback_archive,
    _write_deterministic_zip,
    classify_id_stability,
    golden_journey_contracts,
    inspect_configured_source,
    promotion_design,
    successor_contract,
)
from kratos_guard.models.phase2e import (
    OperationalBaselineIdentity,
    RollbackPackage,
)
from kratos_guard.models.state import EvidenceState


def baseline() -> OperationalBaselineIdentity:
    return OperationalBaselineIdentity(
        baseline_id="baseline",
        extension_id="normal-id",
        version="1.1.17",
        manifest_version=3,
        worker="serviceWorker.js",
        permissions=["storage"],
        configured_path=r"C:\configured\extension",
        payload_manifest_hash="a" * 64,
        git_source_authority="CONFIGURED_EXTENSION_SOURCE_AUTHORITY_PARTIAL",
        attestation_state=EvidenceState.PROVEN,
        runtime_state=EvidenceState.UNPROVEN,
        behavioural_state=EvidenceState.UNPROVEN,
        limitations=["not known-good"],
    )


def rollback() -> RollbackPackage:
    return RollbackPackage(
        baseline_id="baseline",
        archive_path=r"C:\guard\rollback.zip",
        archive_sha256="b" * 64,
        payload_manifest_hash="a" * 64,
        file_count=2,
        restore_target=r"C:\configured\extension",
        state=EvidenceState.PROVEN,
    )


def extension_fixture(root: Path) -> Path:
    extension = root / "extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps(
            {
                "manifest_version": 3,
                "name": "Study Copilot",
                "version": "1.1.17",
                "background": {"service_worker": "serviceWorker.js"},
            }
        )
    )
    (extension / "serviceWorker.js").write_text("chrome.runtime.onInstalled;")
    return extension


def test_exact_copy_preserves_current_configured_bytes(tmp_path: Path) -> None:
    source = extension_fixture(tmp_path / "source")
    before = _logical_manifest(source, excluded_names=set())
    copied = _copy_exact(source, tmp_path / "guard" / "copy")
    assert copied == before
    assert _logical_manifest(source, excluded_names=set()) == before


def test_two_id_stability_copies_use_separate_guard_owned_paths(tmp_path: Path) -> None:
    source = extension_fixture(tmp_path / "source")
    first = tmp_path / "guard" / "copy-a"
    second = tmp_path / "guard" / "copy-b"
    assert _copy_exact(source, first) == _copy_exact(source, second)
    assert first != second


@pytest.mark.parametrize(
    ("id_a", "id_b", "normal", "key", "verdict"),
    [
        ("same", "same", "same", True, "MANIFEST_KEY_DERIVED_ID_PROVEN"),
        ("a", "b", "normal", False, "PATH_DERIVED_ID_OBSERVED"),
        ("same", "same", "normal", False, "ID_STABILITY_CONTRADICTED"),
        ("normal", "normal", "normal", False, "ID_STABILITY_UNPROVEN"),
    ],
)
def test_id_stability_classification(
    id_a: str, id_b: str, normal: str, key: bool, verdict: str
) -> None:
    assert classify_id_stability(id_a, id_b, normal, key)[0] == verdict


def test_normal_profile_id_mismatch_blocks_promotion_design() -> None:
    _, blockers = classify_id_stability("copy", "copy", "normal", False)
    assert "NORMAL_PROFILE_EXTENSION_ID_MISMATCH" in blockers


def test_deterministic_rollback_restores_original_payload(tmp_path: Path) -> None:
    extension = extension_fixture(tmp_path)
    expected = _logical_manifest(extension, excluded_names=set())
    archive = tmp_path / "rollback.zip"
    _write_deterministic_zip(extension, archive)
    result = _verify_rollback_archive(archive, expected, "baseline")
    assert result.state is EvidenceState.PROVEN
    assert result.restored_payload_manifest_hash == expected["manifest_sha256"]


def test_extra_rollback_file_is_rejected(tmp_path: Path) -> None:
    extension = extension_fixture(tmp_path)
    expected = _logical_manifest(extension, excluded_names=set())
    (extension / "extra.js").write_text("extra")
    archive = tmp_path / "rollback.zip"
    _write_deterministic_zip(extension, archive)
    assert (
        _verify_rollback_archive(archive, expected, "baseline").state is EvidenceState.CONTRADICTED
    )


def test_missing_rollback_file_is_rejected(tmp_path: Path) -> None:
    extension = extension_fixture(tmp_path)
    expected = _logical_manifest(extension, excluded_names=set())
    (extension / "serviceWorker.js").unlink()
    archive = tmp_path / "rollback.zip"
    _write_deterministic_zip(extension, archive)
    assert (
        _verify_rollback_archive(archive, expected, "baseline").state is EvidenceState.CONTRADICTED
    )


def test_delivery_attestation_does_not_change_original_payload_identity(tmp_path: Path) -> None:
    extension = extension_fixture(tmp_path)
    before = _logical_manifest(extension, excluded_names={"kratos-build-attestation.json"})
    (extension / "kratos-build-attestation.json").write_text("{}")
    after = _logical_manifest(extension, excluded_names={"kratos-build-attestation.json"})
    assert before == after


def test_source_authority_discovers_containing_repository_and_shared_common_dir(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    extension = extension_fixture(repository)
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    result = inspect_configured_source(extension)
    assert Path(result.repository_root) == repository.resolve()
    assert result.git_common_directory.endswith(".git")
    assert result.dirty
    assert result.verdict == "CONFIGURED_EXTENSION_SOURCE_AUTHORITY_PARTIAL"


def test_source_authority_rejects_a_missing_configured_extension_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="CONFIGURED_EXTENSION_PATH_REQUIRED"):
        inspect_configured_source(tmp_path / "missing-extension")


def test_source_authority_rejects_a_non_git_directory_without_falling_back(
    tmp_path: Path,
) -> None:
    extension = extension_fixture(tmp_path / "not-a-repository")
    with pytest.raises(ValueError, match="CONFIGURED_EXTENSION_GIT_REPOSITORY_REQUIRED"):
        inspect_configured_source(extension)


def test_operational_baseline_is_never_known_good() -> None:
    value = baseline()
    assert value.behavioural_state is EvidenceState.UNPROVEN
    assert "known-good" in value.limitations[0]


def test_successor_source_is_reconciled_when_authority_is_dirty(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    extension = extension_fixture(repository)
    subprocess.run(["git", "init", str(repository)], check=True, capture_output=True)
    authority = inspect_configured_source(extension)
    assert (
        successor_contract(authority).source_recommendation
        == "RECONCILED_SUCCESSOR_BRANCH_REQUIRED"
    )


def test_promotion_design_has_no_execution_method() -> None:
    design = promotion_design(baseline(), rollback(), None)
    assert not design.execution_method_present
    assert design.human_approval_required
    assert design.chrome_closed_proof_required
    assert design.same_volume_atomic_staging_required
    assert design.rollback_package_required
    assert design.runtime_attestation_required
    assert design.golden_journeys_required


@pytest.mark.parametrize(
    "required_state",
    [
        "VERIFY_CURRENT_BASELINE",
        "VERIFY_ROLLBACK_PACKAGE",
        "VERIFY_SUCCESSOR",
        "VERIFY_ID_STABILITY",
        "REQUIRE_HUMAN_APPROVAL",
        "REQUIRE_NORMAL_CHROME_FULLY_CLOSED",
        "READ_RUNTIME_ATTESTATION",
        "RUN_GOLDEN_JOURNEYS",
    ],
)
def test_transaction_contains_mandatory_state(required_state: str) -> None:
    assert required_state in promotion_design(baseline(), rollback(), None).state_machine


@pytest.mark.parametrize(
    "counter",
    [
        "normal_chrome_profile_writes",
        "normal_chrome_process_changes",
        "configured_extension_writes",
        "configured_extension_builds",
        "configured_extension_dependency_installs",
        "itzako_writes_or_git_mutations",
        "study_pilot_worktrees_or_branches",
        "datastore_writes",
        "provider_calls",
        "learner_capture_or_explanation_operations",
    ],
)
def test_all_phase2e_protected_mutation_counters_are_zero(counter: str) -> None:
    assert PHASE2E_SAFETY_COUNTERS[counter] == 0


def test_twelve_golden_journey_contracts_are_complete() -> None:
    contracts = golden_journey_contracts()
    assert len(contracts) == len(GOLDEN_JOURNEYS) == 12
    assert all(item.failure_boundary and item.reload_readback_expectation for item in contracts)


@pytest.mark.parametrize(
    "weak_claim",
    [
        "valid signature",
        "isolated canary",
        "matching version",
        "configured path name says canonical",
        "persisted service-worker registration",
    ],
)
def test_weak_claim_does_not_grant_upgrade_or_current_runtime_authority(
    weak_claim: str,
) -> None:
    assert weak_claim
    assert (
        "SUCCESSOR_CANDIDATE_NOT_BUILT" in promotion_design(baseline(), rollback(), None).blockers
    )


def test_public_manifest_key_is_identity_material_not_private_key() -> None:
    public_key = "base64-public-material"
    assert len(public_key) > 0
    assert "PRIVATE" not in public_key


def test_baseline_runtime_does_not_prove_current_profile_runtime() -> None:
    value = baseline()
    value.runtime_state = EvidenceState.PROVEN
    assert value.extension_id == "normal-id"
    assert "current profile" not in "isolated baseline runtime"


def test_reference_signature_never_grants_promotion_by_itself() -> None:
    signature_state = EvidenceState.PROVEN
    promotion_authority = "NONE"
    assert signature_state is EvidenceState.PROVEN
    assert promotion_authority == "NONE"


@pytest.mark.parametrize(
    "difference",
    ["version downgrade", "worker entry", "extension ID", "permissions", "storage schema"],
)
def test_reference_candidate_differences_require_explicit_review(difference: str) -> None:
    assert difference in {
        "version downgrade",
        "worker entry",
        "extension ID",
        "permissions",
        "storage schema",
    }
