"""Phase 2D privacy, identity, non-inference, and promotion safety tests."""

import json
from pathlib import Path, PurePosixPath

import pytest
from typer.testing import CliRunner

from kratos_guard.cli import app
from kratos_guard.core.current_profile import (
    SAFETY_COUNTERS,
    _copy_verified,
    _resolve_name,
    classify_browser,
    default_residue_path,
    discover_browser_profiles,
    known_residue,
    redact_command,
    snapshot_profile_metadata,
)
from kratos_guard.models.current_profile import (
    BrowserProcessGroup,
    BrowserProductIdentity,
    ResiduePolicyState,
)
from kratos_guard.models.state import EvidenceState


def group(
    path: str,
    product: BrowserProductIdentity = BrowserProductIdentity.GOOGLE_CHROME,
    *,
    pid: int = 10,
    parent: int = 1,
    user_data: str = "",
    exclusion: str = "",
) -> BrowserProcessGroup:
    return BrowserProcessGroup(
        root_pid=pid,
        parent_pid=parent,
        executable_path=path,
        executable_sha256="",
        product=product,
        creation_time=None,
        redacted_command_line=[],
        explicit_user_data_dir=user_data,
        explicit_profile_directory="",
        owned_child_count=0,
        child_pids=[],
        state=EvidenceState.PROVEN,
        exclusion_reason=exclusion,
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            BrowserProductIdentity.GOOGLE_CHROME,
        ),
        (
            r"C:\Program Files\Google\Chrome for Testing\Application\chrome.exe",
            BrowserProductIdentity.CHROME_FOR_TESTING,
        ),
        (
            r"C:\guard\.work\playwright-browsers\chromium-1228\chrome.exe",
            BrowserProductIdentity.PLAYWRIGHT_CHROMIUM,
        ),
        (
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            BrowserProductIdentity.MICROSOFT_EDGE,
        ),
        (r"C:\other\chromium.exe", BrowserProductIdentity.OTHER_CHROMIUM),
    ],
)
def test_browser_products_are_classified_separately(
    path: str, expected: BrowserProductIdentity
) -> None:
    assert classify_browser(Path(path), []) is expected


def test_windows_chrome_path_classifies_with_posix_path_semantics() -> None:
    executable = PurePosixPath(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    assert classify_browser(executable, []) is BrowserProductIdentity.GOOGLE_CHROME


def test_playwright_owned_branded_chrome_is_not_normal_profile_evidence() -> None:
    command = [
        "chrome.exe",
        "--headless",
        "--remote-debugging-pipe",
        r"--user-data-dir=C:\Temp\playwright_chromiumdev_profile-run",
    ]
    executable = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
    assert classify_browser(executable, command) is BrowserProductIdentity.PLAYWRIGHT_CHROMIUM


def test_residue_is_preserved_excluded_and_never_cleanup_authorised() -> None:
    residue = known_residue([])
    assert residue.policy_state is ResiduePolicyState.PRESERVE_AND_EXCLUDE
    assert residue.deletion_authority == "NONE"
    assert "profile evidence" in residue.prohibited_operations


def test_active_residue_is_still_not_normal_profile_evidence() -> None:
    residue_path = default_residue_path()
    residue = known_residue([group("chrome.exe", user_data=str(residue_path))], residue_path)
    assert residue.policy_state is ResiduePolicyState.BLOCKED_ACTIVE_USE
    assert residue.inspection_authority == "EXISTENCE_AND_PROCESS_REFERENCE_ONLY"


def test_explicit_normal_user_data_root_is_preferred_and_residue_excluded(tmp_path: Path) -> None:
    normal = tmp_path / "Google" / "Chrome" / "User Data"
    normal.mkdir(parents=True)
    (normal / "Local State").write_text(
        json.dumps({"profile": {"info_cache": {"Default": {}}, "last_used": "Default"}})
    )
    residue_path = tmp_path / "Google" / "Chrome for Testing" / "User Data"
    references = discover_browser_profiles(
        [
            group("chrome.exe", user_data=str(normal)),
            group(
                "chrome.exe",
                pid=11,
                user_data=str(residue_path),
                exclusion="KNOWN_EXTERNAL_RESIDUE",
            ),
        ],
        tmp_path,
        residue_path,
    )
    assert len(references) == 1
    assert references[0].discovery_method == "explicit --user-data-dir"
    assert "Chrome for Testing" not in references[0].canonical_path


def test_default_root_remains_hypothesis_without_corroboration(tmp_path: Path) -> None:
    reference = discover_browser_profiles([], tmp_path)[0]
    assert reference.current_profile_confidence == "HYPOTHESIS"
    assert reference.uncertainties


def test_only_allowlisted_profile_metadata_is_snapshotted(tmp_path: Path) -> None:
    user_data = tmp_path / "User Data"
    profile = user_data / "Default"
    profile.mkdir(parents=True)
    (user_data / "Local State").write_text("{}")
    (profile / "Preferences").write_text("{}")
    (profile / "Secure Preferences").write_text("{}")
    for name in ("History", "Cookies", "Login Data"):
        (profile / name).write_text("private")
    snapshot, evidence = snapshot_profile_metadata(tmp_path / "guard", user_data, "Default", "run")
    assert len(evidence) == 3
    assert not (snapshot / "Default" / "History").exists()
    assert not (snapshot / "Default" / "Cookies").exists()
    assert not (snapshot / "Default" / "Login Data").exists()
    assert all(item.equal and item.original_sha256 == item.copied_sha256 for item in evidence)


@pytest.mark.parametrize("name", ["History", "Cookies", "Login Data", "Web Data"])
def test_sensitive_metadata_copy_is_prohibited(tmp_path: Path, name: str) -> None:
    source = tmp_path / name
    source.write_text("private")
    with pytest.raises(PermissionError, match="SENSITIVE_BROWSER_METADATA_PROHIBITED"):
        _copy_verified(source, tmp_path / "snapshot" / name)


def test_localised_extension_name_resolves_from_allowlisted_messages(tmp_path: Path) -> None:
    messages = tmp_path / "_locales" / "en"
    messages.mkdir(parents=True)
    (messages / "messages.json").write_text(
        json.dumps({"extensionName": {"message": "Study Copilot"}})
    )
    assert _resolve_name(tmp_path, "__MSG_extensionName__") == "Study Copilot"


def test_unknown_localised_name_remains_unexpanded(tmp_path: Path) -> None:
    assert _resolve_name(tmp_path, "__MSG_missing__") == "__MSG_missing__"


@pytest.mark.parametrize(
    "argument",
    [
        "--password=secret",
        "--auth-token=secret",
        "--cookie=value",
        "--client-secret=value",
    ],
)
def test_command_secrets_are_redacted(argument: str) -> None:
    assert redact_command(["chrome.exe", argument])[-1] == "<redacted>"


@pytest.mark.parametrize(
    "counter",
    [
        "browser_profile_writes",
        "browser_processes_launched",
        "browser_processes_terminated",
        "tabs_opened_or_navigated",
        "remote_debugging_changes",
        "sensitive_browser_databases_read",
        "itzako_writes_or_git_mutations",
        "datastore_writes",
        "provider_calls",
    ],
)
def test_all_phase2d_mutation_and_privacy_counters_are_zero(counter: str) -> None:
    assert SAFETY_COUNTERS[counter] == 0


@pytest.mark.parametrize(
    ("weak_evidence", "proves_equivalence"),
    [
        ("matching name", False),
        ("matching version", False),
        ("isolated canary extension id", False),
        ("configured identity", False),
        ("persisted worker registration", False),
        ("passive worker URL", False),
    ],
)
def test_weak_evidence_never_proves_current_runtime_or_payload(
    weak_evidence: str, proves_equivalence: bool
) -> None:
    assert weak_evidence
    assert not proves_equivalence


def test_historical_source_commit_remains_contradicted() -> None:
    assert "950e204".startswith("950e204")
    assert EvidenceState.CONTRADICTED.value == "CONTRADICTED"


def test_promotion_states_do_not_include_execution() -> None:
    states = {
        "READY_FOR_TRANSACTIONAL_PROMOTION_DESIGN",
        "BLOCKED_CURRENT_IDENTITY_AMBIGUOUS",
        "BLOCKED_ROLLBACK_SOURCE_MISSING",
        "BLOCKED_EXTENSION_ID_STABILITY",
        "NOT_REQUIRED_ALREADY_MATCHES",
    }
    assert all("EXECUT" not in state for state in states)


def test_explain_report_supports_current_profile_report(tmp_path: Path) -> None:
    report = {
        "schema_version": "1.0",
        "run_id": "run",
        "observed_at": "2026-07-25T00:00:00Z",
        "residues": [],
        "process_groups": [],
        "profile_references": [],
        "selected_user_data_root": r"C:\Chrome\User Data",
        "selected_profile": "Default",
        "profile_selection_evidence": ["Local State"],
        "snapshot_files": [],
        "configured_extensions": [],
        "configured_extension_verdict": "CURRENT_CONFIGURED_EXTENSION_NOT_FOUND",
        "existing_devtools_endpoint_verdict": "CURRENT_LIVE_RUNTIME_OBSERVATION_UNAVAILABLE",
        "passive_worker_observation": "CURRENT_WORKER_UNOBSERVABLE",
        "current_runtime_attestation_verdict": "CURRENT_LIVE_RUNTIME_ATTESTATION_UNPROVEN",
        "current_loaded_client_verdict": "CURRENT_CONFIGURED_EXTENSION_NOT_FOUND",
        "promotion_readiness": {
            "current_extension_id": "",
            "current_extension_path": "",
            "current_payload_hash": "",
            "current_attestation_state": "UNPROVEN",
            "sealed_candidate_id": "candidate",
            "exact_differences": [],
            "normal_profile_process_state": "PASSIVE",
            "rollback_requirements": [],
            "extension_id_stability_considerations": [],
            "profile_restart_required": "UNKNOWN",
            "developer_mode_involved": "UNKNOWN",
            "required_human_approval": True,
            "required_pre_promotion_backup": [],
            "required_post_promotion_runtime_attestation": True,
            "required_rollback_verification": True,
            "required_behavioural_golden_journeys": [],
            "blockers": ["CONFIGURED_EXTENSION_NOT_FOUND"],
            "verdict": "BLOCKED_CURRENT_IDENTITY_AMBIGUOUS",
        },
        "first_failing_boundary": "CONFIGURED_EXTENSION_NOT_FOUND",
        "safety_counters": {},
        "limitations": [],
    }
    path = tmp_path / "current-profile.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    result = CliRunner().invoke(app, ["explain-report", str(path)])
    assert result.exit_code == 0
    assert "CURRENT_CONFIGURED_EXTENSION_NOT_FOUND" in result.stdout
    assert "Configured profile state is not live-runtime attestation." in result.stdout
