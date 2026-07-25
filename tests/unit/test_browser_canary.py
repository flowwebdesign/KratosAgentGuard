from pathlib import Path

import pytest

from kratos_guard.core.browser_canary import (
    _assert_no_link_escape,
    _command_hash,
    cleanup_guard_profile,
    plan_extension_canary,
)
from kratos_guard.models import EvidenceState
from kratos_guard.models.canary import (
    BrowserExecutableIdentity,
    CurrentUserRuntimeObservation,
    RuntimeChainVerification,
    RuntimeProofScope,
)


def browser(tmp_path: Path) -> BrowserExecutableIdentity:
    executable = tmp_path / "chrome.exe"
    executable.write_bytes(b"browser")
    from kratos_guard.core.hashing import hash_file

    return BrowserExecutableIdentity(
        product="Test Chromium",
        executable_path=str(executable),
        executable_sha256=hash_file(executable).digest,
        file_version="1",
        architecture="x86_64",
        discovery_method="fixture",
        state=EvidenceState.PROVEN,
        uncertainties=[],
    )


def candidate(guard: Path) -> Path:
    root = guard / ".work" / "candidates" / "candidate"
    extension = root / "artefact" / "extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text("{}", encoding="utf-8")
    return root


def test_guard_owned_profile_path_is_accepted(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    policy = plan_extension_canary(guard, candidate(guard), browser(tmp_path), run_id="run")
    assert Path(policy.user_data_directory).is_relative_to(guard / ".work" / "browser-canaries")


@pytest.mark.parametrize(
    "outside",
    [
        Path(r"C:\Users\person\AppData\Local\Google\Chrome\User Data"),
        Path(r"C:\Users\person\AppData\Local\Microsoft\Edge\User Data"),
        Path(r"C:\temporary-profile"),
    ],
)
def test_normal_or_external_profile_paths_are_rejected(tmp_path: Path, outside: Path) -> None:
    with pytest.raises(PermissionError):
        _assert_no_link_escape(outside, tmp_path / "guard" / ".work" / "browser-canaries")


def test_candidate_outside_guard_workspace_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    (outside / "artefact" / "extension").mkdir(parents=True)
    with pytest.raises(PermissionError):
        plan_extension_canary(tmp_path / "guard", outside, browser(tmp_path))


def test_symlink_escape_is_rejected_when_supported(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(PermissionError):
        _assert_no_link_escape(link, root)


def test_browser_executable_hash_drift_blocks_plan(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    identity = browser(tmp_path)
    Path(identity.executable_path).write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="BROWSER_EXECUTABLE_CHANGED"):
        plan_extension_canary(guard, candidate(guard), identity)


def test_persistent_context_rejects_external_debugging_port(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    with pytest.raises(ValueError, match="persistent-context"):
        plan_extension_canary(
            guard,
            candidate(guard),
            browser(tmp_path),
            debugging_port=9222,
        )


def test_persistent_context_and_exact_extension_are_recorded(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    policy = plan_extension_canary(guard, candidate(guard), browser(tmp_path))
    assert policy.debugging_port == 0
    assert policy.command_line[0] == "playwright.chromium.launch_persistent_context"
    assert "channel=chromium" in policy.command_line
    assert f"--load-extension={policy.extension_path}" in policy.command_line
    assert policy.command_line_sha256 == _command_hash(policy.command_line)


def test_branded_chrome_is_classified_as_sideload_unsupported(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    identity = browser(tmp_path).model_copy(
        update={"product": "Google Chrome", "file_version": "150.0.0.0"}
    )
    with pytest.raises(PermissionError, match="BROWSER_SIDELOAD_CAPABILITY_UNSUPPORTED"):
        plan_extension_canary(guard, candidate(guard), identity)
    assert int(identity.file_version.split(".")[0]) >= 137


def test_plan_records_candidate_witness_for_prelaunch_tamper_detection(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    sealed = candidate(guard)
    policy = plan_extension_canary(guard, sealed, browser(tmp_path))
    before = policy.candidate_manifest_sha256
    (sealed / "artefact" / "extension" / "manifest.json").write_text(
        '{"tampered":true}', encoding="utf-8"
    )
    from kratos_guard.core.browser_canary import candidate_manifest

    assert candidate_manifest(sealed) != before


def test_process_creation_alone_does_not_prove_loaded_extension() -> None:
    scopes = {
        RuntimeProofScope.SEALED_CANDIDATE_ON_DISK: EvidenceState.PROVEN,
        RuntimeProofScope.GUARD_LAUNCHED_BROWSER_PROCESS: EvidenceState.PROVEN,
        RuntimeProofScope.ISOLATED_CANARY_LOADED_EXTENSION: EvidenceState.UNPROVEN,
        RuntimeProofScope.CURRENT_USER_LOADED_EXTENSION: EvidenceState.UNPROVEN,
        RuntimeProofScope.PROMOTED_EXTENSION: EvidenceState.NOT_APPLICABLE,
        RuntimeProofScope.PRODUCT_BEHAVIOUR: EvidenceState.NOT_APPLICABLE,
    }
    result = RuntimeChainVerification(
        scope_states=scopes,
        source_to_build_state=EvidenceState.PROVEN,
        build_to_runtime_state=EvidenceState.UNPROVEN,
        loaded_client_state=EvidenceState.UNPROVEN,
        current_user_loaded_client_state=EvidenceState.UNPROVEN,
        first_failing_boundary="runtime-attestation-readback",
        contradictions=[],
        uncertainties=[],
        verdict="BROWSER_PROCESS_PROVEN_LOADED_EXTENSION_UNPROVEN",
    )
    assert result.build_to_runtime_state is EvidenceState.UNPROVEN


def test_isolated_canary_proof_cannot_satisfy_current_loaded_client() -> None:
    observation = CurrentUserRuntimeObservation(
        preexisting_browser_pids=[10],
        post_canary_browser_pids=[10],
        overlapping_canary_pids=[],
        loaded_extension_state=EvidenceState.UNPROVEN,
        reason="no authorised non-mutating live extension readback",
        state=EvidenceState.PROVEN,
    )
    assert observation.loaded_extension_state is EvidenceState.UNPROVEN


def test_canary_policy_never_adopts_existing_pid(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    policy = plan_extension_canary(guard, candidate(guard), browser(tmp_path))
    assert not hasattr(policy, "existing_pid")


def test_canary_command_has_blank_target_and_blackhole_proxy(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    policy = plan_extension_canary(guard, candidate(guard), browser(tmp_path))
    assert "--proxy-server=http://127.0.0.1:9" in policy.command_line
    assert not any("http://" in item and "127.0.0.1:9" not in item for item in policy.command_line)


def test_profile_cleanup_path_cannot_escape_guard_work(tmp_path: Path) -> None:
    with pytest.raises(PermissionError):
        _assert_no_link_escape(
            tmp_path / "outside", tmp_path / "guard" / ".work" / "browser-canaries"
        )


def test_guard_owned_profile_cleanup_records_evidence(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    profile = guard / ".work" / "browser-canaries" / "old-run" / "profile"
    profile.mkdir(parents=True)
    (profile / "state").write_text("temporary", encoding="utf-8")
    result = cleanup_guard_profile(guard, profile)
    assert result["removed"] is True
    assert not profile.exists()
    assert Path(str(result["evidence_path"])).is_file()


def test_active_guard_profile_cannot_be_cleaned(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    profile = guard / ".work" / "browser-canaries" / "active" / "profile"
    profile.mkdir(parents=True)
    with pytest.raises(PermissionError, match="active"):
        cleanup_guard_profile(guard, profile, active_profile=profile)
