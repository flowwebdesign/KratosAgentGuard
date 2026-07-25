from kratos_guard.models import (
    EvidenceState,
    TargetLoadedClientIdentity,
    TargetSourceIdentity,
    VerifierIdentity,
)


def test_loaded_target_is_not_verifier_build() -> None:
    verifier = VerifierIdentity(
        repository_root="guard",
        git_common_directory="guard/.git",
        branch="main",
        head="abc",
        dirty=False,
        package_name="kratos-agent-guard",
        package_version="0.1.0",
        state=EvidenceState.PROVEN,
    )
    loaded = TargetLoadedClientIdentity(
        client_type="chrome_extension",
        build_id="extension-1.1.17-8e9f11feeaa6f684",
        provenance="prior context",
        source_link_state=EvidenceState.UNPROVEN,
        build_link_state=EvidenceState.UNPROVEN,
        state=EvidenceState.UNPROVEN,
    )
    assert verifier.package_version not in loaded.build_id
    assert loaded.state is EvidenceState.UNPROVEN


def test_verifier_and_target_repositories_are_independent() -> None:
    target = TargetSourceIdentity(
        path="target", repository_root="target", state=EvidenceState.PROVEN
    )
    assert target.repository_root != "guard"


def test_unknown_loaded_extension_is_unproven() -> None:
    loaded = TargetLoadedClientIdentity(
        client_type="chrome_extension",
        provenance="none",
        source_link_state=EvidenceState.UNPROVEN,
        build_link_state=EvidenceState.UNPROVEN,
        state=EvidenceState.UNPROVEN,
    )
    assert loaded.state is EvidenceState.UNPROVEN
