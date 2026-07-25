"""Read-only inspection orchestration."""

from datetime import UTC, datetime
from pathlib import Path

from kratos_guard import __version__
from kratos_guard.adapters.git import git_value, run_git
from kratos_guard.adapters.process import port_accepts_connection
from kratos_guard.core.authority_gate import gate_result
from kratos_guard.core.policy import assert_target_unchanged, filesystem_snapshot
from kratos_guard.models import (
    EvidenceState,
    InspectionReport,
    Observation,
    TargetBuildIdentity,
    TargetRuntimeIdentity,
    TargetSourceIdentity,
    Uncertainty,
    VerifierIdentity,
)
from kratos_guard.projects.base import load_profile
from kratos_guard.projects.itzako.inspector import loaded_client_from_profile


def verifier_identity(repository: Path | None = None) -> VerifierIdentity:
    root_hint = repository or Path(__file__).resolve().parents[3]
    root = git_value(root_hint, ["rev-parse", "--show-toplevel"])
    repo = Path(root) if root else root_hint.resolve()
    common = git_value(repo, ["rev-parse", "--git-common-dir"])
    branch = git_value(repo, ["branch", "--show-current"])
    head = git_value(repo, ["rev-parse", "--verify", "HEAD"])
    dirty_evidence = run_git(repo, ["status", "--porcelain"])
    state = EvidenceState.PROVEN if root and common and head else EvidenceState.UNPROVEN
    return VerifierIdentity(
        repository_root=str(repo),
        git_common_directory=str((repo / common).resolve()) if common else "",
        branch=branch,
        head=head,
        dirty=bool(dirty_evidence.stdout),
        package_name="kratos-agent-guard",
        package_version=__version__,
        state=state,
    )


def inspect_target(target: Path, profile_name: str) -> InspectionReport:
    target = target.resolve()
    before = filesystem_snapshot(target)
    profile = load_profile(profile_name)
    now = datetime.now(UTC)
    root = git_value(target, ["rev-parse", "--show-toplevel"]) if target.exists() else ""
    repo = Path(root) if root else target
    common = git_value(repo, ["rev-parse", "--git-common-dir"]) if root else ""
    branch = git_value(repo, ["branch", "--show-current"]) if root else ""
    head = git_value(repo, ["rev-parse", "--verify", "HEAD"]) if root else ""
    status = run_git(repo, ["status", "--porcelain"]) if root else None
    source_state = EvidenceState.PROVEN if root and common and head else EvidenceState.UNPROVEN
    source = TargetSourceIdentity(
        path=str(target),
        repository_root=root,
        git_common_directory=str((repo / common).resolve()) if common else "",
        branch=branch,
        head=head,
        dirty=bool(status.stdout) if status else None,
        state=source_state,
    )
    observations = [
        Observation(
            subject="target_source",
            claim="path_exists",
            value=str(target.exists()).lower(),
            source="filesystem",
            observed_at=now,
        )
    ]
    uncertainties = [
        Uncertainty(
            subject="target_build",
            state=EvidenceState.UNPROVEN,
            reason="no independently observed build artefact was supplied",
            next_proof="supply a bounded build manifest or artefact path",
        )
    ]
    runtimes: list[TargetRuntimeIdentity] = []
    for component, values in profile["expected_components"].items():
        port = int(values["port"])
        listening = port_accepts_connection("127.0.0.1", port)
        runtimes.append(
            TargetRuntimeIdentity(
                component=str(component),
                endpoint=f"http://127.0.0.1:{port}",
                source_link_state=EvidenceState.UNPROVEN,
                build_link_state=EvidenceState.UNPROVEN,
                state=EvidenceState.UNPROVEN if listening else EvidenceState.INSPECTION_FAILED,
            )
        )
        observations.append(
            Observation(
                subject=f"target_runtime.{component}",
                claim="tcp_connection",
                value="accepted" if listening else "not_accepted",
                source="passive socket connection",
                observed_at=now,
            )
        )
    loaded_client = loaded_client_from_profile(profile)
    assert_target_unchanged(before, target)
    gate_state = (
        EvidenceState.PROVEN if source_state is EvidenceState.PROVEN else EvidenceState.UNPROVEN
    )
    return InspectionReport(
        verifier=verifier_identity(),
        target_source=source,
        target_build=TargetBuildIdentity(
            source_link_state=EvidenceState.UNPROVEN,
            state=EvidenceState.UNPROVEN,
        ),
        target_runtimes=runtimes,
        target_loaded_clients=[loaded_client],
        gate=gate_result(
            gate_state, "source authority proven" if root else "source authority unproven"
        ),
        observations=observations,
        uncertainties=uncertainties,
        target_write_count=0,
    )
