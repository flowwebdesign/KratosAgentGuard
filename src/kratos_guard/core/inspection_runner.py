"""Read-only provenance inspection orchestration."""

from datetime import UTC, datetime
from pathlib import Path

from kratos_guard import __version__
from kratos_guard.adapters.docker import inspect_containers
from kratos_guard.adapters.git import git_value, run_git
from kratos_guard.adapters.http import observe_http
from kratos_guard.adapters.runtime import inspect_listeners
from kratos_guard.core.artifacts import discover_artifacts, source_to_build_link
from kratos_guard.core.authority_gate import gate_result, qualified_gate
from kratos_guard.core.manifests import generate_manifest
from kratos_guard.core.mutation_witness import MutationWitness
from kratos_guard.models import (
    EvidenceState,
    InspectionReport,
    Observation,
    TargetBuildIdentity,
    TargetLoadedClientIdentity,
    TargetRuntimeIdentity,
    TargetSourceIdentity,
    Uncertainty,
    VerifierIdentity,
)
from kratos_guard.models.provenance import (
    ConfiguredExtensionIdentity,
    ProvenanceLink,
    RuntimeEvidence,
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
    dirty_evidence = run_git(repo, ["status", "--porcelain=v2", "--untracked-files=all"])
    state = EvidenceState.PROVEN if root and common and head else EvidenceState.UNPROVEN
    return VerifierIdentity(
        repository_root=str(repo),
        git_common_directory=str((repo / common).resolve()) if common else "",
        branch=branch,
        head=head,
        dirty=bool(dirty_evidence.stdout_excerpt),
        package_name="kratos-agent-guard",
        package_version=__version__,
        state=state,
    )


def inspect_target(
    target: Path, profile_name: str, level: str = "identity-chain"
) -> InspectionReport:
    target = target.resolve()
    profile = load_profile(profile_name)
    witness = MutationWitness(target, list(profile.get("mutation_sentinels", [])))
    now = datetime.now(UTC)
    root = git_value(target, ["rev-parse", "--show-toplevel"]) if target.exists() else ""
    repo = Path(root) if root else target
    common = git_value(repo, ["rev-parse", "--git-common-dir"]) if root else ""
    branch = git_value(repo, ["branch", "--show-current"]) if root else ""
    head = git_value(repo, ["rev-parse", "--verify", "HEAD"]) if root else ""
    status = run_git(repo, ["status", "--porcelain=v2", "--untracked-files=all"]) if root else None
    source_state = EvidenceState.PROVEN if root and common and head else EvidenceState.UNPROVEN
    source = TargetSourceIdentity(
        path=str(target),
        repository_root=root,
        git_common_directory=str((repo / common).resolve()) if common else "",
        branch=branch,
        head=head,
        dirty=bool(status.stdout_excerpt) if status else None,
        state=source_state,
    )
    source_manifest = generate_manifest(
        target,
        max_files=int(profile["limits"]["source_max_files"]),
        max_total_bytes=int(profile["limits"]["source_max_bytes"]),
        exclusions=set(profile.get("source_exclusions", [])),
    )
    artifacts, _ = discover_artifacts(target, profile)
    source_links = [source_to_build_link(source_manifest, artifact) for artifact in artifacts]
    ports = {int(values["port"]) for values in profile.get("expected_components", {}).values()}
    processes = inspect_listeners(ports)
    containers, container_errors = inspect_containers()
    runtime_links = [
        ProvenanceLink(
            link_type="BUILD_TO_RUNTIME",
            source_reference=artifact.manifest_sha256,
            destination_reference=str(process.pid),
            verdict=EvidenceState.UNPROVEN,
            reason=(
                "port, process command line, and version strings do not link exact artefact bytes"
            ),
        )
        for artifact in artifacts
        for process in processes
    ]
    runtime_evidence = RuntimeEvidence(
        processes=processes,
        containers=containers,
        links=runtime_links,
        errors=container_errors,
    )
    target_runtimes = [
        TargetRuntimeIdentity(
            component=component,
            endpoint=f"http://127.0.0.1:{int(values['port'])}",
            process_id=next(
                (
                    process.pid
                    for process in processes
                    if any(endpoint.port == int(values["port"]) for endpoint in process.endpoints)
                ),
                None,
            ),
            source_link_state=EvidenceState.UNPROVEN,
            build_link_state=EvidenceState.UNPROVEN,
            state=EvidenceState.PROVEN
            if any(
                endpoint.port == int(values["port"])
                for process in processes
                for endpoint in process.endpoints
            )
            else EvidenceState.INSPECTION_FAILED,
        )
        for component, values in profile.get("expected_components", {}).items()
    ]
    http_observations = [
        observe_http(endpoint["url"], endpoint["method"], endpoint["purpose"])
        for endpoint in profile.get("safe_http_endpoints", [])
    ]
    configured = ConfiguredExtensionIdentity(
        state=EvidenceState.UNPROVEN,
        limitations=[
            "No Chrome profile metadata was authorised for this run.",
            "Configured identity would not prove live loaded bytes.",
        ],
    )
    loaded_client: TargetLoadedClientIdentity = loaded_client_from_profile(profile)
    witness_result = witness.finish()
    contradictions = [
        link.reason for link in source_links if link.verdict is EvidenceState.CONTRADICTED
    ]
    if witness_result.changed:
        contradictions.append("TARGET_CHANGED_DURING_INSPECTION")
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
            subject="identity_chain",
            state=EvidenceState.UNPROVEN,
            reason="no sealed source-build-runtime-loaded-client chain was observed",
            next_proof="emit sealed build and runtime identity attestations",
        )
    ]
    report = InspectionReport(
        verifier=verifier_identity(),
        target_source=source,
        target_build=TargetBuildIdentity(
            build_id=artifacts[0].embedded_build_id if artifacts else "",
            artifact_path=artifacts[0].candidate.path if artifacts else "",
            source_link_state=source_links[0].verdict if source_links else EvidenceState.UNPROVEN,
            state=EvidenceState.PROVEN if artifacts else EvidenceState.UNPROVEN,
        ),
        target_runtimes=target_runtimes,
        target_loaded_clients=[loaded_client],
        gate=gate_result(
            EvidenceState.UNPROVEN,
            "IDENTITY_CHAIN_INSPECTION_IN_PROGRESS",
            gate_id="identity-chain",
            scope="identity-chain",
        ),
        observations=observations,
        uncertainties=uncertainties,
        target_write_count=0,
        source_manifest=source_manifest,
        build_artifacts=artifacts,
        source_to_build_links=source_links,
        runtime_evidence=runtime_evidence,
        build_to_runtime_links=runtime_links,
        configured_extensions=[configured],
        http_observations=http_observations,
        mutation_witness=witness_result,
        contradictions=contradictions,
        required_next_evidence=[
            "sealed build manifest containing exact source HEAD and source-manifest hash",
            "runtime-exposed or immutable image identity linked to artefact manifest",
            "independently collected live loaded-client evidence envelope",
        ],
        non_guarantees=[
            "HTTP health does not prove behaviour or source identity.",
            "Mutation witness is bounded and is not kernel-level write prevention.",
            "Configured extension identity does not prove live loaded bytes.",
        ],
        learning_summary=(
            "Hashes identify bytes; provenance requires independently evidenced links."
        ),
    )
    report.gate = qualified_gate(report, level)
    return report
