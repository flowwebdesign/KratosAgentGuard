"""Kratos Agent Guard command line interface."""

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from pydantic import BaseModel

from kratos_guard.adapters.docker import inspect_containers
from kratos_guard.adapters.git import git_value
from kratos_guard.adapters.runtime import inspect_listeners
from kratos_guard.core.artifacts import discover_artifacts
from kratos_guard.core.authority_gate import qualified_gate
from kratos_guard.core.bootstrap_gate import BootstrapFacts, bootstrap_verdict
from kratos_guard.core.browser_canary import (
    cleanup_guard_profile,
    discover_browsers,
    plan_extension_canary,
    run_extension_canary,
    verify_runtime_readback,
)
from kratos_guard.core.current_profile import (
    discover_browser_processes,
    discover_browser_profiles,
    inspect_current_profile,
)
from kratos_guard.core.inspection_runner import inspect_target, verifier_identity
from kratos_guard.core.loaded_evidence import validate_envelope
from kratos_guard.core.manifests import generate_manifest
from kratos_guard.core.operations import (
    create_ledger_checkpoint,
    default_configuration_path,
    export_evidence_bundle,
    import_evidence_bundle,
    initialise_configuration,
    load_configuration,
    monitor_health,
    register_folder,
    remove_folder,
    run_monitor,
    verify_evidence_bundle,
    write_service_template,
)
from kratos_guard.core.path_security import ProtectedPath, SafeOutputPolicy
from kratos_guard.core.phase2e import (
    canary_current_baseline,
    classify_reference_candidate,
    inspect_configured_source,
    load_phase2e_config,
    promotion_design,
    seal_current_baseline,
    test_extension_id_stability,
    verify_current_baseline,
)
from kratos_guard.core.phase2f import (
    build_compat_successor,
    compare_successor_baseline,
    create_isolated_reconciliation,
    map_configured_extension_source,
    select_reconciliation_base,
    verify_lineage_attestation,
    verify_reconciliation_workspace,
)
from kratos_guard.core.phase2g import (
    analyse_behavioural_impact,
    bundle_behavioural_lineage,
    compare_behavioural_successor,
    import_successor_bundle,
    run_offline_golden_journeys,
)
from kratos_guard.core.phase2h import (
    classify_protected_target_drift,
    inspect_backend_contract,
    plan_real_backend_journeys,
    run_real_backend_journeys,
    verify_database_readback,
    verify_provider_test_seam,
    verify_real_backend_report,
    verify_synthetic_audit_identity,
)
from kratos_guard.core.phase2i import (
    acquire_audit_writer_lease,
    bundle_backend_audit_lineage,
    inspect_audit_writer_leases,
    inspect_backend_audit_authority,
    inspect_backend_audit_build,
    inspect_backend_audit_runtime,
    release_audit_writer_lease,
    start_backend_audit_runtime,
    stop_backend_audit_runtime,
    verify_audit_provider_scenarios,
    verify_backend_audit_database,
    verify_phase2i_synthetic_audit_identity,
)
from kratos_guard.core.phase2i_journeys import (
    explain_phase2i_report,
    plan_isolated_real_backend_journeys,
    run_isolated_real_backend_journeys,
    verify_phase2i_report,
)
from kratos_guard.core.sealed_build import (
    build_input_manifest,
    build_sealed_candidate,
    candidate_identifier,
    compare_candidates,
    component_build_definition,
    snapshot_component,
    update_reproducibility,
    verify_candidate,
)
from kratos_guard.core.signing import (
    export_public_key,
    export_trust_bundle,
    initialise_key,
    inspect_key,
    local_trust_directory,
    revoke_key,
    rotate_key,
    verify_key_rotation,
)
from kratos_guard.core.standalone import (
    append_ledger_entry,
    compare_folder_snapshots,
    create_synthetic_runtime_statement,
    issue_runtime_challenge,
    snapshot_folder,
    verify_ledger,
    verify_runtime_statement,
)
from kratos_guard.models import CanaryReport, InspectionReport
from kratos_guard.models.build import BuildAttestation
from kratos_guard.models.current_profile import CurrentProfileIdentityReport
from kratos_guard.models.phase2e import Phase2EReport
from kratos_guard.models.phase2f import (
    IsolatedCloneIdentity,
    Phase2FReport,
    ReconciliationLineage,
)
from kratos_guard.models.standalone import (
    FolderSnapshot,
    RuntimeChallenge,
    RuntimeStatement,
    StandaloneStatus,
)
from kratos_guard.projects.base import load_profile
from kratos_guard.reporting.json_report import render_json, write_json
from kratos_guard.reporting.markdown_report import render_markdown
from kratos_guard.reporting.redaction import redact

app = typer.Typer(no_args_is_help=True)
key_app = typer.Typer(no_args_is_help=True)
browser_app = typer.Typer(no_args_is_help=True)
canary_app = typer.Typer(no_args_is_help=True)
ledger_app = typer.Typer(no_args_is_help=True)
attestation_app = typer.Typer(no_args_is_help=True)
monitor_app = typer.Typer(no_args_is_help=True)
standalone_app = typer.Typer(no_args_is_help=True)
folder_app = typer.Typer(no_args_is_help=True)
evidence_app = typer.Typer(no_args_is_help=True)
app.add_typer(key_app, name="key")
app.add_typer(browser_app, name="browser")
app.add_typer(canary_app, name="canary")
app.add_typer(ledger_app, name="ledger")
app.add_typer(attestation_app, name="attestation")
app.add_typer(monitor_app, name="monitor")
app.add_typer(standalone_app, name="standalone")
standalone_app.add_typer(folder_app, name="folder")
standalone_app.add_typer(evidence_app, name="evidence")


def _guard_root() -> Path:
    return Path(verifier_identity().repository_root)


def _output_policy(target: Path) -> SafeOutputPolicy:
    target = target.resolve()
    common = git_value(target, ["rev-parse", "--git-common-dir"])
    common_path = (target / common).resolve() if common else target / ".git"
    return SafeOutputPolicy(
        verifier_root=str(_guard_root()),
        protected_paths=[
            ProtectedPath(path=str(target), reason="inspected target root"),
            ProtectedPath(path=str(common_path), reason="target Git common directory"),
        ],
    )


def _guard_output(path: Path) -> Path:
    policy = SafeOutputPolicy(verifier_root=str(_guard_root()))
    return policy.require_safe(path)


def _write_model(path: Path, model: BaseModel) -> None:
    destination = _guard_output(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = model.model_dump_json(indent=2)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(rendered + "\n")
        stream.flush()
        os.fsync(stream.fileno())


@app.command()
def bootstrap_check(path: Path | None = None) -> None:
    path = path or Path.cwd()
    identity = verifier_identity(path)
    origin = git_value(path, ["remote", "get-url", "origin"]) if (path / ".git").exists() else ""
    if identity.git_common_directory and origin:
        expected = "https://github.com/flowwebdesign/KratosAgentGuard"
        verdict = "PASS_ESTABLISHED" if origin == expected else "BLOCKED_REMOTE_AUTHORITY"
        typer.echo(
            json.dumps(
                {
                    "verdict": verdict,
                    "path": str(path.resolve()),
                    "git_common_directory": identity.git_common_directory,
                    "origin": origin,
                }
            )
        )
        return
    entries = tuple(item.name for item in path.iterdir() if item.name != ".git")
    facts = BootstrapFacts(
        remote_matches=True,
        remote_empty=True,
        local_path=path,
        local_entries=entries,
        inside_target_worktree=False,
    )
    typer.echo(json.dumps({"verdict": bootstrap_verdict(facts), "path": str(path.resolve())}))


@app.command()
def validate_config(profile: str = "itzako") -> None:
    loaded = load_profile(profile)
    typer.echo(json.dumps({"profile": loaded["name"], "valid": True}))


@app.command("source-manifest")
def source_manifest(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    loaded = load_profile(profile)
    manifest = generate_manifest(
        target,
        max_files=int(loaded["limits"]["source_max_files"]),
        max_total_bytes=int(loaded["limits"]["source_max_bytes"]),
        exclusions=set(loaded.get("source_exclusions", [])),
    )
    typer.echo(render_json(manifest))


@app.command("discover-artifacts")
def discover_artifact_command(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    artifacts, _ = discover_artifacts(target, load_profile(profile))
    typer.echo(json.dumps(redact([item.model_dump(mode="json") for item in artifacts]), indent=2))


@app.command("inspect-runtime")
def inspect_runtime(profile: str = "itzako") -> None:
    loaded = load_profile(profile)
    ports = {int(value["port"]) for value in loaded["expected_components"].values()}
    processes = inspect_listeners(ports)
    containers, errors = inspect_containers()
    typer.echo(
        json.dumps(
            redact(
                {
                    "processes": [item.model_dump(mode="json") for item in processes],
                    "containers": [item.model_dump(mode="json") for item in containers],
                    "errors": errors,
                }
            ),
            indent=2,
        )
    )


@app.command()
def inspect(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
    level: Annotated[str, typer.Option()] = "identity-chain",
    output: Annotated[Path | None, typer.Option()] = None,
) -> None:
    safe_output = _output_policy(target).require_safe(output) if output else None
    report = inspect_target(target, profile, level)
    if safe_output:
        write_json(report, safe_output)
    typer.echo(render_json(report))


@app.command()
def gate(
    level: Annotated[str, typer.Option(help="source, build, runtime, or loaded-client")],
    target: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    profile: Annotated[str, typer.Option()] = "itzako",
    candidate: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
) -> None:
    current_levels = {
        "current-profile-path",
        "current-configured-client",
        "current-worker",
        "current-runtime-attestation",
        "promotion-readiness",
    }
    if level in current_levels:
        if candidate is None:
            raise typer.BadParameter("--candidate is required for current-profile gates")
        current_report = inspect_current_profile(_guard_root(), candidate)
        state = "PROVEN"
        if level == "current-profile-path":
            reason = "CURRENT_PROFILE_PATH_PROVEN"
        elif (
            level == "current-configured-client" and len(current_report.configured_extensions) == 1
        ):
            reason = "CURRENT_CONFIGURED_EXTENSION_PROVEN"
        elif level == "promotion-readiness":
            reason = current_report.promotion_readiness.verdict
        else:
            state = "UNPROVEN"
            reason = (
                current_report.passive_worker_observation
                if level == "current-worker"
                else current_report.current_runtime_attestation_verdict
            )
        typer.echo(
            json.dumps(
                {
                    "gate_id": level,
                    "state": state,
                    "reason": reason,
                    "first_failing_boundary": ""
                    if state == "PROVEN"
                    else current_report.first_failing_boundary,
                },
                indent=2,
            )
        )
        raise typer.Exit(0 if state == "PROVEN" else 2)
    if level == "canary-runtime":
        if candidate is None:
            raise typer.BadParameter("--candidate is required for canary-runtime")
        reports = sorted(
            (_guard_root() / "evidence" / "inspections").glob("canary-*.json"),
            key=lambda item: item.stat().st_mtime_ns,
        )
        matching = [
            CanaryReport.model_validate_json(item.read_text(encoding="utf-8"))
            for item in reports
            if json.loads(item.read_text(encoding="utf-8"))
            .get("candidate_identity", {})
            .get("candidate_id")
            == candidate.name
        ]
        proven = bool(
            matching and matching[-1].runtime_verification.build_to_runtime_state.value == "PROVEN"
        )
        typer.echo(
            json.dumps(
                {
                    "gate_id": "canary-runtime",
                    "state": "PROVEN" if proven else "UNPROVEN",
                    "scope": "ISOLATED_CANARY_LOADED_EXTENSION",
                    "first_failing_boundary": "" if proven else "runtime-evidence",
                },
                indent=2,
            )
        )
        raise typer.Exit(0 if proven else 2)
    if level == "current-loaded-client":
        typer.echo(
            json.dumps(
                {
                    "gate_id": "current-loaded-client",
                    "state": "UNPROVEN",
                    "scope": "CURRENT_USER_LOADED_EXTENSION",
                    "reason": "no authorised non-mutating live extension readback",
                },
                indent=2,
            )
        )
        raise typer.Exit(2)
    if target is None:
        raise typer.BadParameter("--target is required for this gate level")
    report = inspect_target(target, profile, level)
    result = qualified_gate(report, level)
    typer.echo(render_json(result))
    raise typer.Exit(result.exit_code)


@app.command()
def explain_report(
    report_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    payload = report_path.read_text(encoding="utf-8")
    if '"schema_version": "kratos-guard.phase2i-report.v1"' in payload:
        typer.echo(json.dumps(explain_phase2i_report(report_path), indent=2, sort_keys=True))
    elif '"phase": "2H"' in payload:
        phase2h_report = json.loads(payload)
        budget = phase2h_report["budget"]
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard Phase 2H real-backend journeys",
                    "",
                    f"Qualified verdict: {phase2h_report['final_verdict']}",
                    f"Candidate: {phase2h_report['candidate_id']}",
                    "Backend contract: " + phase2h_report["backend_contract"]["verdict"],
                    "Synthetic identity: " + phase2h_report["synthetic_identity"]["verdict"],
                    f"Provider seam: {phase2h_report['provider_seam']['verdict']}",
                    "Database readback: " + phase2h_report["database_readback"]["verdict"],
                    "Accepted backend operations: " + str(budget["backend_operations_accepted"]),
                    f"Real provider calls: {phase2h_report['real_provider_calls']}",
                    f"Normal Chrome mutations: {phase2h_report['normal_chrome_mutations']}",
                    f"Promotion authority: {phase2h_report['promotion_authority']}",
                    f"First blocker: {phase2h_report['first_remaining_blocker']}",
                    "",
                    "A blocked dispatch report proves the safety gate, not real-backend "
                    "journey success.",
                ]
            )
        )
    elif '"phase": "2G"' in payload:
        phase2g_report = json.loads(payload)
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard Phase 2G behavioural successor",
                    "",
                    f"Qualified verdict: {phase2g_report['final_verdict']}",
                    f"Authorised fix: {phase2g_report['authorised_fix']}",
                    f"Durable source: {phase2g_report['development_repository']}",
                    f"Development commit: {phase2g_report['development_commit']}",
                    f"Candidate: {phase2g_report['candidate_id']}",
                    f"Isolated runtime: {phase2g_report['isolated_runtime']}",
                    f"Offline journeys: {phase2g_report['offline_journeys']}",
                    f"Behavioural delta: {phase2g_report['behavioural_delta']}",
                    f"Real backend: {phase2g_report['real_backend']}",
                    f"Promotion authority: {phase2g_report['promotion_authority']}",
                    f"First blocker: {phase2g_report['first_remaining_blocker']}",
                    "",
                    "Fixture proof does not imply real-backend or normal-profile proof.",
                ]
            )
        )
    elif '"successor_candidate"' in payload:
        phase2f_report = Phase2FReport.model_validate_json(payload)
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard Phase 2F compatibility successor",
                    "",
                    f"Qualified verdict: {phase2f_report.final_verdict}",
                    f"Source mapping: {phase2f_report.mapping.verdict}",
                    f"Reconciliation base: {phase2f_report.base_selection.selected_commit}",
                    f"Isolated clone: {phase2f_report.clone.verdict}",
                    f"Baseline equivalence: {phase2f_report.reconciliation.verdict}",
                    f"Reconciliation commit: {phase2f_report.reconciliation.commit}",
                    f"Bundle: {phase2f_report.reconciliation.bundle_verification}",
                    f"Successor candidate: {phase2f_report.successor_candidate.candidate_id}",
                    f"Successor version: {phase2f_report.successor_candidate.version}",
                    f"Static compatibility: {phase2f_report.static_compatibility.verdict}",
                    "Isolated runtime: "
                    + str(phase2f_report.successor_canary.get("qualified_verdict", "UNPROVEN")),
                    f"Promotion authority: {phase2f_report.promotion_authority}",
                    f"First blocker: {phase2f_report.first_remaining_blocker}",
                    "",
                    "This compatibility successor does not contain a behavioural fix "
                    "and is not authorised for promotion.",
                ]
            )
        )
    elif '"baseline_attestation"' in payload:
        phase2e_report = Phase2EReport.model_validate_json(payload)
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard Phase 2E operational baseline",
                    "",
                    f"Baseline: {phase2e_report.baseline.baseline_id}",
                    f"Payload: {phase2e_report.baseline.payload_manifest_hash}",
                    f"Source authority: {phase2e_report.source_authority.verdict}",
                    f"Behavioural state: {phase2e_report.baseline.behavioural_state}",
                    "ID stability: "
                    + (
                        phase2e_report.id_stability.verdict
                        if phase2e_report.id_stability
                        else "UNPROVEN"
                    ),
                    "Isolated runtime: "
                    + str(phase2e_report.isolated_canary.get("qualified_verdict", "UNPROVEN")),
                    "Reference candidate: "
                    + str(
                        phase2e_report.reference_candidate_classification.get("verdict", "UNPROVEN")
                    ),
                    f"Promotion design: {phase2e_report.promotion_transaction.verdict}",
                    f"Golden journeys: {len(phase2e_report.golden_journeys)}",
                    f"First blocker: {phase2e_report.first_remaining_blocker}",
                    "",
                    "This report does not authorise or execute normal-profile promotion.",
                ]
            )
        )
    elif '"current_loaded_client_verdict"' in payload:
        current_report = CurrentProfileIdentityReport.model_validate_json(payload)
        extension = (
            current_report.configured_extensions[0]
            if len(current_report.configured_extensions) == 1
            else None
        )
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard current Chrome profile",
                    "",
                    f"Qualified verdict: {current_report.current_loaded_client_verdict}",
                    f"User-data root: {current_report.selected_user_data_root}",
                    f"Profile: {current_report.selected_profile}",
                    f"Configured extension count: {len(current_report.configured_extensions)}",
                    "Extension ID: "
                    + (extension.installation.extension_id if extension else "UNPROVEN"),
                    "Configured payload: "
                    + (extension.artifact.payload_manifest_hash if extension else "UNPROVEN"),
                    f"Worker observation: {current_report.passive_worker_observation}",
                    f"Runtime attestation: {current_report.current_runtime_attestation_verdict}",
                    f"Promotion readiness: {current_report.promotion_readiness.verdict}",
                    f"First failing boundary: {current_report.first_failing_boundary}",
                    "",
                    "Configured profile state is not live-runtime attestation.",
                ]
            )
        )
    elif '"runtime_verification"' in payload:
        canary_report = CanaryReport.model_validate_json(payload)
        typer.echo(
            "\n".join(
                [
                    "# Kratos Agent Guard isolated canary",
                    "",
                    f"Qualified verdict: {canary_report.runtime_verification.verdict}",
                    f"Candidate: {canary_report.candidate_identity['candidate_id']}",
                    f"Browser: {canary_report.browser_executable.product}",
                    "Extension ID: "
                    + (
                        canary_report.extension_runtime.extension_id
                        if canary_report.extension_runtime
                        else "UNPROVEN"
                    ),
                    f"Network: {canary_report.network_isolation.policy}",
                    "Current user runtime: "
                    f"{canary_report.current_user_runtime.loaded_extension_state}",
                    "First failing boundary: "
                    + (canary_report.runtime_verification.first_failing_boundary or "none"),
                    "",
                    "This evidence is scoped to the isolated Guard-owned canary.",
                ]
            )
        )
    else:
        inspection_report = InspectionReport.model_validate_json(payload)
        typer.echo(render_markdown(inspection_report))


@app.command("import-loaded-client-evidence")
def import_loaded_client_evidence(
    evidence_file: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    envelope = validate_envelope(evidence_file)
    destination = _guard_root() / "evidence" / "imported" / f"{envelope.candidate_id}.json"
    SafeOutputPolicy(verifier_root=str(_guard_root())).require_safe(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_json(envelope), encoding="utf-8")
    typer.echo(json.dumps({"stored": str(destination), "integrity": "PROVEN"}))


@app.command()
def self_identity() -> None:
    typer.echo(json.dumps(verifier_identity().model_dump(mode="json"), indent=2, sort_keys=True))


@key_app.command("initialise")
def key_initialise() -> None:
    identity = initialise_key()
    typer.echo(
        json.dumps(
            {
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "public_key_fingerprint": identity.public_key_fingerprint,
                "storage": identity.storage.model_dump(mode="json"),
            },
            indent=2,
        )
    )


@key_app.command("inspect")
def key_inspect() -> None:
    identity = inspect_key()
    typer.echo(
        json.dumps(
            {
                "key_id": identity.key_id,
                "algorithm": identity.algorithm,
                "public_key_fingerprint": identity.public_key_fingerprint,
                "storage": identity.storage.model_dump(mode="json"),
            },
            indent=2,
        )
    )


@key_app.command("export-public")
def key_export_public(
    trust_directory: Annotated[Path | None, typer.Option()] = None,
) -> None:
    destination = _guard_output(trust_directory or _guard_root() / "trust" / "keys")
    trust = export_public_key(destination)
    typer.echo(json.dumps(trust.model_dump(mode="json"), indent=2))


@key_app.command("rotate")
def key_rotate(
    reason: Annotated[str, typer.Option()],
    trust_directory: Annotated[Path | None, typer.Option()] = None,
) -> None:
    destination = trust_directory
    configuration_path = default_configuration_path()
    if destination is None and configuration_path.is_file():
        destination = Path(load_configuration(configuration_path).trust_directory)
    identity = rotate_key(reason, destination)
    typer.echo(json.dumps({"new_key_id": identity.key_id, "rotated": True}))


@key_app.command("revoke")
def key_revoke(
    key_id: Annotated[str, typer.Option()],
    reason: Annotated[str, typer.Option()],
    trust_directory: Annotated[Path | None, typer.Option()] = None,
) -> None:
    destination = trust_directory
    configuration_path = default_configuration_path()
    if destination is None and configuration_path.is_file():
        destination = Path(load_configuration(configuration_path).trust_directory)
    record = revoke_key(key_id, reason, destination)
    typer.echo(record.model_dump_json(indent=2))


@key_app.command("export-bundle")
def key_export_bundle(
    trust_directory: Annotated[Path, typer.Option()],
) -> None:
    exported = export_trust_bundle(trust_directory)
    typer.echo(
        json.dumps(
            {
                "exported_files": [str(path) for path in exported],
                "file_count": len(exported),
                "verdict": "PASS_TRUST_BUNDLE_EXPORTED",
            },
            indent=2,
            sort_keys=True,
        )
    )


def _repository_manifest(target: Path, profile: str) -> tuple[dict[str, object], str]:
    loaded = load_profile(profile)
    manifest = generate_manifest(
        target,
        max_files=int(loaded["limits"]["source_max_files"]),
        max_total_bytes=int(loaded["limits"]["source_max_bytes"]),
        exclusions=set(loaded.get("source_exclusions", [])),
    )
    return loaded, manifest.manifest_sha256


@app.command("build-plan")
def build_plan(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
    component: Annotated[str, typer.Option()] = "extension",
) -> None:
    if component != "extension":
        raise typer.BadParameter("only the extension component is supported")
    loaded = load_profile(profile)
    definition = component_build_definition(target, loaded)
    typer.echo(render_json(definition))


@app.command("snapshot-component")
def snapshot_component_command(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
    component: Annotated[str, typer.Option()] = "extension",
) -> None:
    if component != "extension":
        raise typer.BadParameter("only the extension component is supported")
    loaded, repository_hash = _repository_manifest(target, profile)
    definition = component_build_definition(target, loaded)
    manifest = build_input_manifest(target, definition, repository_hash, "cli-snapshot")
    candidate_id = candidate_identifier(manifest.manifest_sha256)
    workspace = snapshot_component(target, _guard_root(), manifest, candidate_id)
    typer.echo(
        json.dumps(
            {
                "candidate_id": candidate_id,
                "workspace": str(workspace),
                "build_input_manifest_hash": manifest.manifest_sha256,
            },
            indent=2,
        )
    )


@app.command("build-sealed-candidate")
def build_sealed_candidate_command(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
    component: Annotated[str, typer.Option()] = "extension",
) -> None:
    if component != "extension":
        raise typer.BadParameter("only the extension component is supported")
    verifier = verifier_identity()
    if verifier.state.value != "PROVEN" or verifier.dirty:
        raise RuntimeError("verifier authority must be proven and clean before sealed build")
    identity = inspect_key()
    trusted_key = _guard_root() / "trust" / "keys" / f"{identity.key_id}.pub.json"
    if not trusted_key.is_file():
        raise RuntimeError("trusted public key is missing; run key export-public")
    loaded, repository_hash = _repository_manifest(target, profile)
    first = build_sealed_candidate(target, _guard_root(), loaded, repository_hash)
    second = build_sealed_candidate(target, _guard_root(), loaded, repository_hash)
    reproducibility = compare_candidates(
        Path(first.candidate_directory), Path(second.candidate_directory)
    )
    first.delivery_manifest_hash = update_reproducibility(
        Path(first.candidate_directory), reproducibility.state
    )
    second.delivery_manifest_hash = update_reproducibility(
        Path(second.candidate_directory), reproducibility.state
    )
    verification = verify_candidate(Path(first.candidate_directory), trusted_key)
    typer.echo(
        json.dumps(
            {
                "candidate": first.model_dump(mode="json"),
                "reproducibility": reproducibility.model_dump(mode="json"),
                "verification": verification.model_dump(mode="json"),
                "qualified_verdict": (
                    "SOURCE_TO_BUILD_PROVEN_RUNTIME_CHAIN_INCOMPLETE"
                    if verification.overall_provenance_state.value == "PROVEN"
                    else "SOURCE_TO_BUILD_UNPROVEN"
                ),
                "historical_stale_candidate_verdict": "SOURCE_TO_BUILD_LINK_CONTRADICTED",
                "runtime_verdict": "UNPROVEN",
                "loaded_client_verdict": "UNPROVEN",
                "first_failing_boundary": (
                    "build-to-runtime"
                    if verification.overall_provenance_state.value == "PROVEN"
                    else verification.first_failing_boundary
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("verify-attestation")
def verify_attestation_command(
    attestation_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    attestation = BuildAttestation.model_validate_json(attestation_path.read_text(encoding="utf-8"))
    workspace = attestation_path.parent.parent
    trusted_key = _guard_root() / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    result = verify_candidate(workspace, trusted_key)
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.overall_provenance_state.value == "PROVEN" else 3)


@app.command("verify-sealed-candidate")
def verify_sealed_candidate_command(
    candidate_directory: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
) -> None:
    attestation_path = candidate_directory / "evidence" / "build-attestation.json"
    attestation = BuildAttestation.model_validate_json(attestation_path.read_text(encoding="utf-8"))
    trusted_key = _guard_root() / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    result = verify_candidate(candidate_directory, trusted_key)
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.overall_provenance_state.value == "PROVEN" else 3)


@app.command("compare-candidates")
def compare_candidates_command(
    candidate_a: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    candidate_b: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
) -> None:
    typer.echo(render_json(compare_candidates(candidate_a, candidate_b)))


@browser_app.command("discover")
def browser_discover_command() -> None:
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in discover_browsers()],
            indent=2,
            sort_keys=True,
        )
    )


@app.command("inspect-browser-processes")
def inspect_browser_processes_command() -> None:
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in discover_browser_processes()],
            indent=2,
            sort_keys=True,
        )
    )


@app.command("discover-browser-profiles")
def discover_browser_profiles_command() -> None:
    groups = discover_browser_processes()
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in discover_browser_profiles(groups)],
            indent=2,
            sort_keys=True,
        )
    )


@app.command("inspect-current-extension")
def inspect_current_extension_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")
    typer.echo(render_json(inspect_current_profile(_guard_root(), candidate)))


@app.command("compare-current-extension")
def compare_current_extension_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    inspect_current_extension_command(candidate, profile)


@app.command("promotion-readiness")
def promotion_readiness_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")
    typer.echo(render_json(inspect_current_profile(_guard_root(), candidate).promotion_readiness))


@app.command("inspect-configured-source")
def inspect_configured_source_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")
    config = load_phase2e_config(_guard_root())
    typer.echo(render_json(inspect_configured_source(Path(config["extension_path"]))))


@app.command("test-extension-id-stability")
def test_extension_id_stability_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")
    typer.echo(render_json(test_extension_id_stability(_guard_root())))


@app.command("seal-current-baseline")
def seal_current_baseline_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")
    typer.echo(render_json(seal_current_baseline(_guard_root())))


@app.command("verify-current-baseline")
def verify_current_baseline_command(
    baseline: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(json.dumps(verify_current_baseline(baseline, _guard_root()), indent=2))


@app.command("canary-current-baseline")
def canary_current_baseline_command(
    baseline: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(json.dumps(canary_current_baseline(_guard_root(), baseline), indent=2))


@app.command("classify-reference-candidate")
def classify_reference_candidate_command(
    baseline: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(json.dumps(classify_reference_candidate(baseline, candidate), indent=2))


@app.command("design-promotion")
def design_promotion_command(
    baseline: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    candidate_contract: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    report = Phase2EReport.model_validate_json(
        (baseline / "evidence" / "phase2e-report.json").read_text("utf-8")
    )
    contract = json.loads(candidate_contract.read_text("utf-8"))
    if contract.get("verdict") != "SUCCESSOR_CANDIDATE_CONTRACT_DEFINED":
        raise typer.BadParameter("candidate contract is not valid")
    typer.echo(
        render_json(promotion_design(report.baseline, report.rollback_package, report.id_stability))
    )


def _require_itzako(profile: str) -> None:
    if profile != "itzako":
        raise typer.BadParameter("only the itzako profile is supported")


@app.command("map-configured-extension-source")
def map_configured_extension_source_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    _require_itzako(profile)
    typer.echo(render_json(map_configured_extension_source(_guard_root())))


@app.command("select-reconciliation-base")
def select_reconciliation_base_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    _require_itzako(profile)
    typer.echo(render_json(select_reconciliation_base(_guard_root())))


@app.command("create-isolated-reconciliation")
def create_isolated_reconciliation_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    _require_itzako(profile)
    mapping = map_configured_extension_source(_guard_root())
    selection = select_reconciliation_base(_guard_root())
    clone, lineage, plan = create_isolated_reconciliation(_guard_root(), mapping, selection)
    typer.echo(
        json.dumps(
            {
                "clone": clone.model_dump(mode="json"),
                "lineage": lineage.model_dump(mode="json"),
                "plan": plan.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("verify-baseline-equivalence")
def verify_baseline_equivalence_command(
    reconciliation: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    result = verify_reconciliation_workspace(_guard_root(), reconciliation)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
    raise typer.Exit(0 if result["verdict"] == "BASELINE_EQUIVALENT_BUILD_PROVEN" else 3)


@app.command("seal-reconciliation-lineage")
def seal_reconciliation_lineage_command(
    reconciliation: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    result = verify_lineage_attestation(_guard_root(), reconciliation)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
    raise typer.Exit(0 if result["verdict"] == "RECONCILIATION_LINEAGE_SIGNATURE_PROVEN" else 3)


@app.command("build-compat-successor")
def build_compat_successor_command(
    reconciliation: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    clone = IsolatedCloneIdentity.model_validate_json(
        (reconciliation / "evidence" / "clone-identity.json").read_text("utf-8")
    )
    lineage = ReconciliationLineage.model_validate_json(
        (reconciliation / "evidence" / "reconciliation-lineage.json").read_text("utf-8")
    )
    delta, candidate = build_compat_successor(_guard_root(), clone, lineage, reconciliation.name)
    typer.echo(
        json.dumps(
            {
                "delta": delta.model_dump(mode="json"),
                "candidate": candidate.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("verify-compat-successor")
def verify_compat_successor_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    verify_sealed_candidate_command(candidate)


@app.command("compare-successor-baseline")
def compare_successor_baseline_command(
    baseline: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(render_json(compare_successor_baseline(baseline, candidate)))


@app.command("import-successor-bundle")
def import_successor_bundle_command(
    bundle: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    destination: Annotated[Path, typer.Option(file_okay=False)],
) -> None:
    typer.echo(
        json.dumps(
            import_successor_bundle(bundle, destination),
            indent=2,
            sort_keys=True,
        )
    )


@app.command("analyse-behavioural-impact")
def analyse_behavioural_impact_command(
    repository: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    fix: Annotated[str, typer.Option()],
) -> None:
    typer.echo(render_json(analyse_behavioural_impact(repository, fix)))


@app.command("run-offline-golden-journeys")
def run_offline_golden_journeys_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    suite: Annotated[str, typer.Option()] = "itzako-extension",
) -> None:
    if suite != "itzako-extension":
        raise typer.BadParameter("suite must be itzako-extension")
    typer.echo(render_json(run_offline_golden_journeys(_guard_root(), candidate)))


@app.command("verify-behavioural-successor")
def verify_behavioural_successor_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    base_candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(render_json(compare_behavioural_successor(base_candidate, candidate)))


@app.command("bundle-behavioural-lineage")
def bundle_behavioural_lineage_command(
    repository: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(
        json.dumps(
            bundle_behavioural_lineage(_guard_root(), repository),
            indent=2,
            sort_keys=True,
        )
    )


@app.command("inspect-backend-contract")
def inspect_backend_contract_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    typer.echo(render_json(inspect_backend_contract(profile)))


@app.command("classify-protected-target-drift")
def classify_protected_target_drift_command(
    baseline: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    current: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    typer.echo(render_json(classify_protected_target_drift(baseline, current)))


@app.command("verify-synthetic-audit-identity")
def verify_synthetic_audit_identity_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    typer.echo(render_json(verify_synthetic_audit_identity(profile)))


@app.command("verify-provider-test-seam")
def verify_provider_test_seam_command(
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    typer.echo(render_json(verify_provider_test_seam(profile)))


@app.command("verify-database-readback")
def verify_database_readback_command(
    profile: Annotated[str, typer.Option()] = "itzako",
    run_marker: Annotated[str, typer.Option()] = "",
) -> None:
    typer.echo(render_json(verify_database_readback(profile, run_marker)))


@app.command("plan-real-backend-journeys")
def plan_real_backend_journeys_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    typer.echo(render_json(plan_real_backend_journeys(_guard_root(), candidate)))


@app.command("run-real-backend-journeys")
def run_real_backend_journeys_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    plan: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    report, report_path = run_real_backend_journeys(_guard_root(), candidate, plan)
    typer.echo(
        json.dumps(
            {
                "report_path": str(report_path),
                "report": report.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("verify-real-backend-report")
def verify_real_backend_report_command(
    report: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    typer.echo(
        json.dumps(
            verify_real_backend_report(report),
            indent=2,
            sort_keys=True,
        )
    )


@app.command("provision-backend-audit-authority")
def provision_backend_audit_authority_command(
    source_commit: Annotated[str, typer.Option()],
    destination: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    """Verify the explicitly named existing isolated backend authority."""

    result = inspect_backend_audit_authority(destination, source_commit)
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict == "BACKEND_AUDIT_SOURCE_AUTHORITY_PROVEN" else 3)


@app.command("bundle-backend-audit-lineage")
def bundle_backend_audit_lineage_command(
    repository: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    output_directory: Annotated[Path, typer.Option(file_okay=False)],
) -> None:
    result = bundle_backend_audit_lineage(_guard_root(), repository, output_directory)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


@app.command("verify-backend-audit-build")
def verify_backend_audit_build_command(
    attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    lineage_attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    result = inspect_backend_audit_build(_guard_root(), attestation, lineage_attestation)
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict == "BACKEND_AUDIT_BUILD_PROVEN" else 3)


@app.command("verify-backend-audit-database")
def verify_backend_audit_database_command(
    container: Annotated[str, typer.Option()] = "kag-phase2i-postgres",
) -> None:
    database, roles = verify_backend_audit_database(container)
    typer.echo(
        json.dumps(
            {
                "database": database.model_dump(mode="json"),
                "roles": [role.model_dump(mode="json") for role in roles],
            },
            indent=2,
            sort_keys=True,
        )
    )
    proven = database.verdict == "AUDIT_DATABASE_ISOLATION_PROVEN" and all(
        role.verdict in {"AUDIT_BACKEND_ROLE_PROVEN", "AUDIT_READONLY_ROLE_PROVEN"}
        for role in roles
    )
    raise typer.Exit(0 if proven else 3)


@app.command("verify-phase2i-synthetic-audit-identity")
def verify_phase2i_synthetic_audit_identity_command() -> None:
    result = verify_phase2i_synthetic_audit_identity()
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict == "SYNTHETIC_AUDIT_IDENTITY_PROVEN" else 3)


@app.command("verify-audit-provider-scenarios")
def verify_audit_provider_scenarios_command(
    repository: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    scenarios = verify_audit_provider_scenarios(repository)
    typer.echo(
        json.dumps(
            {
                "scenario_version": scenarios[0].scenario_version,
                "scenarios": [item.model_dump(mode="json") for item in scenarios],
                "verdict": "DETERMINISTIC_PROVIDER_SEAM_PROVEN",
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("inspect-audit-writer-leases")
def inspect_audit_writer_leases_command() -> None:
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in inspect_audit_writer_leases()],
            indent=2,
            sort_keys=True,
        )
    )


@app.command("acquire-audit-writer-lease")
def acquire_audit_writer_lease_command(
    candidate: Annotated[str, typer.Option()],
    run_marker: Annotated[str, typer.Option()],
    backend_build_id: Annotated[str, typer.Option()],
    ttl_seconds: Annotated[int, typer.Option(min=600, max=3600)] = 1800,
    expected_activity: Annotated[int, typer.Option(min=0)] = 0,
) -> None:
    result = acquire_audit_writer_lease(
        candidate,
        run_marker,
        backend_build_id,
        ttl_seconds=ttl_seconds,
        expected_activity=expected_activity,
    )
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict == "AUDIT_WRITER_LEASE_PROVEN" else 3)


@app.command("release-audit-writer-lease")
def release_audit_writer_lease_command(
    lease: Annotated[str, typer.Option()],
    terminal_outcome: Annotated[str, typer.Option()],
) -> None:
    result = release_audit_writer_lease(lease, terminal_outcome)
    typer.echo(result.model_dump_json(indent=2))


@app.command("start-backend-audit-runtime")
def start_backend_audit_runtime_command(
    attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    lineage_attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    runtime_directory: Annotated[Path, typer.Option(file_okay=False)],
) -> None:
    build = inspect_backend_audit_build(_guard_root(), attestation, lineage_attestation)
    runtime, owner_path = start_backend_audit_runtime(_guard_root(), build, runtime_directory)
    typer.echo(
        json.dumps(
            {
                "runtime": runtime.model_dump(mode="json"),
                "owner_path": str(owner_path),
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise typer.Exit(0 if runtime.verdict == "BACKEND_AUDIT_RUNTIME_PROVEN" else 3)


@app.command("inspect-backend-audit-runtime")
def inspect_backend_audit_runtime_command(
    attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    lineage_attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    build = inspect_backend_audit_build(_guard_root(), attestation, lineage_attestation)
    runtime = inspect_backend_audit_runtime(build)
    typer.echo(runtime.model_dump_json(indent=2))
    raise typer.Exit(0 if runtime.verdict == "BACKEND_AUDIT_RUNTIME_PROVEN" else 3)


@app.command("stop-backend-audit-runtime")
def stop_backend_audit_runtime_command(
    owner: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    typer.echo(json.dumps(stop_backend_audit_runtime(owner), indent=2, sort_keys=True))


@app.command("plan-isolated-real-backend-journeys")
def plan_isolated_real_backend_journeys_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    lineage_attestation: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    runtime_owner: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    backend_repository: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    synthetic_user_id: Annotated[str, typer.Option()],
) -> None:
    result = plan_isolated_real_backend_journeys(
        _guard_root(),
        candidate,
        attestation,
        lineage_attestation,
        runtime_owner,
        backend_repository,
        synthetic_user_id,
    )
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.dispatch_authorised else 3)


@app.command("run-isolated-real-backend-journeys")
def run_isolated_real_backend_journeys_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    lease: Annotated[str, typer.Option()],
    plan: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    report, report_path = run_isolated_real_backend_journeys(_guard_root(), candidate, lease, plan)
    typer.echo(
        json.dumps(
            {
                "report": report.model_dump(mode="json"),
                "report_path": str(report_path),
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("verify-phase2i-report")
def verify_phase2i_report_command(
    report: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    result = verify_phase2i_report(report)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))
    raise typer.Exit(0 if result["verdict"] == "PHASE2I_REPORT_VERIFIED" else 3)


@canary_app.command("plan-extension")
def canary_plan_extension_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    policy = plan_extension_canary(_guard_root(), candidate)
    typer.echo(render_json(policy))


@canary_app.command("run-extension")
def canary_run_extension_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    loaded = load_profile(profile)
    target = Path(str(loaded["verified_source_root"]))
    policy = plan_extension_canary(_guard_root(), candidate)
    report = run_extension_canary(
        _guard_root(),
        candidate,
        target,
        policy,
        verifier_identity().model_dump(mode="json"),
    )
    destination = _guard_root() / "evidence" / "inspections" / f"canary-{report.run_id}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_json(report) + "\n", encoding="utf-8")
    typer.echo(render_json(report))
    raise typer.Exit(
        0 if report.runtime_verification.build_to_runtime_state.value == "PROVEN" else 2
    )


@canary_app.command("cleanup-profile")
def canary_cleanup_profile_command(
    profile_path: Annotated[Path, typer.Option(exists=True, file_okay=False)],
) -> None:
    result = cleanup_guard_profile(_guard_root(), profile_path)
    typer.echo(json.dumps(result, indent=2, sort_keys=True))


@app.command("verify-runtime-readback")
def verify_runtime_readback_command(
    candidate: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    evidence: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    runtime_payload = payload["runtime_attestation"]
    runtime_hash = payload["runtime_attestation_file_sha256"]
    result = verify_runtime_readback(candidate, runtime_payload, runtime_hash, _guard_root())
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.state.value == "PROVEN" else 3)


@ledger_app.command("append")
def ledger_append_command(
    event_type: Annotated[str, typer.Option()],
    subject: Annotated[str, typer.Option()],
    payload_json: Annotated[str, typer.Option()] = "{}",
    ledger: Annotated[Path | None, typer.Option()] = None,
) -> None:
    destination = ledger or _guard_root() / "evidence" / "standalone" / "ledger.jsonl"
    destination = _guard_output(destination)
    payload = json.loads(payload_json)
    if not isinstance(payload, dict):
        raise typer.BadParameter("payload-json must decode to an object")
    entry = append_ledger_entry(destination, event_type, subject, payload)
    typer.echo(render_json(entry))


@ledger_app.command("verify")
def ledger_verify_command(
    trust_key: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    ledger: Annotated[Path | None, typer.Option()] = None,
) -> None:
    source = ledger or _guard_root() / "evidence" / "standalone" / "ledger.jsonl"
    result = verify_ledger(source, trust_key)
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.verdict == "PASS_LEDGER_VERIFIED" else 3)


@attestation_app.command("issue")
def attestation_issue_command(
    subject: Annotated[str, typer.Option()],
    output: Annotated[Path | None, typer.Option()] = None,
    expected_build_id: Annotated[str, typer.Option()] = "",
    expected_artifact_sha256: Annotated[str | None, typer.Option()] = None,
    ttl_seconds: Annotated[int, typer.Option(min=1, max=3600)] = 300,
) -> None:
    challenge = issue_runtime_challenge(
        subject,
        expected_build_id=expected_build_id,
        expected_artifact_sha256=expected_artifact_sha256,
        ttl_seconds=ttl_seconds,
    )
    destination = output or (
        _guard_root()
        / "evidence"
        / "standalone"
        / "challenges"
        / f"{challenge.challenge_id}.json"
    )
    _write_model(destination, challenge)
    typer.echo(render_json(challenge))


@attestation_app.command("synthetic-produce")
def attestation_synthetic_produce_command(
    challenge_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    artifact_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    output_directory: Annotated[Path | None, typer.Option()] = None,
    build_id: Annotated[str, typer.Option()] = "",
) -> None:
    challenge = RuntimeChallenge.model_validate_json(challenge_path.read_text(encoding="utf-8"))
    output_root = output_directory or (
        _guard_root() / "evidence" / "standalone" / "synthetic" / challenge.challenge_id
    )
    output_root = _output_policy(artifact_root).require_safe(output_root)
    trust_path = output_root / "producer-trust.pub.json"
    statement = create_synthetic_runtime_statement(
        challenge,
        artifact_root,
        trust_path,
        build_id=build_id,
    )
    statement_path = output_root / "runtime-statement.json"
    _write_model(statement_path, statement)
    typer.echo(
        json.dumps(
            {
                "producer_scope": statement.producer_scope,
                "producer_trust_path": str(trust_path),
                "statement": statement.model_dump(mode="json"),
                "statement_path": str(statement_path),
                "user_loaded_runtime_claim": "UNPROVEN_SYNTHETIC_SCOPE",
            },
            indent=2,
            sort_keys=True,
        )
    )


@attestation_app.command("verify")
def attestation_verify_command(
    challenge_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    statement_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    guard_trust_key: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    producer_trust_key: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    replay_directory: Annotated[Path | None, typer.Option()] = None,
) -> None:
    challenge = RuntimeChallenge.model_validate_json(challenge_path.read_text(encoding="utf-8"))
    statement = RuntimeStatement.model_validate_json(statement_path.read_text(encoding="utf-8"))
    replay_root = replay_directory or _guard_root() / "evidence" / "standalone" / "replay"
    replay_root = _guard_output(replay_root)
    result = verify_runtime_statement(
        challenge,
        statement,
        guard_trust_key,
        producer_trust_key,
        replay_root,
    )
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.verdict.startswith("PASS_") else 3)


@monitor_app.command("snapshot")
def monitor_snapshot_command(
    root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    output: Annotated[Path | None, typer.Option()] = None,
    max_files: Annotated[int, typer.Option(min=1, max=100_000)] = 5000,
    max_file_bytes: Annotated[int, typer.Option(min=1)] = 10_000_000,
) -> None:
    snapshot = snapshot_folder(root, max_files=max_files, max_file_bytes=max_file_bytes)
    if output is not None:
        destination = _output_policy(root).require_safe(output)
        _write_model(destination, snapshot)
    typer.echo(render_json(snapshot))


@monitor_app.command("compare")
def monitor_compare_command(
    baseline_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    current_path: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    baseline = FolderSnapshot.model_validate_json(baseline_path.read_text(encoding="utf-8"))
    current = FolderSnapshot.model_validate_json(current_path.read_text(encoding="utf-8"))
    result = compare_folder_snapshots(baseline, current)
    typer.echo(render_json(result))
    raise typer.Exit(0 if result.verdict == "PASS_NO_FOLDER_DRIFT" else 2)


@monitor_app.command("watch")
def monitor_watch_command(
    root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    ledger: Annotated[Path | None, typer.Option()] = None,
    interval_seconds: Annotated[float, typer.Option(min=0.1, max=60.0)] = 5.0,
    iterations: Annotated[int, typer.Option(min=1, max=1000)] = 1,
) -> None:
    ledger_path = ledger or _guard_root() / "evidence" / "standalone" / "ledger.jsonl"
    ledger_path = _output_policy(root).require_safe(ledger_path)
    baseline = snapshot_folder(root)
    append_ledger_entry(
        ledger_path,
        "folder.monitor.started",
        str(root.resolve()),
        {"manifest_sha256": baseline.manifest_sha256, "file_count": baseline.file_count},
    )
    drift_count = 0
    for index in range(1, iterations):
        time.sleep(interval_seconds)
        current = snapshot_folder(root)
        comparison = compare_folder_snapshots(baseline, current)
        if comparison.verdict != "PASS_NO_FOLDER_DRIFT":
            drift_count += 1
            append_ledger_entry(
                ledger_path,
                "folder.drift.detected",
                str(root.resolve()),
                comparison.model_dump(mode="json"),
            )
        baseline = current
        typer.echo(
            json.dumps(
                {"iteration": index + 1, "manifest_sha256": current.manifest_sha256}
            )
        )
    typer.echo(
        json.dumps(
            {
                "drift_events": drift_count,
                "iterations": iterations,
                "ledger": str(ledger_path),
                "verdict": "PASS_MONITOR_COMPLETED",
            },
            indent=2,
            sort_keys=True,
        )
    )


@standalone_app.command("init")
def standalone_init_command(
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    configuration_path = (config or default_configuration_path()).resolve()
    orphaned_default_ledger = configuration_path.parent / "evidence" / "ledger.jsonl"
    if not configuration_path.is_file() and orphaned_default_ledger.is_file():
        try:
            inspect_key()
        except FileNotFoundError as error:
            raise RuntimeError("STANDALONE_LEDGER_PRIVATE_KEY_REQUIRED") from error
    configuration = initialise_configuration(configuration_path)
    ledger = Path(configuration.ledger_path)
    if ledger.is_file():
        try:
            identity = inspect_key()
        except FileNotFoundError as error:
            raise RuntimeError("STANDALONE_LEDGER_PRIVATE_KEY_REQUIRED") from error
        verification = verify_ledger(ledger, Path(configuration.trust_directory))
        if verification.verdict != "PASS_LEDGER_VERIFIED":
            raise RuntimeError(
                "STANDALONE_LEDGER_VERIFICATION_REQUIRED:"
                + (verification.first_error or verification.verdict)
            )
        entries = [line for line in ledger.read_text(encoding="utf-8").splitlines() if line]
        previous_key_id = str(json.loads(entries[-1])["signing_key_id"])
        if identity.key_id != previous_key_id and not verify_key_rotation(
            previous_key_id,
            identity.key_id,
            local_trust_directory(),
        ):
            raise RuntimeError("STANDALONE_LEDGER_ACTIVE_KEY_CONTINUITY_REQUIRED")
    else:
        identity = initialise_key()
        append_ledger_entry(
            ledger,
            "guard.initialised",
            "standalone",
            {"configuration_schema": configuration.schema_version},
        )
    export_trust_bundle(Path(configuration.trust_directory))
    typer.echo(
        json.dumps(
            {
                "configuration": configuration.model_dump(mode="json"),
                "configuration_path": str(configuration_path),
                "key_id": identity.key_id,
                "verdict": "PASS_STANDALONE_INITIALISED",
            },
            indent=2,
            sort_keys=True,
        )
    )


@folder_app.command("add")
def standalone_folder_add_command(
    path: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    label: Annotated[str, typer.Option()],
    config: Annotated[Path | None, typer.Option()] = None,
    max_files: Annotated[int, typer.Option(min=1, max=100_000)] = 5000,
    max_file_bytes: Annotated[int, typer.Option(min=1)] = 10_000_000,
    max_total_bytes: Annotated[int, typer.Option(min=1)] = 500_000_000,
) -> None:
    configuration_path = (config or default_configuration_path()).resolve()
    record = register_folder(
        configuration_path,
        path,
        label,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
    )
    typer.echo(record.model_dump_json(indent=2))


@folder_app.command("list")
def standalone_folder_list_command(
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    configuration = load_configuration(config or default_configuration_path())
    typer.echo(
        json.dumps(
            {
                "folder_count": len(configuration.folders),
                "folders": [
                    item.model_dump(mode="json") for item in configuration.folders
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


@folder_app.command("remove")
def standalone_folder_remove_command(
    folder_id: Annotated[str, typer.Option()],
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    removed = remove_folder(
        (config or default_configuration_path()).resolve(), folder_id
    )
    typer.echo(
        json.dumps(
            {
                "folder_id": removed.folder_id,
                "removed": True,
                "verdict": "PASS_MONITORED_FOLDER_REMOVED",
            },
            indent=2,
            sort_keys=True,
        )
    )


@standalone_app.command("run")
def standalone_run_command(
    config: Annotated[Path | None, typer.Option()] = None,
    iterations: Annotated[int, typer.Option(min=0)] = 0,
) -> None:
    result = run_monitor(
        (config or default_configuration_path()).resolve(),
        iterations=None if iterations == 0 else iterations,
    )
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict.startswith("PASS_") else 3)


@standalone_app.command("health")
def standalone_health_command(
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    result = monitor_health((config or default_configuration_path()).resolve())
    typer.echo(result.model_dump_json(indent=2))
    raise typer.Exit(0 if result.verdict.startswith("PASS_") else 3)


@standalone_app.command("service-template")
def standalone_service_template_command(
    kind: Annotated[str, typer.Option()],
    output: Annotated[Path, typer.Option()],
) -> None:
    destination = write_service_template(kind, output)
    typer.echo(
        json.dumps(
            {
                "kind": kind,
                "template_path": str(destination),
                "verdict": "PASS_SERVICE_TEMPLATE_WRITTEN",
            },
            indent=2,
            sort_keys=True,
        )
    )


@standalone_app.command("status")
def installed_standalone_status_command(
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    configuration_path = (config or default_configuration_path()).resolve()
    blockers: list[str] = []
    try:
        configuration = load_configuration(configuration_path)
    except (FileNotFoundError, OSError, ValueError) as error:
        typer.echo(
            json.dumps(
                {
                    "blockers": [str(error)],
                    "configuration_path": str(configuration_path),
                    "verdict": "BLOCKED_STANDALONE_NOT_INITIALISED",
                },
                indent=2,
                sort_keys=True,
            )
        )
        raise typer.Exit(3) from error
    try:
        identity = inspect_key()
        key_state = identity.storage.state
    except (FileNotFoundError, OSError, PermissionError, RuntimeError, ValueError):
        key_state = "UNPROVEN"
        blockers.append("SIGNING_TRUST_ROOT_UNPROVEN")
    ledger = verify_ledger(
        Path(configuration.ledger_path), Path(configuration.trust_directory)
    )
    if ledger.verdict != "PASS_LEDGER_VERIFIED":
        blockers.append(ledger.first_error or ledger.verdict)
    if not configuration.folders:
        blockers.append("NO_MONITORED_FOLDERS_CONFIGURED")
    health = monitor_health(configuration_path)
    if not health.verdict.startswith("PASS_"):
        blockers.extend(health.blockers or [health.verdict])
    verdict = "PASS_STANDALONE_V1_READY" if not blockers else "BLOCKED_STANDALONE_V1"
    typer.echo(
        json.dumps(
            {
                "blockers": blockers,
                "configuration_path": str(configuration_path),
                "configured_folder_count": len(configuration.folders),
                "key_state": key_state,
                "ledger": ledger.model_dump(mode="json"),
                "monitor_health": health.model_dump(mode="json"),
                "verdict": verdict,
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise typer.Exit(0 if verdict.startswith("PASS_") else 3)


@evidence_app.command("export")
def standalone_evidence_export_command(
    destination: Annotated[Path, typer.Option()],
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    exported = export_evidence_bundle(
        (config or default_configuration_path()).resolve(), destination
    )
    typer.echo(
        json.dumps(
            {
                "bundle_path": str(exported),
                "verdict": "PASS_EVIDENCE_BUNDLE_EXPORTED",
            },
            indent=2,
            sort_keys=True,
        )
    )


@evidence_app.command("verify")
def standalone_evidence_verify_command(
    bundle: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    expected_trust_anchor_key_id: Annotated[str, typer.Option()],
) -> None:
    verification = verify_evidence_bundle(
        bundle,
        expected_trust_anchor_key_id=expected_trust_anchor_key_id,
    )
    typer.echo(verification.model_dump_json(indent=2))
    raise typer.Exit(0 if verification.verdict.startswith("PASS_") else 3)


@evidence_app.command("checkpoint")
def standalone_evidence_checkpoint_command(
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    checkpoint = create_ledger_checkpoint(
        (config or default_configuration_path()).resolve()
    )
    typer.echo(json.dumps(checkpoint, indent=2, sort_keys=True))


@evidence_app.command("import")
def standalone_evidence_import_command(
    bundle: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
    expected_trust_anchor_key_id: Annotated[str, typer.Option()],
    config: Annotated[Path | None, typer.Option()] = None,
) -> None:
    destination = import_evidence_bundle(
        (config or default_configuration_path()).resolve(),
        bundle,
        expected_trust_anchor_key_id,
    )
    typer.echo(
        json.dumps(
            {
                "imported_path": str(destination),
                "verdict": "PASS_EVIDENCE_BUNDLE_IMPORTED",
            },
            indent=2,
            sort_keys=True,
        )
    )


@app.command("standalone-status")
def standalone_status_command(
    ledger: Annotated[Path | None, typer.Option()] = None,
    trust_key: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, readable=True)
    ] = None,
    configured_folder: Annotated[
        Path | None, typer.Option(exists=True, file_okay=False, readable=True)
    ] = None,
) -> None:
    identity = verifier_identity()
    blockers: list[str] = []
    signing_identity = None
    try:
        signing_identity = inspect_key()
        signing_state = signing_identity.storage.state
    except (FileNotFoundError, PermissionError, RuntimeError, ValueError) as error:
        signing_state = str(error)
        blockers.append("SIGNING_TRUST_ROOT_UNPROVEN")
    if signing_state != "TRUST_ROOT_PROVEN" and "SIGNING_TRUST_ROOT_UNPROVEN" not in blockers:
        blockers.append("SIGNING_TRUST_ROOT_UNPROVEN")
    if identity.state.value != "PROVEN":
        blockers.append("GUARD_REPOSITORY_IDENTITY_UNPROVEN")
    if identity.dirty:
        blockers.append("GUARD_REPOSITORY_DIRTY")

    ledger_path = (ledger or _guard_root() / "evidence" / "standalone" / "ledger.jsonl").resolve()
    trusted_path = trust_key.resolve() if trust_key is not None else None
    if trusted_path is None and signing_identity is not None:
        candidate = (
            _guard_root() / "trust" / "keys" / f"{signing_identity.key_id}.pub.json"
        ).resolve()
        if candidate.is_file():
            trusted_path = candidate
    ledger_count = 0
    ledger_head = "0" * 64
    if not ledger_path.is_file():
        ledger_state = "NOT_INITIALISED"
        blockers.append("EVIDENCE_LEDGER_NOT_INITIALISED")
    elif trusted_path is None:
        ledger_state = "PRESENT_TRUST_KEY_MISSING"
        blockers.append("EVIDENCE_LEDGER_TRUST_KEY_MISSING")
    else:
        try:
            ledger_verification = verify_ledger(ledger_path, trusted_path)
        except (OSError, RuntimeError, ValueError):
            ledger_state = "VERIFICATION_ERROR"
            blockers.append("EVIDENCE_LEDGER_VERIFICATION_ERROR")
        else:
            ledger_state = ledger_verification.verdict
            ledger_count = ledger_verification.entry_count
            ledger_head = ledger_verification.head_hash
            if ledger_verification.verdict != "PASS_LEDGER_VERIFIED":
                blockers.append(ledger_verification.first_error or ledger_verification.verdict)

    configured_state = (
        "CONFIGURED_UNINSPECTED" if configured_folder is not None else "NOT_CONFIGURED"
    )
    verdict = "PASS_STANDALONE_GUARD_READY" if not blockers else "BLOCKED_STANDALONE_GUARD"
    status = StandaloneStatus(
        observed_at=datetime.now(UTC),
        guard_repository=identity.repository_root,
        guard_head=identity.head,
        guard_branch=identity.branch,
        guard_dirty=identity.dirty,
        signing_key_state=signing_state,
        evidence_ledger_state=ledger_state,
        evidence_ledger_entry_count=ledger_count,
        evidence_ledger_head_hash=ledger_head,
        trusted_key_path=str(trusted_path) if trusted_path is not None else "",
        configured_folder_state=configured_state,
        runtime_attestation_state="PROTOCOL_AVAILABLE_UNATTESTED",
        current_user_loaded_runtime_state="UNPROVEN",
        blockers=blockers,
        limitations=[
            (
                "The configured folder is recorded but is not inspected by this command."
                if configured_folder is not None
                else "No external target is configured or inspected by this command."
            ),
            "Synthetic producer proof cannot establish a user's loaded runtime identity.",
            "A target must independently implement the challenge-response protocol "
            "for runtime proof.",
        ],
        verdict=verdict,
    )
    typer.echo(render_json(status))
    raise typer.Exit(0 if verdict.startswith("PASS_") else 3)
