"""Kratos Agent Guard command line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer

from kratos_guard.adapters.docker import inspect_containers
from kratos_guard.adapters.git import git_value
from kratos_guard.adapters.runtime import inspect_listeners
from kratos_guard.core.artifacts import discover_artifacts
from kratos_guard.core.authority_gate import qualified_gate
from kratos_guard.core.bootstrap_gate import BootstrapFacts, bootstrap_verdict
from kratos_guard.core.inspection_runner import inspect_target, verifier_identity
from kratos_guard.core.loaded_evidence import validate_envelope
from kratos_guard.core.manifests import generate_manifest
from kratos_guard.core.path_security import ProtectedPath, SafeOutputPolicy
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
    initialise_key,
    inspect_key,
    rotate_key,
)
from kratos_guard.models import InspectionReport
from kratos_guard.projects.base import load_profile
from kratos_guard.reporting.json_report import render_json, write_json
from kratos_guard.reporting.markdown_report import render_markdown
from kratos_guard.reporting.redaction import redact

app = typer.Typer(no_args_is_help=True)
key_app = typer.Typer(no_args_is_help=True)
app.add_typer(key_app, name="key")


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
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    level: Annotated[str, typer.Option(help="source, build, runtime, or loaded-client")],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    report = inspect_target(target, profile, level)
    result = qualified_gate(report, level)
    typer.echo(render_json(result))
    raise typer.Exit(result.exit_code)


@app.command()
def explain_report(
    report_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    report = InspectionReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    typer.echo(render_markdown(report))


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
def key_export_public() -> None:
    trust = export_public_key(_guard_root() / "trust" / "keys")
    typer.echo(json.dumps(trust.model_dump(mode="json"), indent=2))


@key_app.command("rotate")
def key_rotate(reason: Annotated[str, typer.Option()]) -> None:
    identity = rotate_key(reason)
    typer.echo(json.dumps({"new_key_id": identity.key_id, "rotated": True}))


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
    from kratos_guard.models.build import BuildAttestation

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
    from kratos_guard.models.build import BuildAttestation

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
