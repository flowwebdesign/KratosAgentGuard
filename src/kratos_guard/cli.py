"""Kratos Agent Guard command line interface."""

import json
from pathlib import Path
from typing import Annotated

import typer

from kratos_guard.core.authority_gate import EXIT_CODES
from kratos_guard.core.bootstrap_gate import BootstrapFacts, bootstrap_verdict
from kratos_guard.core.inspection_runner import inspect_target, verifier_identity
from kratos_guard.models import InspectionReport
from kratos_guard.projects.base import load_profile
from kratos_guard.reporting.json_report import render_json, write_json
from kratos_guard.reporting.markdown_report import render_markdown

app = typer.Typer(no_args_is_help=True)


@app.command()
def bootstrap_check(path: Path | None = None) -> None:
    path = path or Path.cwd()
    identity = verifier_identity(path)
    origin = ""
    if (path / ".git").exists():
        from kratos_guard.adapters.git import git_value

        origin = git_value(path, ["remote", "get-url", "origin"])
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
        remote_empty=False,
        local_path=path,
        local_entries=entries,
        inside_target_worktree=False,
        local_git_common_directory=".git" if (path / ".git").exists() else "",
    )
    typer.echo(json.dumps({"verdict": bootstrap_verdict(facts), "path": str(path.resolve())}))


@app.command()
def validate_config(profile: str = "itzako") -> None:
    loaded = load_profile(profile)
    typer.echo(json.dumps({"profile": loaded["name"], "valid": True}))


@app.command()
def inspect(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
    output: Annotated[Path | None, typer.Option()] = None,
) -> None:
    report = inspect_target(target, profile)
    if output:
        write_json(report, output)
    typer.echo(render_json(report))


@app.command()
def gate(
    target: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    profile: Annotated[str, typer.Option()] = "itzako",
) -> None:
    report = inspect_target(target, profile)
    typer.echo(render_json(report.gate))
    raise typer.Exit(EXIT_CODES[report.gate.verdict])


@app.command()
def explain_report(
    report_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
) -> None:
    report = InspectionReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    typer.echo(render_markdown(report))


@app.command()
def self_identity() -> None:
    typer.echo(json.dumps(verifier_identity().model_dump(mode="json"), indent=2, sort_keys=True))
