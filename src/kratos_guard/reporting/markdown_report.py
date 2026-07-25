"""Generated human-readable evidence."""

from kratos_guard.models import InspectionReport


def render_markdown(report: InspectionReport) -> str:
    lines = [
        "# Kratos Agent Guard Inspection",
        "",
        f"- Gate: `{report.gate.verdict}`",
        f"- Summary: {report.gate.summary}",
        f"- Verifier repository: `{report.verifier.repository_root}`",
        f"- Verifier HEAD: `{report.verifier.head or 'UNPROVEN'}`",
        f"- Target source: `{report.target_source.path}`",
        f"- Target source state: `{report.target_source.state}`",
        f"- Target writes: `{report.target_write_count}`",
        "",
        "## Identity boundaries",
        "",
        f"- Target build: `{report.target_build.state}`",
        f"- Target loaded client: `{report.target_loaded_clients[0].state}`",
        "",
        "HTTP or TCP availability is reachability evidence only; it does not prove source, "
        "build, or behavioural identity.",
        "",
    ]
    return "\n".join(lines)
