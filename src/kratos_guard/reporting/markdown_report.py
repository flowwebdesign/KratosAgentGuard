"""Generated qualified human-readable evidence."""

from kratos_guard.models import InspectionReport
from kratos_guard.reporting.redaction import redact_text


def _items(values: list[str]) -> list[str]:
    return [f"- {value}" for value in values] or ["- None observed"]


def render_markdown(report: InspectionReport) -> str:
    manifest = report.source_manifest
    runtime = report.runtime_evidence
    witness = report.mutation_witness
    lines = [
        "# Kratos Agent Guard Provenance Inspection",
        "",
        "## 1. Executive qualified verdict",
        f"- Gate: `{report.gate.gate_id}`",
        f"- Scope: `{report.gate.scope}`",
        f"- Verdict: `{report.gate.verdict}`",
        f"- Summary: `{report.gate.summary}`",
        "",
        "## 2. Verifier identity",
        f"- Repository: `{report.verifier.repository_root}`",
        f"- HEAD: `{report.verifier.head or 'UNPROVEN'}`",
        "",
        "## 3. Target source identity",
        f"- Repository: `{report.target_source.repository_root}`",
        f"- HEAD: `{report.target_source.head or 'UNPROVEN'}`",
        f"- Dirty: `{report.target_source.dirty}`",
        "",
        "## 4. Source manifest",
        f"- Hash: `{manifest.manifest_sha256 if manifest else 'UNPROVEN'}`",
        f"- Files: `{manifest.file_count if manifest else 0}`",
        "",
        "## 5. Build candidates",
        *_items([artifact.candidate.path for artifact in report.build_artifacts]),
        "",
        "## 6. Build artefact manifests",
        *_items([artifact.manifest_sha256 for artifact in report.build_artifacts]),
        "",
        "## 7. Source-to-build links",
        *_items([f"`{link.verdict}` — {link.reason}" for link in report.source_to_build_links]),
        "",
        "## 8. Process identities",
        *_items(
            [f"PID {item.pid}: {item.executable}" for item in runtime.processes] if runtime else []
        ),
        "",
        "## 9. Container identities",
        *_items(
            [f"{item.container_id}: {item.image_reference}" for item in runtime.containers]
            if runtime
            else []
        ),
        "",
        "## 10. Build-to-runtime links",
        *_items([f"`{link.verdict}` — {link.reason}" for link in report.build_to_runtime_links]),
        "",
        "## 11. Configured extension evidence",
        *_items([str(item.state) for item in report.configured_extensions]),
        "",
        "## 12. Live loaded-client evidence",
        *_items([str(item.state) for item in report.target_loaded_clients]),
        "",
        "## 13. Reachability and health observations",
        *_items(
            [
                f"{item.method} {item.url}: {item.status} ({item.purpose})"
                for item in report.http_observations
            ]
        ),
        "",
        "## 14. Mutation witness",
        f"- Result: `{witness.verdict if witness else 'INSPECTION_FAILED'}`",
        "",
        "## 15. First failing identity boundary",
        f"- `{report.gate.first_failing_boundary or 'none'}`",
        "",
        "## 16. Contradictions",
        *_items(report.contradictions),
        "",
        "## 17. Uncertainties",
        *_items([item.reason for item in report.uncertainties]),
        "",
        "## 18. Required next evidence",
        *_items(report.required_next_evidence),
        "",
        "## 19. Explicit non-guarantees",
        *_items(report.non_guarantees),
        "",
        "## 20. Learning summary",
        report.learning_summary,
        "",
    ]
    return redact_text("\n".join(lines))
