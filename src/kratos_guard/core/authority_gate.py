"""Evidence-state gate semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from kratos_guard.models import EvidenceState, GateResult

if TYPE_CHECKING:
    from kratos_guard.models import InspectionReport
    from kratos_guard.models.provenance import ProvenanceLink

EXIT_CODES = {
    EvidenceState.PROVEN: 0,
    EvidenceState.NOT_APPLICABLE: 0,
    EvidenceState.UNPROVEN: 2,
    EvidenceState.CONTRADICTED: 3,
    EvidenceState.INSPECTION_FAILED: 4,
}


def gate_result(
    state: EvidenceState,
    summary: str,
    *,
    gate_id: str = "legacy",
    scope: str = "source",
    claim: str = "",
    first_failing_boundary: str = "",
    blockers: list[str] | None = None,
) -> GateResult:
    return GateResult(
        gate_id=gate_id,
        scope=scope,
        claim=claim or summary,
        verdict=state,
        exit_code=EXIT_CODES[state],
        summary=summary,
        first_failing_boundary=first_failing_boundary,
        blockers=blockers or [],
    )


def qualified_gate(report: InspectionReport, level: str) -> GateResult:
    from kratos_guard.models import InspectionReport

    if not isinstance(report, InspectionReport):
        raise TypeError("report must be an InspectionReport")
    states = {
        "source": (
            report.target_source.state,
            "TARGET_SOURCE_AUTHORITY_PROVEN",
            "target source repository identity",
        ),
        "build": (
            _best_link(report.source_to_build_links),
            "SOURCE_TO_BUILD_LINK_PROVEN",
            "source-to-build provenance",
        ),
        "runtime": (
            _best_link(report.build_to_runtime_links),
            "BUILD_TO_RUNTIME_LINK_PROVEN",
            "build-to-runtime provenance",
        ),
        "loaded-client": (
            report.target_loaded_clients[0].state,
            "TARGET_LOADED_CLIENT_PROVEN",
            "live loaded-client identity",
        ),
        "identity-chain": (
            EvidenceState.PROVEN
            if all(
                (
                    report.target_source.state is EvidenceState.PROVEN,
                    _best_link(report.source_to_build_links) is EvidenceState.PROVEN,
                    _best_link(report.build_to_runtime_links) is EvidenceState.PROVEN,
                    report.target_loaded_clients[0].state is EvidenceState.PROVEN,
                )
            )
            else EvidenceState.UNPROVEN,
            "COMPLETE_IDENTITY_CHAIN_PROVEN",
            "complete source-build-runtime-loaded identity chain",
        ),
    }
    if level not in states:
        raise ValueError(f"unknown gate level: {level}")
    state, gate_id, claim = states[level]
    boundaries = {
        "source": "target-source",
        "build": "source-to-build",
        "runtime": "build-to-runtime",
        "loaded-client": "loaded-client",
    }
    boundary = "" if state is EvidenceState.PROVEN else boundaries.get(level, level)
    if level == "identity-chain" and state is not EvidenceState.PROVEN:
        if report.target_source.state is not EvidenceState.PROVEN:
            boundary = "target-source"
        elif _best_link(report.source_to_build_links) is not EvidenceState.PROVEN:
            boundary = "source-to-build"
        elif _best_link(report.build_to_runtime_links) is not EvidenceState.PROVEN:
            boundary = "build-to-runtime"
        else:
            boundary = "loaded-client"
    summary = gate_id if state is EvidenceState.PROVEN else f"{gate_id}_{state}"
    if level == "identity-chain" and report.target_source.state is EvidenceState.PROVEN:
        summary = "SOURCE_AUTHORITY_PROVEN_IDENTITY_CHAIN_INCOMPLETE"
    result = gate_result(
        state,
        summary,
        gate_id=gate_id,
        scope=level,
        claim=claim,
        first_failing_boundary=boundary,
        blockers=report.contradictions if state is EvidenceState.CONTRADICTED else [],
    )
    result.uncertainties = report.uncertainties
    result.evidence_references = [
        reference
        for reference in [
            report.source_manifest.manifest_sha256 if report.source_manifest else "",
            *[artifact.manifest_sha256 for artifact in report.build_artifacts],
        ]
        if reference
    ]
    return result


def _best_link(links: list[ProvenanceLink]) -> EvidenceState:
    from kratos_guard.models.provenance import ProvenanceLink

    if not all(isinstance(link, ProvenanceLink) for link in links):
        return EvidenceState.INSPECTION_FAILED
    states = {link.verdict for link in links}
    if EvidenceState.CONTRADICTED in states:
        return EvidenceState.CONTRADICTED
    if EvidenceState.PROVEN in states:
        return EvidenceState.PROVEN
    return EvidenceState.UNPROVEN
