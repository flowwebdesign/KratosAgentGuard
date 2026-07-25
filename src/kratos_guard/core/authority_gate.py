"""Evidence-state gate semantics."""

from kratos_guard.models import EvidenceState, GateResult

EXIT_CODES = {
    EvidenceState.PROVEN: 0,
    EvidenceState.NOT_APPLICABLE: 0,
    EvidenceState.UNPROVEN: 2,
    EvidenceState.CONTRADICTED: 3,
    EvidenceState.INSPECTION_FAILED: 4,
}


def gate_result(state: EvidenceState, summary: str) -> GateResult:
    return GateResult(verdict=state, exit_code=EXIT_CODES[state], summary=summary)
