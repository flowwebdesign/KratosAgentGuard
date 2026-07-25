from kratos_guard.core.authority_gate import gate_result
from kratos_guard.models import EvidenceState


def test_gate_exit_codes_match_semantics() -> None:
    assert gate_result(EvidenceState.PROVEN, "ok").exit_code == 0
    assert gate_result(EvidenceState.UNPROVEN, "unknown").exit_code == 2
    assert gate_result(EvidenceState.CONTRADICTED, "bad").exit_code == 3
    assert gate_result(EvidenceState.INSPECTION_FAILED, "failed").exit_code == 4


def test_http_200_does_not_prove_identity() -> None:
    result = gate_result(EvidenceState.UNPROVEN, "HTTP 200 is reachability only")
    assert result.verdict is EvidenceState.UNPROVEN
