"""Gate and report verdicts."""

from kratos_guard.models.evidence import Observation, StrictModel, Uncertainty
from kratos_guard.models.identity import (
    TargetBuildIdentity,
    TargetLoadedClientIdentity,
    TargetRuntimeIdentity,
    TargetSourceIdentity,
    VerifierIdentity,
)
from kratos_guard.models.state import EvidenceState


class GateResult(StrictModel):
    verdict: EvidenceState
    exit_code: int
    summary: str
    observations: list[Observation] = []
    uncertainties: list[Uncertainty] = []


class InspectionReport(StrictModel):
    schema_version: str = "1.0"
    verifier: VerifierIdentity
    target_source: TargetSourceIdentity
    target_build: TargetBuildIdentity
    target_runtimes: list[TargetRuntimeIdentity]
    target_loaded_clients: list[TargetLoadedClientIdentity]
    gate: GateResult
    observations: list[Observation]
    uncertainties: list[Uncertainty]
    target_write_count: int = 0
