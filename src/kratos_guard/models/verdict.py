"""Gate and report verdicts."""

from kratos_guard.models.evidence import Observation, StrictModel, Uncertainty
from kratos_guard.models.identity import (
    TargetBuildIdentity,
    TargetLoadedClientIdentity,
    TargetRuntimeIdentity,
    TargetSourceIdentity,
    VerifierIdentity,
)
from kratos_guard.models.provenance import (
    ArtifactManifest,
    ConfiguredExtensionIdentity,
    HttpIdentityObservation,
    MutationWitnessResult,
    ProvenanceLink,
    RuntimeEvidence,
    SourceManifest,
)
from kratos_guard.models.state import EvidenceState


class GateResult(StrictModel):
    gate_id: str = "legacy"
    scope: str = "source"
    claim: str = ""
    verdict: EvidenceState
    exit_code: int
    summary: str = ""
    evidence_references: list[str] = []
    blockers: list[str] = []
    observations: list[Observation] = []
    uncertainties: list[Uncertainty] = []
    first_failing_boundary: str = ""


class InspectionReport(StrictModel):
    schema_version: str = "2.0"
    verifier: VerifierIdentity
    target_source: TargetSourceIdentity
    target_build: TargetBuildIdentity
    target_runtimes: list[TargetRuntimeIdentity]
    target_loaded_clients: list[TargetLoadedClientIdentity]
    gate: GateResult
    observations: list[Observation]
    uncertainties: list[Uncertainty]
    target_write_count: int = 0
    source_manifest: SourceManifest | None = None
    build_artifacts: list[ArtifactManifest] = []
    source_to_build_links: list[ProvenanceLink] = []
    runtime_evidence: RuntimeEvidence | None = None
    build_to_runtime_links: list[ProvenanceLink] = []
    configured_extensions: list[ConfiguredExtensionIdentity] = []
    http_observations: list[HttpIdentityObservation] = []
    mutation_witness: MutationWitnessResult | None = None
    contradictions: list[str] = []
    required_next_evidence: list[str] = []
    non_guarantees: list[str] = []
    learning_summary: str = ""
