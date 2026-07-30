"""Strict evidence models."""

from kratos_guard.models.canary import CanaryReport, RuntimeProofScope
from kratos_guard.models.evidence import CommandEvidence, HashEvidence, Observation, Uncertainty
from kratos_guard.models.identity import (
    TargetBuildIdentity,
    TargetLoadedClientIdentity,
    TargetRuntimeIdentity,
    TargetSourceIdentity,
    VerifierIdentity,
)
from kratos_guard.models.standalone import (
    FolderComparison,
    FolderSnapshot,
    LedgerEntry,
    LedgerVerification,
    RuntimeAttestationVerification,
    RuntimeChallenge,
    RuntimeStatement,
    StandaloneStatus,
)
from kratos_guard.models.state import EvidenceState
from kratos_guard.models.verdict import GateResult, InspectionReport

__all__ = [
    "CommandEvidence",
    "CanaryReport",
    "EvidenceState",
    "GateResult",
    "HashEvidence",
    "InspectionReport",
    "FolderComparison",
    "FolderSnapshot",
    "LedgerEntry",
    "LedgerVerification",
    "Observation",
    "RuntimeProofScope",
    "RuntimeAttestationVerification",
    "RuntimeChallenge",
    "RuntimeStatement",
    "StandaloneStatus",
    "TargetBuildIdentity",
    "TargetLoadedClientIdentity",
    "TargetRuntimeIdentity",
    "TargetSourceIdentity",
    "Uncertainty",
    "VerifierIdentity",
]
