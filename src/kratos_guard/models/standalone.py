"""Strict models for Guard-owned standalone monitoring and attestations."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from kratos_guard.models.evidence import StrictModel

Digest = str


class LedgerEntry(StrictModel):
    schema_version: Literal["kratos-guard.evidence-ledger-entry.v1"] = (
        "kratos-guard.evidence-ledger-entry.v1"
    )
    sequence: int = Field(ge=1)
    recorded_at: datetime
    event_type: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9._-]+$")
    subject: str = Field(min_length=1, max_length=500)
    payload: dict[str, object]
    previous_entry_hash: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    signing_key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    entry_hash: Digest = Field(pattern=r"^[a-f0-9]{64}$")


class LedgerVerification(StrictModel):
    schema_version: Literal["kratos-guard.evidence-ledger-verification.v1"] = (
        "kratos-guard.evidence-ledger-verification.v1"
    )
    ledger_path: str
    entry_count: int = Field(ge=0)
    head_hash: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    chain_state: str
    signature_state: str
    first_error: str = ""
    verdict: str


class RuntimeChallenge(StrictModel):
    schema_version: Literal["kratos-guard.runtime-challenge.v1"] = (
        "kratos-guard.runtime-challenge.v1"
    )
    challenge_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    nonce: str = Field(min_length=32, max_length=200)
    issued_at: datetime
    expires_at: datetime
    subject: str = Field(min_length=1, max_length=500)
    expected_build_id: str = ""
    expected_artifact_sha256: Digest | None = Field(
        default=None, pattern=r"^[a-f0-9]{64}$"
    )
    verifier_key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class RuntimeStatement(StrictModel):
    schema_version: Literal["kratos-guard.runtime-statement.v1"] = (
        "kratos-guard.runtime-statement.v1"
    )
    statement_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    challenge_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    nonce: str = Field(min_length=32, max_length=200)
    observed_at: datetime
    subject: str = Field(min_length=1, max_length=500)
    runtime_kind: str = Field(min_length=1, max_length=100)
    producer_scope: str = Field(min_length=1, max_length=100)
    build_id: str = Field(min_length=1, max_length=500)
    artifact_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    executable_manifest_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    process_id: int | None = Field(default=None, ge=1)
    claims: dict[str, object] = Field(default_factory=dict)
    producer_key_id: str = Field(min_length=1)
    signature: str = Field(min_length=1)


class RuntimeAttestationVerification(StrictModel):
    schema_version: Literal["kratos-guard.runtime-attestation-verification.v1"] = (
        "kratos-guard.runtime-attestation-verification.v1"
    )
    challenge_id: str
    statement_id: str
    subject: str
    build_id: str
    artifact_sha256: str
    challenge_signature_state: str
    producer_signature_state: str
    freshness_state: str
    replay_state: str
    producer_scope: str
    current_user_loaded_runtime_state: str
    blockers: list[str] = Field(default_factory=list)
    verdict: str


class FolderFileIdentity(StrictModel):
    relative_path: str
    sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    byte_count: int = Field(ge=0)


class FolderSnapshot(StrictModel):
    schema_version: Literal["kratos-guard.folder-snapshot.v1"] = (
        "kratos-guard.folder-snapshot.v1"
    )
    root: str
    observed_at: datetime
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    manifest_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    files: list[FolderFileIdentity]
    excluded_directories: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class FolderComparison(StrictModel):
    schema_version: Literal["kratos-guard.folder-comparison.v1"] = (
        "kratos-guard.folder-comparison.v1"
    )
    baseline_manifest_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    current_manifest_sha256: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    added: list[str]
    removed: list[str]
    changed: list[str]
    verdict: str


class StandaloneStatus(StrictModel):
    schema_version: Literal["kratos-guard.standalone-status.v2"] = (
        "kratos-guard.standalone-status.v2"
    )
    observed_at: datetime
    guard_repository: str
    guard_head: str
    guard_branch: str
    guard_dirty: bool
    signing_key_state: str
    evidence_ledger_state: str
    evidence_ledger_entry_count: int = Field(ge=0)
    evidence_ledger_head_hash: Digest = Field(pattern=r"^[a-f0-9]{64}$")
    trusted_key_path: str
    configured_folder_state: str
    runtime_attestation_state: str
    current_user_loaded_runtime_state: str
    blockers: list[str] = Field(default_factory=list)
    limitations: list[str]
    verdict: str
