"""Separate verifier and target identity domains."""

from pydantic import Field

from kratos_guard.models.evidence import StrictModel
from kratos_guard.models.state import EvidenceState


class VerifierIdentity(StrictModel):
    repository_root: str
    git_common_directory: str
    branch: str
    head: str
    dirty: bool
    package_name: str
    package_version: str
    state: EvidenceState


class TargetSourceIdentity(StrictModel):
    path: str
    repository_root: str = ""
    git_common_directory: str = ""
    branch: str = ""
    head: str = ""
    dirty: bool | None = None
    state: EvidenceState


class TargetBuildIdentity(StrictModel):
    build_id: str = ""
    artifact_path: str = ""
    source_link_state: EvidenceState
    state: EvidenceState


class TargetRuntimeIdentity(StrictModel):
    component: str
    endpoint: str = ""
    process_id: int | None = Field(default=None, ge=0)
    source_link_state: EvidenceState
    build_link_state: EvidenceState
    state: EvidenceState


class TargetLoadedClientIdentity(StrictModel):
    client_type: str
    build_id: str = ""
    provenance: str
    source_link_state: EvidenceState
    build_link_state: EvidenceState
    state: EvidenceState
