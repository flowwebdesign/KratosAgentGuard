"""Phase 2A provenance models."""

from datetime import datetime

from pydantic import Field

from kratos_guard.models.evidence import HashEvidence, StrictModel
from kratos_guard.models.state import EvidenceState


class ManifestEntry(StrictModel):
    path: str
    kind: str
    size: int = Field(ge=0)
    sha256: str = ""
    link_target: str = ""


class SourceManifest(StrictModel):
    repository_root: str
    git_common_directory: str
    branch: str
    head: str
    dirty: bool
    staged: bool
    scope: str
    included_paths: list[str]
    excluded_paths: list[str]
    file_count: int
    total_bytes: int
    entries: list[ManifestEntry]
    manifest_sha256: str
    generated_at: datetime
    tool_version: str
    state: EvidenceState
    limitations: list[str] = []


class ArtifactCandidate(StrictModel):
    path: str
    artifact_type: str
    discovery_method: str
    evidence_state: EvidenceState
    uncertainties: list[str] = []


class ArtifactManifest(StrictModel):
    candidate: ArtifactCandidate
    file_count: int
    total_bytes: int
    manifest_sha256: str
    embedded_version: str = ""
    embedded_build_id: str = ""
    embedded_git_head: str = ""
    embedded_source_hash: str = ""
    parsed_metadata_source: str = ""
    parser: str = ""
    exclusions: list[str] = []
    uncertainties: list[str] = []


class BuildMetadataClaim(StrictModel):
    name: str
    value: str
    source: str
    state: EvidenceState


class BuildIdentity(StrictModel):
    artifact_path: str
    artifact_manifest_hash: str
    build_id: str = ""
    version: str = ""
    state: EvidenceState


class ProvenanceLink(StrictModel):
    link_type: str
    source_reference: str
    destination_reference: str
    verdict: EvidenceState
    evidence_references: list[str] = []
    reason: str


class MutationSnapshot(StrictModel):
    captured_at: datetime
    git_status_hash: str
    tracked_diff_hash: str
    staged_diff_hash: str
    conflicted_paths_hash: str
    untracked_manifest_hash: str
    sentinel_hashes: list[HashEvidence]
    root_metadata_hash: str
    coverage: list[str]
    exclusions: list[str]


class MutationWitnessResult(StrictModel):
    started_at: datetime
    finished_at: datetime
    before: MutationSnapshot
    after: MutationSnapshot
    changed: bool
    verdict: str
    limitations: list[str]


class ListeningEndpoint(StrictModel):
    address: str
    port: int
    pid: int | None = None
    state: EvidenceState


class RuntimeProcessIdentity(StrictModel):
    pid: int
    parent_pid: int | None = None
    executable: str = ""
    command_line: list[str] = []
    working_directory: str = ""
    creation_time: datetime | None = None
    endpoints: list[ListeningEndpoint] = []
    state: EvidenceState
    errors: list[str] = []


class ContainerIdentity(StrictModel):
    container_id: str
    name: str = ""
    image_reference: str = ""
    image_digest: str = ""
    command: str = ""
    mounts: list[str] = []
    labels: dict[str, str] = {}
    exposed_ports: list[str] = []
    started_at: str = ""
    state: EvidenceState
    uncertainties: list[str] = []


class RuntimeEvidence(StrictModel):
    processes: list[RuntimeProcessIdentity]
    containers: list[ContainerIdentity]
    links: list[ProvenanceLink]
    errors: list[str] = []


class HttpIdentityObservation(StrictModel):
    url: str
    method: str
    status: int | None = None
    content_type: str = ""
    body_sha256: str = ""
    body_excerpt: str = ""
    duration_ms: float
    purpose: str
    state: EvidenceState


class ConfiguredExtensionIdentity(StrictModel):
    extension_id: str = ""
    configured_path: str = ""
    configured_version: str = ""
    profile_identifier: str = ""
    metadata_timestamp: datetime | None = None
    state: EvidenceState
    limitations: list[str] = []


class LoadedClientEvidenceEnvelope(StrictModel):
    extension_id: str
    extension_version: str
    candidate_id: str
    build_hash: str
    source_head: str
    source_manifest_hash: str
    collection_method: str
    collection_timestamp: datetime
    profile_identity: str
    integrity_hash: str
