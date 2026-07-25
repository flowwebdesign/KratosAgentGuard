"""Profile-bounded, non-executing artifact discovery."""

import json
import re
from pathlib import Path
from typing import Any

from kratos_guard.core.manifests import generate_manifest
from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import (
    ArtifactCandidate,
    ArtifactManifest,
    ProvenanceLink,
    SourceManifest,
)

LITERAL = re.compile(
    r"\b(buildStamp|version|commit|sourceManifestHash|buildId)\s*:\s*[\"']([^\"']+)[\"']"
)


def parse_static_javascript_metadata(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if any(token in text for token in ("eval(", "Function(", "require(", "import(")):
        return {}
    return {match.group(1): match.group(2) for match in LITERAL.finditer(text)}


def discover_artifacts(
    target: Path, profile: dict[str, Any]
) -> tuple[list[ArtifactManifest], list[ProvenanceLink]]:
    target = target.resolve()
    manifests: list[ArtifactManifest] = []
    links: list[ProvenanceLink] = []
    for relative in profile.get("build_discovery_roots", []):
        candidate_path = (target / relative).resolve()
        if not candidate_path.is_dir():
            continue
        candidate = ArtifactCandidate(
            path=str(candidate_path),
            artifact_type="extension_directory",
            discovery_method=f"profile bounded root: {relative}",
            evidence_state=EvidenceState.PROVEN,
            uncertainties=["Directory existence does not prove it was produced by a build."],
        )
        bounded = generate_manifest(
            target,
            scope=relative,
            max_files=int(profile["limits"]["artifact_max_files"]),
            max_total_bytes=int(profile["limits"]["artifact_max_bytes"]),
        )
        metadata: dict[str, str] = {}
        parser = ""
        metadata_source = ""
        manifest_path = candidate_path / "manifest.json"
        if manifest_path.is_file():
            parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
            metadata["version"] = str(parsed.get("version", ""))
            metadata_source = str(manifest_path)
            parser = "json"
        build_info = candidate_path / "buildInfo.js"
        if build_info.is_file():
            metadata.update(parse_static_javascript_metadata(build_info))
            metadata_source = f"{metadata_source};{build_info}".strip(";")
            parser = "json+constrained-js-literals"
        manifests.append(
            ArtifactManifest(
                candidate=candidate,
                file_count=bounded.file_count,
                total_bytes=bounded.total_bytes,
                manifest_sha256=bounded.manifest_sha256,
                embedded_version=metadata.get("version", ""),
                embedded_build_id=metadata.get("buildId", metadata.get("buildStamp", "")),
                embedded_git_head=metadata.get("commit", ""),
                embedded_source_hash=metadata.get("sourceManifestHash", ""),
                parsed_metadata_source=metadata_source,
                parser=parser,
                exclusions=bounded.excluded_paths,
                uncertainties=[
                    "No sealed build manifest containing source HEAD and source-manifest hash."
                ],
            )
        )
    return manifests, links


def source_to_build_link(source: SourceManifest, artifact: ArtifactManifest) -> ProvenanceLink:
    embedded_head = artifact.embedded_git_head
    embedded_hash = artifact.embedded_source_hash
    if embedded_hash and embedded_hash != source.manifest_sha256:
        verdict = EvidenceState.CONTRADICTED
        reason = "embedded source-manifest hash contradicts observed source"
    elif embedded_head and not source.head.startswith(embedded_head):
        verdict = EvidenceState.CONTRADICTED
        reason = "embedded Git HEAD contradicts observed source"
    elif (
        embedded_hash == source.manifest_sha256
        and embedded_head
        and source.head.startswith(embedded_head)
    ):
        verdict = EvidenceState.PROVEN
        reason = "embedded Git HEAD and exact source-manifest hash both match"
    else:
        verdict = EvidenceState.UNPROVEN
        reason = "folder names, versions, timestamps, or Git HEAD alone are insufficient"
    return ProvenanceLink(
        link_type="SOURCE_TO_BUILD",
        source_reference=source.manifest_sha256,
        destination_reference=artifact.manifest_sha256,
        verdict=verdict,
        evidence_references=[artifact.parsed_metadata_source]
        if artifact.parsed_metadata_source
        else [],
        reason=reason,
    )
