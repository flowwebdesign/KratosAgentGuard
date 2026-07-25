import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

import kratos_guard.core.browser_canary as canary
from kratos_guard.core.signing import calculate_attestation_integrity
from kratos_guard.models import EvidenceState
from kratos_guard.models.build import BuildAttestation, BuilderIdentity


def attestation() -> BuildAttestation:
    value = BuildAttestation(
        schema_version="1.0",
        project="itzako",
        component="extension",
        candidate_id="candidate",
        source_repository="repository",
        source_head="source-head",
        source_dirty=True,
        source_staged=False,
        repository_source_manifest_hash="r" * 64,
        component_build_input_manifest_hash="i" * 64,
        dependency_lockfile_hashes={},
        build_script_hashes={},
        configuration_hashes={},
        builder=BuilderIdentity(
            guard_version="0.4.0",
            guard_head="guard-head",
            python_version="3.12",
            operating_system="test",
            node_version="v24",
            package_manager_version="NOT_APPLICABLE",
        ),
        guard_head="guard-head",
        guard_version="0.4.0",
        build_command=["internal"],
        build_started_at=datetime.now(UTC),
        build_finished_at=datetime.now(UTC),
        build_exit_code=0,
        build_environment_policy_hash="p" * 64,
        artefact_payload_manifest_hash="a" * 64,
        artefact_file_count=1,
        artefact_total_bytes=1,
        build_reproducibility_state="REPRODUCIBLE_BUILD_PROVEN",
        signing_key_id="ed25519-test",
        signature_algorithm="Ed25519",
        signature="signature",
        attestation_created_at=datetime.now(UTC),
        limitations=[],
        evidence_references=[],
    )
    value.integrity_sha256 = calculate_attestation_integrity(value)
    return value


def write_attestation(candidate: Path, value: BuildAttestation) -> bytes:
    evidence = candidate / "evidence"
    evidence.mkdir(parents=True)
    raw = (json.dumps(value.model_dump(mode="json"), indent=2, sort_keys=True) + "\n").encode()
    (evidence / "build-attestation.json").write_bytes(raw)
    return raw


@pytest.fixture
def proven_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        canary,
        "verify_candidate",
        lambda candidate, trusted: SimpleNamespace(
            overall_provenance_state=EvidenceState.PROVEN,
            signature_state=EvidenceState.PROVEN,
            signer_trust_state=EvidenceState.PROVEN,
        ),
    )


def test_valid_worker_readback_proves_runtime_link(tmp_path: Path, proven_verifier: None) -> None:
    candidate = tmp_path / "candidate"
    value = attestation()
    raw = write_attestation(candidate, value)
    result = canary.verify_runtime_readback(
        candidate,
        value.model_dump(mode="json"),
        sha256(raw).hexdigest(),
        tmp_path,
        "extension-service-worker-fetch",
    )
    assert result.state is EvidenceState.PROVEN
    assert result.source == "extension-service-worker-fetch"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("candidate_id", "other-candidate"),
        ("artefact_payload_manifest_hash", "b" * 64),
        ("signing_key_id", "ed25519-other"),
    ],
)
def test_runtime_identity_mismatch_is_contradicted(
    tmp_path: Path,
    proven_verifier: None,
    field: str,
    replacement: str,
) -> None:
    candidate = tmp_path / "candidate"
    disk = attestation()
    write_attestation(candidate, disk)
    runtime = disk.model_copy(update={field: replacement})
    runtime.integrity_sha256 = calculate_attestation_integrity(runtime)
    runtime_raw = (
        json.dumps(runtime.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    ).encode()
    result = canary.verify_runtime_readback(
        candidate,
        runtime.model_dump(mode="json"),
        sha256(runtime_raw).hexdigest(),
        tmp_path,
    )
    assert result.state is EvidenceState.CONTRADICTED
