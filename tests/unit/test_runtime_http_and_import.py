import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest

from kratos_guard.adapters.docker import assert_docker_read_only
from kratos_guard.adapters.runtime import inspect_listeners
from kratos_guard.core.loaded_evidence import envelope_integrity, validate_envelope
from kratos_guard.models import EvidenceState


def test_port_to_process_identity_can_be_observed() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        results = inspect_listeners({port})
        assert any(endpoint.port == port for item in results for endpoint in item.endpoints)


def test_process_identity_does_not_prove_build_identity() -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        results = inspect_listeners({server.getsockname()[1]})
        assert results and all(
            item.state in {EvidenceState.PROVEN, EvidenceState.INSPECTION_FAILED}
            for item in results
        )


def test_docker_mutating_commands_are_rejected() -> None:
    with pytest.raises(PermissionError):
        assert_docker_read_only(["restart", "container"])
    assert_docker_read_only(["image", "inspect", "sha256:abc"])


def envelope() -> dict[str, object]:
    payload: dict[str, object] = {
        "extension_id": "abc",
        "extension_version": "1.0",
        "candidate_id": "candidate",
        "build_hash": "b" * 64,
        "source_head": "abc",
        "source_manifest_hash": "a" * 64,
        "collection_method": "external signed collector",
        "collection_timestamp": datetime.now(UTC).isoformat(),
        "profile_identity": "Default",
    }
    payload["integrity_hash"] = envelope_integrity(payload)
    return payload


def test_imported_loaded_client_evidence_is_schema_validated(tmp_path: Path) -> None:
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(envelope()), encoding="utf-8")
    assert validate_envelope(path).candidate_id == "candidate"


def test_tampered_evidence_envelope_is_rejected(tmp_path: Path) -> None:
    payload = envelope()
    payload["build_hash"] = "tampered"
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        validate_envelope(path)
