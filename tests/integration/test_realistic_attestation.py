import json
import subprocess
from pathlib import Path

import pytest

import kratos_guard.core.signing as signing
from kratos_guard.core.sealed_build import (
    build_sealed_candidate,
    verify_candidate,
)
from kratos_guard.models import EvidenceState


@pytest.fixture
def isolated_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    key_root = tmp_path / "local-key-store"
    monkeypatch.setattr(signing, "key_store_root", lambda: key_root)
    monkeypatch.setattr(signing, "_restrict_key_directory", lambda path: path.mkdir(parents=True))
    original = signing.assess_key_storage

    def safe(path: Path | None = None):
        return original(path or key_root).model_copy(
            update={
                "exists": True,
                "restrictive_acl": True,
                "broadly_writable": False,
                "state": "TRUST_ROOT_PROVEN",
            }
        )

    monkeypatch.setattr(signing, "assess_key_storage", safe)
    identity = signing.initialise_key()
    trust = signing.export_public_key(tmp_path / "trust")
    assert identity.key_id == trust.key_id
    return key_root, Path(trust.trusted_public_key_path)


def target(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    extension = root / "Study_master" / "extension"
    extension.mkdir(parents=True)
    (extension / "manifest.json").write_text(
        json.dumps({"manifest_version": 3, "name": "Test", "version": "1.0"}),
        encoding="utf-8",
    )
    (extension / "README.md").write_text("# Test Extension", encoding="utf-8")
    (extension / "background.js").write_text("const x = 1;\n", encoding="utf-8")
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "-m", "source"], check=True, capture_output=True
    )
    return root


def profile() -> dict[str, object]:
    return {"mutation_sentinels": ["Study_master/extension/manifest.json"]}


def test_new_sealed_candidate_proves_source_to_build(
    tmp_path: Path, isolated_key: tuple[Path, Path]
) -> None:
    _, trusted = isolated_key
    source = target(tmp_path)
    before = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain=v2", "--untracked-files=all"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    result = build_sealed_candidate(source, tmp_path / "guard", profile(), "r" * 64)
    verification = verify_candidate(Path(result.candidate_directory), trusted)
    after = subprocess.run(
        ["git", "-C", str(source), "status", "--porcelain=v2", "--untracked-files=all"],
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    assert verification.overall_provenance_state is EvidenceState.PROVEN
    assert before == after
    assert not any(path.name.startswith("kratos") for path in source.rglob("*"))


def test_tampered_source_claim_is_contradicted(
    tmp_path: Path, isolated_key: tuple[Path, Path]
) -> None:
    _, trusted = isolated_key
    result = build_sealed_candidate(target(tmp_path), tmp_path / "guard", profile(), "r" * 64)
    workspace = Path(result.candidate_directory)
    input_path = workspace / "evidence" / "build-input-manifest.json"
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    payload["repository_head"] = "tampered"
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    verification = verify_candidate(workspace, trusted)
    assert verification.source_claim_state is EvidenceState.CONTRADICTED


def test_tampered_build_input_hash_is_contradicted(
    tmp_path: Path, isolated_key: tuple[Path, Path]
) -> None:
    _, trusted = isolated_key
    result = build_sealed_candidate(target(tmp_path), tmp_path / "guard", profile(), "r" * 64)
    workspace = Path(result.candidate_directory)
    input_path = workspace / "evidence" / "build-input-manifest.json"
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    payload["manifest_sha256"] = "tampered"
    input_path.write_text(json.dumps(payload), encoding="utf-8")
    assert verify_candidate(workspace, trusted).build_input_state is EvidenceState.CONTRADICTED


def test_tampered_artifact_payload_is_contradicted(
    tmp_path: Path, isolated_key: tuple[Path, Path]
) -> None:
    _, trusted = isolated_key
    result = build_sealed_candidate(target(tmp_path), tmp_path / "guard", profile(), "r" * 64)
    workspace = Path(result.candidate_directory)
    (workspace / "artefact" / "extension" / "background.js").write_text(
        "tampered", encoding="utf-8"
    )
    assert verify_candidate(workspace, trusted).artefact_claim_state is EvidenceState.CONTRADICTED


def test_valid_signature_does_not_prove_unsupported_claims(
    tmp_path: Path, isolated_key: tuple[Path, Path]
) -> None:
    _, trusted = isolated_key
    result = build_sealed_candidate(target(tmp_path), tmp_path / "guard", profile(), "r" * 64)
    workspace = Path(result.candidate_directory)
    (workspace / "artefact" / "extension" / "background.js").write_text(
        "different", encoding="utf-8"
    )
    verification = verify_candidate(workspace, trusted)
    assert verification.signature_state is EvidenceState.PROVEN
    assert verification.overall_provenance_state is EvidenceState.CONTRADICTED
