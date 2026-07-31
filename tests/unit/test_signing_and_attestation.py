from datetime import UTC, datetime
from pathlib import Path

import pytest

import kratos_guard.core.signing as signing
from kratos_guard.models.build import BuilderIdentity


@pytest.fixture
def safe_key_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "keys"
    monkeypatch.setattr(signing, "key_store_root", lambda: root)
    monkeypatch.setattr(signing, "_restrict_key_directory", lambda path: path.mkdir(parents=True))
    original = signing.assess_key_storage

    def safe(path: Path | None = None):
        assessment = original(path or root)
        return assessment.model_copy(
            update={
                "exists": True,
                "restrictive_acl": True,
                "broadly_writable": False,
                "state": "TRUST_ROOT_PROVEN",
            }
        )

    monkeypatch.setattr(signing, "assess_key_storage", safe)
    signing.initialise_key()
    return root


def test_windows_key_store_uses_local_app_data() -> None:
    local_app_data = Path("C:/Users/test/AppData/Local")
    assert signing.key_store_root(
        environment={"LOCALAPPDATA": str(local_app_data)},
        platform_name="win32",
        home=Path("C:/Users/test"),
    ) == local_app_data / "KratosAgentGuard" / "keys"


def test_linux_key_store_uses_xdg_data_home(tmp_path: Path) -> None:
    data_home = tmp_path / "xdg"
    assert signing.key_store_root(
        environment={"XDG_DATA_HOME": str(data_home)},
        platform_name="linux",
        home=tmp_path / "home",
    ) == data_home / "kratos-agent-guard" / "keys"


def test_linux_key_store_has_native_home_fallback(tmp_path: Path) -> None:
    home = tmp_path / "home"
    assert signing.key_store_root(
        environment={},
        platform_name="linux",
        home=home,
    ) == home / ".local" / "share" / "kratos-agent-guard" / "keys"


def test_linux_key_store_rejects_relative_xdg_data_home(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="XDG_DATA_HOME must be an absolute path"):
        signing.key_store_root(
            environment={"XDG_DATA_HOME": "relative"},
            platform_name="linux",
            home=tmp_path,
        )


def test_private_key_is_outside_repository(safe_key_store: Path, tmp_path: Path) -> None:
    identity = signing.inspect_key()
    assert Path(identity.private_key_path).is_relative_to(safe_key_store)
    assert not Path(identity.private_key_path).is_relative_to(tmp_path / "repo")


def test_existing_key_is_not_silently_overwritten(safe_key_store: Path) -> None:
    first = signing.inspect_key()
    second = signing.initialise_key()
    assert first.public_key_fingerprint == second.public_key_fingerprint


def test_public_key_fingerprint_is_stable(safe_key_store: Path) -> None:
    assert (
        signing.inspect_key().public_key_fingerprint == signing.inspect_key().public_key_fingerprint
    )


def test_public_export_contains_no_private_key(safe_key_store: Path, tmp_path: Path) -> None:
    trust = signing.export_public_key(tmp_path / "trust")
    content = Path(trust.trusted_public_key_path).read_text(encoding="utf-8")
    assert "PRIVATE KEY" not in content
    assert "public_key_base64" in content


def test_canonical_json_is_deterministic(safe_key_store: Path) -> None:
    attestation = attestation_fixture()
    first = signing.canonicalise_attestation_payload(attestation)
    second = signing.canonicalise_attestation_payload(attestation)
    assert first == second


def attestation_fixture():
    from kratos_guard.models.build import BuildAttestation

    return BuildAttestation(
        schema_version="1.0",
        project="itzako",
        component="extension",
        candidate_id="candidate",
        source_repository="flowwebdesign/Study-Pilot",
        source_head="abc",
        source_dirty=True,
        source_staged=False,
        repository_source_manifest_hash="r" * 64,
        component_build_input_manifest_hash="i" * 64,
        dependency_lockfile_hashes={},
        build_script_hashes={},
        configuration_hashes={},
        builder=BuilderIdentity(
            guard_version="0.3.0",
            guard_head="g",
            python_version="3.12",
            operating_system="test",
            node_version="v20",
            package_manager_version="NOT_APPLICABLE",
        ),
        guard_head="g",
        guard_version="0.3.0",
        build_command=["internal"],
        build_started_at=datetime.now(UTC),
        build_finished_at=datetime.now(UTC),
        build_exit_code=0,
        build_environment_policy_hash="p" * 64,
        artefact_payload_manifest_hash="a" * 64,
        artefact_file_count=1,
        artefact_total_bytes=1,
        build_reproducibility_state="REPRODUCIBLE_BUILD_PROVEN",
        signing_key_id="placeholder",
        signature_algorithm="Ed25519",
        attestation_created_at=datetime.now(UTC),
        limitations=[],
        evidence_references=[],
    )


def test_attestation_signature_verifies(safe_key_store: Path, tmp_path: Path) -> None:
    identity = signing.inspect_key()
    trust = signing.export_public_key(tmp_path / "trust")
    attestation = attestation_fixture()
    attestation.signing_key_id = identity.key_id
    signing.sign_attestation(attestation)
    result = signing.verify_attestation_signature(attestation, Path(trust.trusted_public_key_path))
    assert result.signature_state == "SIGNATURE_VALID"
    assert result.signer_trust_state == "TRUST_ROOT_PROVEN"


def test_tampered_signature_fails(safe_key_store: Path, tmp_path: Path) -> None:
    identity = signing.inspect_key()
    trust = signing.export_public_key(tmp_path / "trust")
    attestation = attestation_fixture()
    attestation.signing_key_id = identity.key_id
    signing.sign_attestation(attestation)
    attestation.source_head = "tampered"
    assert (
        signing.verify_attestation_signature(
            attestation, Path(trust.trusted_public_key_path)
        ).signature_state
        == "SIGNATURE_INVALID"
    )


def test_signature_field_is_excluded_from_signed_payload(safe_key_store: Path) -> None:
    attestation = attestation_fixture()
    before = signing.canonicalise_attestation_payload(attestation)
    attestation.signature = "different"
    assert signing.canonicalise_attestation_payload(attestation) == before
