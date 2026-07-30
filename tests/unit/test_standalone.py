import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import kratos_guard.core.signing as signing
from kratos_guard.core.standalone import (
    append_ledger_entry,
    compare_folder_snapshots,
    create_synthetic_runtime_statement,
    issue_runtime_challenge,
    snapshot_folder,
    verify_ledger,
    verify_runtime_statement,
)


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


def guard_trust_path(tmp_path: Path) -> Path:
    trust = signing.export_public_key(tmp_path / "trust")
    return Path(trust.trusted_public_key_path)


def test_folder_snapshot_is_deterministic_and_detects_drift(tmp_path: Path) -> None:
    root = tmp_path / "observed"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "b.txt").write_text("b", encoding="utf-8")
    first = snapshot_folder(root)
    second = snapshot_folder(root)
    assert first.manifest_sha256 == second.manifest_sha256
    assert [item.relative_path for item in first.files] == ["a.txt", "nested/b.txt"]

    (root / "a.txt").write_text("changed", encoding="utf-8")
    (root / "nested" / "b.txt").unlink()
    (root / "new.txt").write_text("new", encoding="utf-8")
    comparison = compare_folder_snapshots(first, snapshot_folder(root))
    assert comparison.changed == ["a.txt"]
    assert comparison.removed == ["nested/b.txt"]
    assert comparison.added == ["new.txt"]
    assert comparison.verdict == "DRIFT_DETECTED"


def test_folder_snapshot_excludes_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "observed"
    outside = tmp_path / "outside.txt"
    root.mkdir()
    outside.write_text("outside", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    snapshot = snapshot_folder(root)
    assert snapshot.files == []
    assert snapshot.limitations == ["SYMLINK_EXCLUDED:link.txt"]


def test_ledger_is_signed_hash_linked_and_tamper_evident(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    trust = guard_trust_path(tmp_path)
    first = append_ledger_entry(ledger, "guard.started", "standalone", {"value": 1})
    second = append_ledger_entry(ledger, "guard.checked", "standalone", {"value": 2})
    assert second.previous_entry_hash == first.entry_hash
    result = verify_ledger(ledger, trust)
    assert result.verdict == "PASS_LEDGER_VERIFIED"
    assert result.entry_count == 2
    assert result.head_hash == second.entry_hash

    lines = ledger.read_text(encoding="utf-8").splitlines()
    payload = json.loads(lines[0])
    payload["payload"]["value"] = 99
    lines[0] = json.dumps(payload, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tampered = verify_ledger(ledger, trust)
    assert tampered.verdict == "FAIL_LEDGER_VERIFICATION"
    assert tampered.first_error == "ENTRY_HASH_INVALID:1"
    with pytest.raises(ValueError, match="LEDGER_ENTRY_INTEGRITY_INVALID"):
        append_ledger_entry(ledger, "guard.refused", "standalone", {})


def test_missing_ledger_fails_closed(safe_key_store: Path, tmp_path: Path) -> None:
    result = verify_ledger(tmp_path / "missing.jsonl", guard_trust_path(tmp_path))
    assert result.verdict == "BLOCKED_LEDGER_MISSING"
    assert result.signature_state == "UNPROVEN"


def test_synthetic_challenge_response_verifies_but_not_as_loaded_user_runtime(
    safe_key_store: Path, tmp_path: Path
) -> None:
    observed_at = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    (artifact / "worker.js").write_text("fixture", encoding="utf-8")
    expected = snapshot_folder(artifact).manifest_sha256
    challenge = issue_runtime_challenge(
        "standalone-fixture",
        expected_build_id="fixture-build",
        expected_artifact_sha256=expected,
        now=observed_at,
    )
    producer_trust = tmp_path / "producer.pub.json"
    statement = create_synthetic_runtime_statement(
        challenge,
        artifact,
        producer_trust,
        build_id="fixture-build",
        now=observed_at + timedelta(seconds=1),
    )
    result = verify_runtime_statement(
        challenge,
        statement,
        guard_trust_path(tmp_path),
        producer_trust,
        tmp_path / "replay",
        now=observed_at + timedelta(seconds=2),
    )
    assert result.verdict == "PASS_SYNTHETIC_RUNTIME_ATTESTATION"
    assert result.current_user_loaded_runtime_state == "UNPROVEN_SYNTHETIC_SCOPE"
    assert result.blockers == []


def test_runtime_attestation_replay_is_rejected(safe_key_store: Path, tmp_path: Path) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    (artifact / "worker.js").write_text("fixture", encoding="utf-8")
    challenge = issue_runtime_challenge("fixture", now=now)
    producer_trust = tmp_path / "producer.pub.json"
    statement = create_synthetic_runtime_statement(
        challenge, artifact, producer_trust, now=now + timedelta(seconds=1)
    )
    trust = guard_trust_path(tmp_path)
    replay = tmp_path / "replay"
    first = verify_runtime_statement(
        challenge, statement, trust, producer_trust, replay, now=now + timedelta(seconds=2)
    )
    second = verify_runtime_statement(
        challenge, statement, trust, producer_trust, replay, now=now + timedelta(seconds=3)
    )
    assert first.verdict == "PASS_SYNTHETIC_RUNTIME_ATTESTATION"
    assert second.verdict == "FAIL_RUNTIME_ATTESTATION"
    assert "ATTESTATION_REPLAY_DETECTED" in second.blockers


def test_expired_or_wrong_build_attestation_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    (artifact / "worker.js").write_text("fixture", encoding="utf-8")
    challenge = issue_runtime_challenge(
        "fixture", expected_build_id="required-build", ttl_seconds=1, now=now
    )
    producer_trust = tmp_path / "producer.pub.json"
    statement = create_synthetic_runtime_statement(
        challenge, artifact, producer_trust, build_id="wrong-build", now=now
    )
    result = verify_runtime_statement(
        challenge,
        statement,
        guard_trust_path(tmp_path),
        producer_trust,
        tmp_path / "replay",
        now=now + timedelta(seconds=2),
    )
    assert result.verdict == "FAIL_RUNTIME_ATTESTATION"
    assert "CHALLENGE_EXPIRED" in result.blockers
    assert "BUILD_ID_MISMATCH" in result.blockers


def test_tampered_challenge_signature_fails_closed(safe_key_store: Path, tmp_path: Path) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    challenge = issue_runtime_challenge("fixture", now=now)
    producer_trust = tmp_path / "producer.pub.json"
    statement = create_synthetic_runtime_statement(challenge, artifact, producer_trust, now=now)
    challenge.subject = "tampered"
    result = verify_runtime_statement(
        challenge,
        statement,
        guard_trust_path(tmp_path),
        producer_trust,
        tmp_path / "replay",
        now=now,
    )
    assert result.verdict == "FAIL_RUNTIME_ATTESTATION"
    assert "CHALLENGE_SIGNATURE_INVALID" in result.blockers
    assert "SUBJECT_MISMATCH" in result.blockers
