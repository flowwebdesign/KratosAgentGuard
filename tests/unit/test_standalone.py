import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

import kratos_guard.core.signing as signing
from kratos_guard.core.standalone import (
    append_ledger_entry,
    canonical_json_bytes,
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


def test_folder_snapshot_enforces_total_byte_limit(tmp_path: Path) -> None:
    root = tmp_path / "observed"
    root.mkdir()
    (root / "a.txt").write_text("1234", encoding="utf-8")
    (root / "b.txt").write_text("5678", encoding="utf-8")

    with pytest.raises(ValueError, match="MAX_TOTAL_BYTES_EXCEEDED:7"):
        snapshot_folder(root, max_total_bytes=7)


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


def test_ledger_append_rejects_rehashed_entry_with_invalid_signature(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    append_ledger_entry(ledger, "guard.started", "standalone", {})
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["signature"] = "AAAA"
    unsigned_hash_payload = dict(payload)
    unsigned_hash_payload.pop("entry_hash")
    payload["entry_hash"] = sha256(canonical_json_bytes(unsigned_hash_payload)).hexdigest()
    ledger.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="LEDGER_ENTRY_SIGNATURE_INVALID"):
        append_ledger_entry(ledger, "guard.refused", "standalone", {})


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


def test_runtime_statement_key_substitution_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    challenge = issue_runtime_challenge("fixture", now=now)
    correct_trust = tmp_path / "correct.pub.json"
    substituted_trust = tmp_path / "substituted.pub.json"
    statement = create_synthetic_runtime_statement(
        challenge, artifact, correct_trust, now=now + timedelta(seconds=1)
    )
    create_synthetic_runtime_statement(
        challenge, artifact, substituted_trust, now=now + timedelta(seconds=1)
    )

    result = verify_runtime_statement(
        challenge,
        statement,
        guard_trust_path(tmp_path),
        substituted_trust,
        tmp_path / "replay",
        now=now + timedelta(seconds=2),
    )

    assert result.verdict == "FAIL_RUNTIME_ATTESTATION"
    assert result.producer_signature_state == "SIGNATURE_INVALID"
    assert result.blockers == ["PRODUCER_SIGNATURE_INVALID"]
    assert not (tmp_path / "replay").exists()


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


def test_runtime_challenge_cannot_be_reused_with_a_new_signed_statement(
    safe_key_store: Path, tmp_path: Path
) -> None:
    now = datetime.now(UTC)
    artifact = tmp_path / "fixture"
    artifact.mkdir()
    (artifact / "worker.js").write_text("fixture", encoding="utf-8")
    challenge = issue_runtime_challenge("fixture", now=now)
    first_trust = tmp_path / "producer-one.pub.json"
    second_trust = tmp_path / "producer-two.pub.json"
    first_statement = create_synthetic_runtime_statement(
        challenge, artifact, first_trust, now=now + timedelta(seconds=1)
    )
    second_statement = create_synthetic_runtime_statement(
        challenge, artifact, second_trust, now=now + timedelta(seconds=2)
    )
    assert first_statement.statement_id != second_statement.statement_id
    replay = tmp_path / "replay"
    guard_trust = guard_trust_path(tmp_path)

    first = verify_runtime_statement(
        challenge,
        first_statement,
        guard_trust,
        first_trust,
        replay,
        now=now + timedelta(seconds=3),
    )
    second = verify_runtime_statement(
        challenge,
        second_statement,
        guard_trust,
        second_trust,
        replay,
        now=now + timedelta(seconds=4),
    )

    assert first.verdict == "PASS_SYNTHETIC_RUNTIME_ATTESTATION"
    assert second.verdict == "FAIL_RUNTIME_ATTESTATION"
    assert second.replay_state == "REPLAY_DETECTED"
    assert second.blockers == ["ATTESTATION_REPLAY_DETECTED"]
    assert list(replay.glob("*.json")) == [replay / f"{challenge.challenge_id}.json"]


def test_stale_dead_process_ledger_lock_is_recovered(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    lock = ledger.with_suffix(".jsonl.lock")
    lock.write_text(
        json.dumps(
            {
                "created_at": "2000-01-01T00:00:00+00:00",
                "process_id": 2_147_483_647,
                "token": "a" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    entry = append_ledger_entry(
        ledger,
        "guard.recovered",
        "standalone",
        {},
        stale_lock_seconds=1,
    )

    assert entry.sequence == 1
    assert not lock.exists()


def test_live_process_ledger_lock_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    lock = ledger.with_suffix(".jsonl.lock")
    original = {
        "created_at": "2000-01-01T00:00:00+00:00",
        "process_id": os.getpid(),
        "token": "b" * 64,
    }
    lock.write_text(json.dumps(original) + "\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="LOCK_ALREADY_HELD"):
        append_ledger_entry(
            ledger,
            "guard.refused",
            "standalone",
            {},
            stale_lock_seconds=1,
        )

    assert json.loads(lock.read_text(encoding="utf-8")) == original
    assert not ledger.exists()


def test_malformed_stale_ledger_lock_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    lock = ledger.with_suffix(".jsonl.lock")
    lock.write_text("pid=unknown\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="LOCK_ALREADY_HELD"):
        append_ledger_entry(
            ledger,
            "guard.refused",
            "standalone",
            {},
            stale_lock_seconds=1,
        )

    assert lock.read_text(encoding="utf-8") == "pid=unknown\n"
    assert not ledger.exists()


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
