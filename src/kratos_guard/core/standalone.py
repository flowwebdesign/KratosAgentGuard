"""Guard-owned standalone evidence, monitoring, and runtime-attestation primitives."""

import base64
import json
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kratos_guard.core.signing import inspect_key, sign_payload_bytes, verify_payload_signature
from kratos_guard.models.standalone import (
    FolderComparison,
    FolderFileIdentity,
    FolderSnapshot,
    LedgerEntry,
    LedgerVerification,
    RuntimeAttestationVerification,
    RuntimeChallenge,
    RuntimeStatement,
)

ZERO_HASH = "0" * 64
DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        ".work",
        "__pycache__",
        "build",
        "dist",
        "evidence",
        "node_modules",
    }
)


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _model_signing_bytes(model: LedgerEntry | RuntimeChallenge | RuntimeStatement) -> bytes:
    payload = model.model_dump(mode="json")
    payload.pop("signature", None)
    if isinstance(model, LedgerEntry):
        payload.pop("entry_hash", None)
    return canonical_json_bytes(payload)


def _ledger_hash(entry: LedgerEntry) -> str:
    payload = entry.model_dump(mode="json")
    payload.pop("entry_hash", None)
    return sha256(canonical_json_bytes(payload)).hexdigest()


@contextmanager
def _exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise RuntimeError(f"LOCK_ALREADY_HELD:{path}") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode())
        os.fsync(descriptor)
        os.close(descriptor)
        yield
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)


def append_ledger_entry(
    ledger_path: Path,
    event_type: str,
    subject: str,
    payload: dict[str, object],
    *,
    now: datetime | None = None,
) -> LedgerEntry:
    """Append one signed, hash-linked JSONL record with an exclusive writer lock."""
    ledger_path = ledger_path.resolve()
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    with _exclusive_lock(lock_path):
        previous_hash = ZERO_HASH
        sequence = 1
        if ledger_path.is_file():
            lines = [line for line in ledger_path.read_text(encoding="utf-8").splitlines() if line]
            for expected_sequence, line in enumerate(lines, 1):
                previous = LedgerEntry.model_validate_json(line)
                if previous.sequence != expected_sequence:
                    raise ValueError("LEDGER_SEQUENCE_INVALID")
                if previous.previous_entry_hash != previous_hash:
                    raise ValueError("LEDGER_CHAIN_INVALID")
                if _ledger_hash(previous) != previous.entry_hash:
                    raise ValueError("LEDGER_ENTRY_INTEGRITY_INVALID")
                previous_hash = previous.entry_hash
            sequence = len(lines) + 1
        identity = inspect_key()
        entry = LedgerEntry(
            sequence=sequence,
            recorded_at=now or datetime.now(UTC),
            event_type=event_type,
            subject=subject,
            payload=payload,
            previous_entry_hash=previous_hash,
            signing_key_id=identity.key_id,
            signature="pending",
            entry_hash=ZERO_HASH,
        )
        signing_identity, entry.signature = sign_payload_bytes(_model_signing_bytes(entry))
        if signing_identity.key_id != entry.signing_key_id:
            raise RuntimeError("SIGNING_KEY_CHANGED_DURING_APPEND")
        entry.entry_hash = _ledger_hash(entry)
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with ledger_path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(entry.model_dump(mode="json"), sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return entry


def verify_ledger(ledger_path: Path, trusted_key_path: Path) -> LedgerVerification:
    """Verify sequencing, hash links, entry integrity, and every signature."""
    if not ledger_path.is_file():
        return LedgerVerification(
            ledger_path=str(ledger_path.resolve()),
            entry_count=0,
            head_hash=ZERO_HASH,
            chain_state="LEDGER_MISSING",
            signature_state="UNPROVEN",
            first_error="LEDGER_MISSING",
            verdict="BLOCKED_LEDGER_MISSING",
        )
    previous_hash = ZERO_HASH
    head_hash = ZERO_HASH
    count = 0
    chain_state = "CHAIN_VALID"
    signature_state = "SIGNATURE_VALID"
    first_error = ""
    for line_number, line in enumerate(ledger_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        count += 1
        try:
            entry = LedgerEntry.model_validate_json(line)
        except Exception:
            chain_state = "CHAIN_INVALID"
            first_error = f"MALFORMED_ENTRY:{line_number}"
            break
        if entry.sequence != count or entry.previous_entry_hash != previous_hash:
            chain_state = "CHAIN_INVALID"
            first_error = f"CHAIN_LINK_INVALID:{line_number}"
            break
        if _ledger_hash(entry) != entry.entry_hash:
            chain_state = "CHAIN_INVALID"
            first_error = f"ENTRY_HASH_INVALID:{line_number}"
            break
        signature = verify_payload_signature(
            _model_signing_bytes(entry),
            entry.signature,
            trusted_key_path,
            entry.signing_key_id,
        )
        if (
            signature.signature_state != "SIGNATURE_VALID"
            or signature.signer_trust_state != "TRUST_ROOT_PROVEN"
        ):
            signature_state = "SIGNATURE_INVALID"
            first_error = f"ENTRY_SIGNATURE_INVALID:{line_number}"
            break
        previous_hash = entry.entry_hash
        head_hash = entry.entry_hash
    verdict = (
        "PASS_LEDGER_VERIFIED"
        if count > 0 and chain_state == "CHAIN_VALID" and signature_state == "SIGNATURE_VALID"
        else "FAIL_LEDGER_VERIFICATION"
    )
    return LedgerVerification(
        ledger_path=str(ledger_path.resolve()),
        entry_count=count,
        head_hash=head_hash,
        chain_state=chain_state,
        signature_state=signature_state,
        first_error=first_error,
        verdict=verdict,
    )


def issue_runtime_challenge(
    subject: str,
    *,
    expected_build_id: str = "",
    expected_artifact_sha256: str | None = None,
    ttl_seconds: int = 300,
    now: datetime | None = None,
) -> RuntimeChallenge:
    if not 1 <= ttl_seconds <= 3600:
        raise ValueError("ttl_seconds must be between 1 and 3600")
    issued_at = now or datetime.now(UTC)
    identity = inspect_key()
    challenge = RuntimeChallenge(
        challenge_id=secrets.token_hex(16),
        nonce=secrets.token_urlsafe(32),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl_seconds),
        subject=subject,
        expected_build_id=expected_build_id,
        expected_artifact_sha256=expected_artifact_sha256,
        verifier_key_id=identity.key_id,
        signature="pending",
    )
    signing_identity, challenge.signature = sign_payload_bytes(_model_signing_bytes(challenge))
    if signing_identity.key_id != challenge.verifier_key_id:
        raise RuntimeError("SIGNING_KEY_CHANGED_DURING_CHALLENGE")
    return challenge


def snapshot_folder(
    root: Path,
    *,
    max_files: int = 5000,
    max_file_bytes: int = 10_000_000,
    now: datetime | None = None,
) -> FolderSnapshot:
    """Create a deterministic, read-only manifest without following symlinks."""
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    identities: list[FolderFileIdentity] = []
    total_bytes = 0
    limitations: list[str] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in DEFAULT_EXCLUDED_DIRECTORIES
            and not (current_path / directory).is_symlink()
        )
        for filename in sorted(files):
            candidate = current_path / filename
            if candidate.is_symlink():
                limitations.append(f"SYMLINK_EXCLUDED:{candidate.relative_to(root).as_posix()}")
                continue
            stat = candidate.stat()
            relative = candidate.relative_to(root).as_posix()
            if stat.st_size > max_file_bytes:
                limitations.append(f"FILE_TOO_LARGE:{relative}:{stat.st_size}")
                continue
            if len(identities) >= max_files:
                raise ValueError(f"MAX_FILE_COUNT_EXCEEDED:{max_files}")
            digest = sha256(candidate.read_bytes()).hexdigest()
            identities.append(
                FolderFileIdentity(relative_path=relative, sha256=digest, byte_count=stat.st_size)
            )
            total_bytes += stat.st_size
    manifest_payload = [item.model_dump(mode="json") for item in identities]
    manifest_hash = sha256(canonical_json_bytes(manifest_payload)).hexdigest()
    return FolderSnapshot(
        root=str(root),
        observed_at=now or datetime.now(UTC),
        file_count=len(identities),
        total_bytes=total_bytes,
        manifest_sha256=manifest_hash,
        files=identities,
        excluded_directories=sorted(DEFAULT_EXCLUDED_DIRECTORIES),
        limitations=limitations,
    )


def compare_folder_snapshots(
    baseline: FolderSnapshot, current: FolderSnapshot
) -> FolderComparison:
    baseline_files = {item.relative_path: item.sha256 for item in baseline.files}
    current_files = {item.relative_path: item.sha256 for item in current.files}
    added = sorted(current_files.keys() - baseline_files.keys())
    removed = sorted(baseline_files.keys() - current_files.keys())
    changed = sorted(
        path
        for path in baseline_files.keys() & current_files.keys()
        if baseline_files[path] != current_files[path]
    )
    verdict = "PASS_NO_FOLDER_DRIFT" if not (added or removed or changed) else "DRIFT_DETECTED"
    return FolderComparison(
        baseline_manifest_sha256=baseline.manifest_sha256,
        current_manifest_sha256=current.manifest_sha256,
        added=added,
        removed=removed,
        changed=changed,
        verdict=verdict,
    )


def _write_ephemeral_trust_root(private: Ed25519PrivateKey, destination: Path) -> str:
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = sha256(public_bytes).hexdigest()
    key_id = f"synthetic-ed25519-{fingerprint[:16]}"
    payload = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "public_key_fingerprint": fingerprint,
        "public_key_base64": base64.b64encode(public_bytes).decode(),
        "scope": "GUARD_OWNED_SYNTHETIC",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return key_id


def create_synthetic_runtime_statement(
    challenge: RuntimeChallenge,
    artifact_root: Path,
    producer_trust_path: Path,
    *,
    build_id: str = "",
    now: datetime | None = None,
) -> RuntimeStatement:
    """Create a Guard-owned fixture response; it never represents a user's loaded runtime."""
    snapshot = snapshot_folder(artifact_root, now=now)
    private = Ed25519PrivateKey.generate()
    producer_key_id = _write_ephemeral_trust_root(private, producer_trust_path)
    statement = RuntimeStatement(
        statement_id=secrets.token_hex(16),
        challenge_id=challenge.challenge_id,
        nonce=challenge.nonce,
        observed_at=now or datetime.now(UTC),
        subject=challenge.subject,
        runtime_kind="GUARD_SYNTHETIC_FIXTURE",
        producer_scope="GUARD_OWNED_SYNTHETIC",
        build_id=build_id or f"synthetic-{snapshot.manifest_sha256[:16]}",
        artifact_sha256=snapshot.manifest_sha256,
        executable_manifest_sha256=snapshot.manifest_sha256,
        process_id=os.getpid(),
        claims={
            "artifact_file_count": snapshot.file_count,
            "artifact_total_bytes": snapshot.total_bytes,
            "loaded_user_profile": False,
        },
        producer_key_id=producer_key_id,
        signature="pending",
    )
    signature = private.sign(_model_signing_bytes(statement))
    statement.signature = base64.b64encode(signature).decode()
    return statement


def verify_runtime_statement(
    challenge: RuntimeChallenge,
    statement: RuntimeStatement,
    guard_trust_key: Path,
    producer_trust_key: Path,
    replay_root: Path,
    *,
    now: datetime | None = None,
) -> RuntimeAttestationVerification:
    checked_at = now or datetime.now(UTC)
    blockers: list[str] = []
    challenge_signature = verify_payload_signature(
        _model_signing_bytes(challenge),
        challenge.signature,
        guard_trust_key,
        challenge.verifier_key_id,
    )
    if (
        challenge_signature.signature_state != "SIGNATURE_VALID"
        or challenge_signature.signer_trust_state != "TRUST_ROOT_PROVEN"
    ):
        blockers.append("CHALLENGE_SIGNATURE_INVALID")
    producer_signature = verify_payload_signature(
        _model_signing_bytes(statement),
        statement.signature,
        producer_trust_key,
        statement.producer_key_id,
    )
    if (
        producer_signature.signature_state != "SIGNATURE_VALID"
        or producer_signature.signer_trust_state != "TRUST_ROOT_PROVEN"
    ):
        blockers.append("PRODUCER_SIGNATURE_INVALID")
    if statement.challenge_id != challenge.challenge_id:
        blockers.append("CHALLENGE_ID_MISMATCH")
    if not secrets.compare_digest(statement.nonce, challenge.nonce):
        blockers.append("NONCE_MISMATCH")
    if statement.subject != challenge.subject:
        blockers.append("SUBJECT_MISMATCH")
    freshness_state = "FRESH"
    if checked_at < challenge.issued_at or checked_at > challenge.expires_at:
        freshness_state = "EXPIRED"
        blockers.append("CHALLENGE_EXPIRED")
    if statement.observed_at < challenge.issued_at or statement.observed_at > challenge.expires_at:
        freshness_state = "OUTSIDE_CHALLENGE_WINDOW"
        blockers.append("STATEMENT_OUTSIDE_CHALLENGE_WINDOW")
    if challenge.expected_build_id and statement.build_id != challenge.expected_build_id:
        blockers.append("BUILD_ID_MISMATCH")
    if (
        challenge.expected_artifact_sha256
        and statement.artifact_sha256 != challenge.expected_artifact_sha256
    ):
        blockers.append("ARTIFACT_SHA256_MISMATCH")
    replay_root.mkdir(parents=True, exist_ok=True)
    replay_marker = replay_root / f"{challenge.challenge_id}-{statement.statement_id}.json"
    replay_state = "UNUSED"
    if replay_marker.exists():
        replay_state = "REPLAY_DETECTED"
        blockers.append("ATTESTATION_REPLAY_DETECTED")
    if not blockers:
        try:
            descriptor = os.open(replay_marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            replay_state = "REPLAY_DETECTED"
            blockers.append("ATTESTATION_REPLAY_DETECTED")
        else:
            marker = canonical_json_bytes(
                {
                    "challenge_id": challenge.challenge_id,
                    "statement_id": statement.statement_id,
                    "verified_at": checked_at.isoformat(),
                }
            )
            os.write(descriptor, marker + b"\n")
            os.fsync(descriptor)
            os.close(descriptor)
    verdict = (
        "PASS_SYNTHETIC_RUNTIME_ATTESTATION"
        if not blockers and statement.producer_scope == "GUARD_OWNED_SYNTHETIC"
        else ("PASS_RUNTIME_ATTESTATION" if not blockers else "FAIL_RUNTIME_ATTESTATION")
    )
    loaded_state = (
        "UNPROVEN_SYNTHETIC_SCOPE"
        if statement.producer_scope == "GUARD_OWNED_SYNTHETIC"
        else "UNPROVEN_EXTERNAL_ATTESTATION_SCOPE"
    )
    return RuntimeAttestationVerification(
        challenge_id=challenge.challenge_id,
        statement_id=statement.statement_id,
        subject=statement.subject,
        build_id=statement.build_id,
        artifact_sha256=statement.artifact_sha256,
        challenge_signature_state=challenge_signature.signature_state,
        producer_signature_state=producer_signature.signature_state,
        freshness_state=freshness_state,
        replay_state=replay_state,
        producer_scope=statement.producer_scope,
        current_user_loaded_runtime_state=loaded_state,
        blockers=blockers,
        verdict=verdict,
    )
