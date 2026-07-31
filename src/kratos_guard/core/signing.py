"""Ed25519 local trust-root management and attestation signatures."""

import base64
import getpass
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from kratos_guard.models.build import (
    BuildAttestation,
    KeyStorageAssessment,
    SignatureEvidence,
    SigningKeyIdentity,
    TrustRoot,
)
from kratos_guard.models.standalone import KeyRevocationRecord, KeyRotationRecord


def key_store_root(
    *,
    environment: Mapping[str, str] | None = None,
    platform_name: str | None = None,
    home: Path | None = None,
) -> Path:
    """Return the native per-user data path for the Guard private key."""
    current_environment = os.environ if environment is None else environment
    current_platform = sys.platform if platform_name is None else platform_name
    if current_platform == "win32":
        local = current_environment.get("LOCALAPPDATA")
        if not local:
            raise RuntimeError("LOCALAPPDATA is required for the Windows signing key store")
        return Path(local) / "KratosAgentGuard" / "keys"
    user_home = Path.home() if home is None else home
    if current_platform == "darwin":
        return user_home / "Library" / "Application Support" / "KratosAgentGuard" / "keys"
    xdg_data_home = current_environment.get("XDG_DATA_HOME")
    data_home = Path(xdg_data_home) if xdg_data_home else user_home / ".local" / "share"
    if not data_home.is_absolute():
        raise RuntimeError("XDG_DATA_HOME must be an absolute path")
    return data_home / "kratos-agent-guard" / "keys"


def _fingerprint(public_bytes: bytes) -> str:
    return sha256(public_bytes).hexdigest()


def _canonical_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def local_trust_directory() -> Path:
    return key_store_root() / "trust"


def _public_key_payload(private: Ed25519PrivateKey) -> dict[str, str]:
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = _fingerprint(public_bytes)
    return {
        "algorithm": "Ed25519",
        "key_id": f"ed25519-{fingerprint[:16]}",
        "public_key_fingerprint": fingerprint,
        "public_key_base64": base64.b64encode(public_bytes).decode(),
    }


def _write_public_key(private: Ed25519PrivateKey, trust_directory: Path) -> Path:
    payload = _public_key_payload(private)
    trust_directory.mkdir(parents=True, exist_ok=True)
    destination = trust_directory / f"{payload['key_id']}.pub.json"
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if destination.exists():
        if destination.read_text(encoding="utf-8") != rendered:
            raise ValueError("TRUST_KEY_COLLISION")
        return destination
    destination.write_text(rendered, encoding="utf-8")
    return destination


def _rotation_signing_bytes(record: KeyRotationRecord) -> bytes:
    payload = record.model_dump(mode="json")
    payload.pop("previous_key_signature", None)
    payload.pop("new_key_signature", None)
    return _canonical_bytes(payload)


def _revocation_signing_bytes(record: KeyRevocationRecord) -> bytes:
    payload = record.model_dump(mode="json")
    payload.pop("signature", None)
    return _canonical_bytes(payload)


def assess_key_storage(path: Path | None = None) -> KeyStorageAssessment:
    root = (path or key_store_root()).resolve()
    details: list[str] = []
    broad = False
    restrictive = False
    if root.exists() and os.name == "nt":
        completed = subprocess.run(
            ["icacls", str(root)], capture_output=True, check=False, text=True, timeout=10
        )
        output = completed.stdout
        broad_names = ("Everyone:", "BUILTIN\\Users:", "Authenticated Users:")
        broad = any(
            any(name in line for name in broad_names)
            and any(flag in line for flag in ("(F)", "(M)", "(W)"))
            for line in output.splitlines()
        )
        restrictive = completed.returncode == 0 and not broad
        details.append("Windows ACL inspected with icacls")
    elif root.exists():
        mode = root.stat().st_mode & 0o777
        broad = bool(mode & 0o077)
        restrictive = not broad
        details.append(f"POSIX mode {mode:o}")
    state = (
        "KEY_STORAGE_UNSAFE" if broad else ("TRUST_ROOT_PROVEN" if restrictive else "KEY_MISSING")
    )
    return KeyStorageAssessment(
        path=str(root),
        exists=root.exists(),
        restrictive_acl=restrictive,
        broadly_writable=broad,
        state=state,
        details=details,
    )


def _restrict_key_directory(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        user = getpass.getuser()
        completed = subprocess.run(
            [
                "icacls",
                str(root),
                "/inheritance:r",
                "/grant:r",
                f"{user}:(OI)(CI)F",
                "SYSTEM:(OI)(CI)F",
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0:
            raise PermissionError("failed to apply restrictive key-store ACL")
    else:
        root.chmod(0o700)


def restrict_private_directory(root: Path) -> None:
    """Apply the same private per-user storage boundary to non-key Guard state."""
    _restrict_key_directory(root)


def initialise_key() -> SigningKeyIdentity:
    root = key_store_root()
    private_path = root / "attestation-ed25519.pem"
    if private_path.exists():
        identity = inspect_key()
        private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("KEY_MISMATCH")
        _write_public_key(private, local_trust_directory())
        return identity
    _restrict_key_directory(root)
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_path.write_bytes(private_bytes)
    if os.name != "nt":
        private_path.chmod(0o600)
    _write_public_key(private, local_trust_directory())
    assessment = assess_key_storage(root)
    if not assessment.restrictive_acl:
        private_path.unlink(missing_ok=True)
        raise PermissionError("KEY_STORAGE_UNSAFE")
    return inspect_key()


def inspect_key() -> SigningKeyIdentity:
    root = key_store_root()
    private_path = root / "attestation-ed25519.pem"
    if not private_path.is_file():
        raise FileNotFoundError("KEY_MISSING")
    assessment = assess_key_storage(root)
    if not assessment.restrictive_acl:
        raise PermissionError("KEY_STORAGE_UNSAFE")
    private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = _fingerprint(public_bytes)
    key_id = f"ed25519-{fingerprint[:16]}"
    return SigningKeyIdentity(
        key_id=key_id,
        algorithm="Ed25519",
        public_key_fingerprint=fingerprint,
        private_key_path=str(private_path),
        public_key_path=str(root / f"{key_id}.pub.json"),
        storage=assessment,
    )


def export_public_key(trust_directory: Path) -> TrustRoot:
    identity = inspect_key()
    private = serialization.load_pem_private_key(
        Path(identity.private_key_path).read_bytes(), password=None
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    destination = _write_public_key(private, trust_directory)
    return TrustRoot(
        key_id=identity.key_id,
        public_key_fingerprint=identity.public_key_fingerprint,
        trusted_public_key_path=str(destination),
        state="TRUST_ROOT_PROVEN",
    )


def export_trust_bundle(destination: Path) -> list[Path]:
    """Export all public keys and signed lifecycle records; never private keys."""
    initialise_key()
    source = local_trust_directory()
    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    exported: list[Path] = []
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        exported.append(target)
    return exported


def trusted_key_path(trust_path: Path, key_id: str) -> Path:
    if trust_path.is_file():
        return trust_path
    return trust_path / f"{key_id}.pub.json"


def verify_key_rotation(
    previous_key_id: str,
    new_key_id: str,
    trust_directory: Path,
) -> bool:
    record_path = (
        trust_directory / "rotations" / f"{previous_key_id}-to-{new_key_id}.json"
    )
    if not record_path.is_file():
        return False
    try:
        record = KeyRotationRecord.model_validate_json(
            record_path.read_text(encoding="utf-8")
        )
        if (
            record.previous_key_id != previous_key_id
            or record.new_key_id != new_key_id
        ):
            return False
        payload = _rotation_signing_bytes(record)
        previous = verify_payload_signature(
            payload,
            record.previous_key_signature,
            trusted_key_path(trust_directory, previous_key_id),
            previous_key_id,
        )
        new = verify_payload_signature(
            payload,
            record.new_key_signature,
            trusted_key_path(trust_directory, new_key_id),
            new_key_id,
        )
    except (FileNotFoundError, OSError, ValueError):
        return False
    return (
        previous.signature_state == "SIGNATURE_VALID"
        and previous.signer_trust_state == "TRUST_ROOT_PROVEN"
        and new.signature_state == "SIGNATURE_VALID"
        and new.signer_trust_state == "TRUST_ROOT_PROVEN"
    )


def key_revocation_state(key_id: str, trust_directory: Path) -> str:
    path = trust_directory / "revocations" / f"{key_id}.json"
    if not path.is_file():
        return "NOT_REVOKED"
    try:
        record = KeyRevocationRecord.model_validate_json(path.read_text(encoding="utf-8"))
        if record.revoked_key_id != key_id:
            return "REVOCATION_INVALID"
        verification = verify_payload_signature(
            _revocation_signing_bytes(record),
            record.signature,
            trusted_key_path(trust_directory, record.authorised_by_key_id),
            record.authorised_by_key_id,
        )
    except (FileNotFoundError, OSError, ValueError):
        return "REVOCATION_INVALID"
    if (
        verification.signature_state != "SIGNATURE_VALID"
        or verification.signer_trust_state != "TRUST_ROOT_PROVEN"
    ):
        return "REVOCATION_INVALID"
    return "REVOKED"


def is_key_revoked(key_id: str, trust_directory: Path) -> bool:
    return key_revocation_state(key_id, trust_directory) != "NOT_REVOKED"


def canonicalise_attestation_payload(attestation: BuildAttestation) -> bytes:
    payload = attestation.model_dump(mode="json")
    payload.pop("signature", None)
    payload.pop("integrity_sha256", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def calculate_attestation_integrity(attestation: BuildAttestation) -> str:
    return sha256(canonicalise_attestation_payload(attestation)).hexdigest()


def sign_attestation(attestation: BuildAttestation) -> SignatureEvidence:
    identity = inspect_key()
    if identity.key_id != attestation.signing_key_id:
        raise ValueError("KEY_MISMATCH")
    private = serialization.load_pem_private_key(
        Path(identity.private_key_path).read_bytes(), password=None
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    payload = canonicalise_attestation_payload(attestation)
    signature = private.sign(payload)
    attestation.integrity_sha256 = sha256(payload).hexdigest()
    attestation.signature = base64.b64encode(signature).decode()
    return SignatureEvidence(
        algorithm="Ed25519",
        key_id=identity.key_id,
        payload_sha256=attestation.integrity_sha256,
        signature=attestation.signature,
        signature_state="SIGNATURE_VALID",
        signer_trust_state="TRUST_ROOT_PROVEN",
    )


def load_trusted_public_key(path: Path) -> tuple[TrustRoot, Ed25519PublicKey]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    public_bytes = base64.b64decode(payload["public_key_base64"])
    fingerprint = _fingerprint(public_bytes)
    if fingerprint != payload["public_key_fingerprint"]:
        raise ValueError("trusted public-key fingerprint mismatch")
    trust = TrustRoot(
        key_id=payload["key_id"],
        public_key_fingerprint=fingerprint,
        trusted_public_key_path=str(path),
        state="TRUST_ROOT_PROVEN",
    )
    return trust, Ed25519PublicKey.from_public_bytes(public_bytes)


def verify_attestation_signature(
    attestation: BuildAttestation, trusted_key_path: Path
) -> SignatureEvidence:
    trust, public = load_trusted_public_key(trusted_key_path)
    payload = canonicalise_attestation_payload(attestation)
    signature_state = "SIGNATURE_INVALID"
    try:
        public.verify(base64.b64decode(attestation.signature), payload)
        signature_state = "SIGNATURE_VALID"
    except (ValueError, InvalidSignature):
        pass
    signer_state = (
        "TRUST_ROOT_PROVEN" if trust.key_id == attestation.signing_key_id else "SIGNER_UNTRUSTED"
    )
    return SignatureEvidence(
        algorithm="Ed25519",
        key_id=attestation.signing_key_id,
        payload_sha256=sha256(payload).hexdigest(),
        signature=attestation.signature,
        signature_state=signature_state,
        signer_trust_state=signer_state,
    )


def sign_payload_bytes(payload: bytes) -> tuple[SigningKeyIdentity, str]:
    """Sign canonical bytes with the established Guard trust root."""
    identity = inspect_key()
    private = serialization.load_pem_private_key(
        Path(identity.private_key_path).read_bytes(), password=None
    )
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    signature = private.sign(payload)
    return identity, base64.b64encode(signature).decode()


def verify_payload_signature(
    payload: bytes,
    signature: str,
    trusted_key_path: Path,
    expected_key_id: str,
) -> SignatureEvidence:
    """Verify canonical bytes against an explicit public trust-root file."""
    trust, public = load_trusted_public_key(trusted_key_path)
    signature_state = "SIGNATURE_INVALID"
    try:
        public.verify(base64.b64decode(signature, validate=True), payload)
        signature_state = "SIGNATURE_VALID"
    except (ValueError, InvalidSignature):
        pass
    signer_state = (
        "TRUST_ROOT_PROVEN" if trust.key_id == expected_key_id else "SIGNER_UNTRUSTED"
    )
    return SignatureEvidence(
        algorithm="Ed25519",
        key_id=expected_key_id,
        payload_sha256=sha256(payload).hexdigest(),
        signature=signature,
        signature_state=signature_state,
        signer_trust_state=signer_state,
    )


def verify_local_payload_signature(
    payload: bytes,
    signature: str,
    expected_key_id: str,
) -> SignatureEvidence:
    """Verify bytes against the protected local historical trust bundle."""
    initialise_key()
    return verify_payload_signature(
        payload,
        signature,
        trusted_key_path(local_trust_directory(), expected_key_id),
        expected_key_id,
    )


def rotate_key(
    reason: str,
    trust_directory: Path | None = None,
    *,
    now: datetime | None = None,
) -> SigningKeyIdentity:
    if not reason.strip():
        raise ValueError("rotation reason is required")
    old_identity = initialise_key()
    private_path = Path(old_identity.private_key_path)
    old_private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    if not isinstance(old_private, Ed25519PrivateKey):
        raise ValueError("KEY_MISMATCH")
    root = private_path.parent
    lock_path = root / "rotation.lock"
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise RuntimeError("KEY_ROTATION_ALREADY_ACTIVE") from error
    try:
        os.write(descriptor, f"{os.getpid()}\n".encode())
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        abandoned_candidates = [
            root / "attestation-ed25519.pem.next",
            *root.glob(".attestation-ed25519.*.next"),
        ]
        for abandoned_next in abandoned_candidates:
            abandoned_next.unlink(missing_ok=True)
        new_private = Ed25519PrivateKey.generate()
        new_payload = _public_key_payload(new_private)
        rotated_at = now or datetime.now(UTC)
        record = KeyRotationRecord(
            previous_key_id=old_identity.key_id,
            new_key_id=new_payload["key_id"],
            rotated_at=rotated_at,
            reason=reason.strip(),
            previous_key_signature="pending",
            new_key_signature="pending",
        )
        payload = _rotation_signing_bytes(record)
        record.previous_key_signature = base64.b64encode(old_private.sign(payload)).decode()
        record.new_key_signature = base64.b64encode(new_private.sign(payload)).decode()

        local_trust = local_trust_directory()
        _write_public_key(old_private, local_trust)
        _write_public_key(new_private, local_trust)
        rotations = local_trust / "rotations"
        rotations.mkdir(parents=True, exist_ok=True)
        record_path = (
            rotations / f"{record.previous_key_id}-to-{record.new_key_id}.json"
        )
        with record_path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(record.model_dump_json(indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

        next_path = root / f".attestation-ed25519.{record.new_key_id}.next"
        with next_path.open("x+b") as stream:
            stream.write(
                new_private.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            next_path.chmod(0o600)
        next_path.replace(private_path)
        if trust_directory is not None:
            export_trust_bundle(trust_directory)
        return inspect_key()
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        lock_path.unlink(missing_ok=True)


def revoke_key(
    key_id: str,
    reason: str,
    trust_directory: Path | None = None,
    *,
    now: datetime | None = None,
) -> KeyRevocationRecord:
    if not reason.strip():
        raise ValueError("revocation reason is required")
    current = initialise_key()
    if key_id == current.key_id:
        raise ValueError("ACTIVE_KEY_MUST_BE_ROTATED_BEFORE_REVOCATION")
    local_trust = local_trust_directory()
    if not trusted_key_path(local_trust, key_id).is_file():
        raise FileNotFoundError("REVOCATION_KEY_UNKNOWN")
    record = KeyRevocationRecord(
        revoked_key_id=key_id,
        authorised_by_key_id=current.key_id,
        revoked_at=now or datetime.now(UTC),
        reason=reason.strip(),
        signature="pending",
    )
    _, record.signature = sign_payload_bytes(_revocation_signing_bytes(record))
    revocations = local_trust / "revocations"
    revocations.mkdir(parents=True, exist_ok=True)
    destination = revocations / f"{key_id}.json"
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(record.model_dump_json(indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    if trust_directory is not None:
        export_trust_bundle(trust_directory)
    return record
