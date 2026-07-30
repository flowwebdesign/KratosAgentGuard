"""Ed25519 local trust-root management and attestation signatures."""

import base64
import getpass
import json
import os
import subprocess
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


def key_store_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        raise RuntimeError("LOCALAPPDATA is required for the signing key store")
    return Path(local) / "KratosAgentGuard" / "keys"


def _fingerprint(public_bytes: bytes) -> str:
    return sha256(public_bytes).hexdigest()


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


def initialise_key() -> SigningKeyIdentity:
    root = key_store_root()
    private_path = root / "attestation-ed25519.pem"
    if private_path.exists():
        return inspect_key()
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
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    trust_directory.mkdir(parents=True, exist_ok=True)
    destination = trust_directory / f"{identity.key_id}.pub.json"
    payload = {
        "algorithm": "Ed25519",
        "key_id": identity.key_id,
        "public_key_fingerprint": identity.public_key_fingerprint,
        "public_key_base64": base64.b64encode(public_bytes).decode(),
    }
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return TrustRoot(
        key_id=identity.key_id,
        public_key_fingerprint=identity.public_key_fingerprint,
        trusted_public_key_path=str(destination),
        state="TRUST_ROOT_PROVEN",
    )


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


def rotate_key(reason: str) -> SigningKeyIdentity:
    if not reason.strip():
        raise ValueError("rotation reason is required")
    identity = inspect_key()
    private_path = Path(identity.private_key_path)
    archive = private_path.parent / "rotated"
    archive.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    destination = archive / f"{identity.key_id}-{timestamp}.pem"
    private_path.replace(destination)
    record = archive / f"{identity.key_id}-{timestamp}.json"
    record.write_text(
        json.dumps(
            {
                "key_id": identity.key_id,
                "rotated_at": timestamp,
                "reason": reason,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return initialise_key()
