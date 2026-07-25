"""Imported loaded-client evidence trust boundary."""

import json
from hashlib import sha256
from pathlib import Path

from kratos_guard.models.provenance import LoadedClientEvidenceEnvelope


def envelope_integrity(payload: dict[str, object]) -> str:
    canonical = {key: value for key, value in payload.items() if key != "integrity_hash"}
    return sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def validate_envelope(path: Path) -> LoadedClientEvidenceEnvelope:
    payload = json.loads(path.read_text(encoding="utf-8"))
    envelope = LoadedClientEvidenceEnvelope.model_validate(payload)
    if envelope.integrity_hash != envelope_integrity(payload):
        raise ValueError("loaded-client evidence integrity hash mismatch")
    return envelope
