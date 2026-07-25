"""Bounded file hashing."""

from hashlib import sha256
from pathlib import Path

from kratos_guard.models import HashEvidence


def hash_file(path: Path, maximum_bytes: int = 10_000_000) -> HashEvidence:
    size = path.stat().st_size
    if size > maximum_bytes:
        raise ValueError(f"refusing to hash file larger than {maximum_bytes} bytes")
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return HashEvidence(path=str(path.resolve()), digest=digest.hexdigest(), byte_count=size)
