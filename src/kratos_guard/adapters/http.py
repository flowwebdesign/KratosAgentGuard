"""Allowlisted read-only HTTP identity observations."""

from datetime import UTC, datetime
from hashlib import sha256
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from kratos_guard.models import EvidenceState
from kratos_guard.models.provenance import HttpIdentityObservation
from kratos_guard.reporting.redaction import redact_text


def observe_http(
    url: str, method: str, purpose: str, timeout: float = 2.0
) -> HttpIdentityObservation:
    if method not in {"HEAD", "GET"}:
        raise PermissionError("only HEAD and explicitly allowlisted GET observations are supported")
    started = datetime.now(UTC)
    status = None
    content_type = ""
    body = b""
    try:
        request = Request(url, method=method, headers={"User-Agent": "kratos-agent-guard/0.2"})
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            status = response.status
            content_type = response.headers.get("content-type", "")
            body = response.read(16384) if method == "GET" else b""
    except HTTPError as error:
        status = error.code
    except (OSError, URLError):
        pass
    duration = (datetime.now(UTC) - started).total_seconds() * 1000
    return HttpIdentityObservation(
        url=redact_text(url),
        method=method,
        status=status,
        content_type=content_type,
        body_sha256=sha256(body).hexdigest() if body else "",
        body_excerpt=redact_text(body.decode(errors="replace")[:2048]),
        duration_ms=duration,
        purpose=purpose,
        state=EvidenceState.PROVEN if status is not None else EvidenceState.INSPECTION_FAILED,
    )


def get_status(url: str, timeout: float = 1.0) -> tuple[int | None, str]:
    result = observe_http(url, "GET", "legacy reachability", timeout)
    return result.status, result.content_type
