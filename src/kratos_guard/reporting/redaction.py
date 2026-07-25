"""Redaction before evidence persistence."""

import re
from typing import Any

SECRET_KEY = re.compile(
    r"(token|secret|password|passwd|cookie|authorization|api[_-]?key|access[_-]?key|dsn)",
    re.IGNORECASE,
)
PATTERNS = [
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (
        re.compile(r"(?i)\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+"),
        r"\1: [REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(password|passwd|api[_-]?key|access[_-]?token)\s*[=:]\s*[^\s&;]+"),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)([a-z][a-z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@"),
        r"\1[REDACTED]:[REDACTED]@",
    ),
    (
        re.compile(r"(?i)([?&](?:access_token|token|api_key|key)=)[^&#\s]+"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED PRIVATE KEY]",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED JWT]",
    ),
    (
        re.compile(r"(?im)^\s*[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|COOKIE|API_KEY)[A-Z0-9_]*=.*$"),
        "[REDACTED ENV]",
    ),
]


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SECRET_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_exception(error: BaseException) -> str:
    return redact_text(f"{type(error).__name__}: {error}")
