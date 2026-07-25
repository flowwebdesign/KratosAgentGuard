from kratos_guard.reporting.redaction import redact


def test_redaction_removes_secrets() -> None:
    payload = {"api_key": "secret-value", "header": "Bearer abc.def"}
    assert redact(payload) == {"api_key": "[REDACTED]", "header": "Bearer [REDACTED]"}
