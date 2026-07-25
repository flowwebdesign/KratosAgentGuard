import subprocess
from hashlib import sha256
from pathlib import Path

from kratos_guard.adapters.git import run_git
from kratos_guard.reporting.json_report import write_json
from kratos_guard.reporting.redaction import redact, redact_exception, redact_text


def test_command_evidence_hashes_and_bounds_output(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-b", "main", str(tmp_path)], check=True, capture_output=True)
    for index in range(500):
        (tmp_path / f"file-{index:04}.txt").write_text("x", encoding="utf-8")
    evidence = run_git(tmp_path, ["status", "--porcelain=v2", "--untracked-files=all"])
    assert len(evidence.stdout_sha256) == 64
    assert len(evidence.stderr_sha256) == 64
    assert len(evidence.stdout_excerpt) <= 4096
    assert evidence.stderr_sha256 == sha256(b"").hexdigest()


def test_redaction_handles_adversarial_secret_forms() -> None:
    value = """
Authorization: Bearer abc.def.ghi
COOKIE=session=secret
DATABASE_URL=postgresql://alice:hunter2@localhost/db
https://user:pass@example.com/x?access_token=token123
API_KEY=topsecret
-----BEGIN PRIVATE KEY-----
secret-material
-----END PRIVATE KEY-----
eyJabcdefgh.ijklmnop.qrstuvwx
"""
    redacted = redact_text(value)
    for secret in ("hunter2", "token123", "topsecret", "secret-material", "abc.def.ghi"):
        assert secret not in redacted


def test_nested_redaction_occurs_before_report_serialisation() -> None:
    payload = {"nested": [{"password": "secret"}, "Bearer abc123"], "cookie": "value"}
    rendered = str(redact(payload))
    assert "secret" not in rendered
    assert "abc123" not in rendered
    assert "value" not in rendered


def test_exception_redaction() -> None:
    assert "hunter2" not in redact_exception(ValueError("postgres://u:hunter2@host/db"))


def test_secrets_are_redacted_before_disk_write(tmp_path: Path) -> None:
    from kratos_guard.core.inspection_runner import inspect_target

    target = tmp_path / "target"
    target.mkdir()
    report = inspect_target(target, "itzako")
    report.observations[0].value = "Bearer secret-token"
    output = tmp_path / "report.json"
    write_json(report, output)
    assert "secret-token" not in output.read_text(encoding="utf-8")
