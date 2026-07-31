import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import kratos_guard.cli as cli
import kratos_guard.core.signing as signing
from kratos_guard.core.standalone import append_ledger_entry
from kratos_guard.models.identity import VerifierIdentity
from kratos_guard.models.state import EvidenceState


@pytest.fixture
def standalone_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[CliRunner, Path]:
    guard_root = tmp_path / "guard"
    guard_root.mkdir()
    key_root = tmp_path / "keys"
    monkeypatch.setattr(signing, "key_store_root", lambda: key_root)
    monkeypatch.setattr(signing, "_restrict_key_directory", lambda path: path.mkdir(parents=True))
    original_assessment = signing.assess_key_storage

    def safe_assessment(path: Path | None = None):
        assessment = original_assessment(path or key_root)
        return assessment.model_copy(
            update={
                "exists": True,
                "restrictive_acl": True,
                "broadly_writable": False,
                "state": "TRUST_ROOT_PROVEN",
            }
        )

    monkeypatch.setattr(signing, "assess_key_storage", safe_assessment)
    signing.initialise_key()
    identity = VerifierIdentity(
        repository_root=str(guard_root),
        git_common_directory=str(guard_root / ".git"),
        branch="main",
        head="a" * 40,
        dirty=False,
        package_name="kratos-agent-guard",
        package_version="test",
        state=EvidenceState.PROVEN,
    )
    monkeypatch.setattr(cli, "verifier_identity", lambda: identity)
    return CliRunner(), guard_root


def test_standalone_status_blocks_when_ledger_is_not_initialised(
    standalone_cli: tuple[CliRunner, Path],
) -> None:
    runner, guard_root = standalone_cli
    result = runner.invoke(cli.app, ["standalone-status"])

    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["guard_repository"] == str(guard_root)
    assert payload["evidence_ledger_state"] == "NOT_INITIALISED"
    assert payload["blockers"] == ["EVIDENCE_LEDGER_NOT_INITIALISED"]
    assert payload["verdict"] == "BLOCKED_STANDALONE_GUARD"


def test_standalone_status_passes_only_after_ledger_signature_verification(
    standalone_cli: tuple[CliRunner, Path],
) -> None:
    runner, guard_root = standalone_cli
    ledger = guard_root / "evidence" / "standalone" / "ledger.jsonl"
    trust = signing.export_public_key(guard_root / "trust" / "keys")
    entry = append_ledger_entry(ledger, "guard.started", "standalone", {})

    result = runner.invoke(
        cli.app,
        [
            "standalone-status",
            "--ledger",
            str(ledger),
            "--trust-key",
            trust.trusted_public_key_path,
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["evidence_ledger_state"] == "PASS_LEDGER_VERIFIED"
    assert payload["evidence_ledger_entry_count"] == 1
    assert payload["evidence_ledger_head_hash"] == entry.entry_hash
    assert payload["blockers"] == []
    assert payload["verdict"] == "PASS_STANDALONE_GUARD_READY"


def test_standalone_status_blocks_corrupted_ledger_evidence(
    standalone_cli: tuple[CliRunner, Path],
) -> None:
    runner, guard_root = standalone_cli
    ledger = guard_root / "evidence" / "standalone" / "ledger.jsonl"
    trust = signing.export_public_key(guard_root / "trust" / "keys")
    append_ledger_entry(ledger, "guard.started", "standalone", {})
    payload = json.loads(ledger.read_text(encoding="utf-8"))
    payload["entry_hash"] = "f" * 64
    ledger.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    result = runner.invoke(
        cli.app,
        [
            "standalone-status",
            "--ledger",
            str(ledger),
            "--trust-key",
            trust.trusted_public_key_path,
        ],
    )

    assert result.exit_code == 3
    status = json.loads(result.stdout)
    assert status["evidence_ledger_state"] == "FAIL_LEDGER_VERIFICATION"
    assert status["blockers"] == ["ENTRY_HASH_INVALID:1"]
    assert status["verdict"] == "BLOCKED_STANDALONE_GUARD"
