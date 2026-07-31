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
    key_root = tmp_path / "private" / "keys"
    monkeypatch.setattr(signing, "key_store_root", lambda: key_root)
    monkeypatch.setattr(
        signing,
        "_restrict_key_directory",
        lambda path: path.mkdir(parents=True, exist_ok=True),
    )
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


def test_standalone_init_rejects_an_existing_ledger_without_active_key_continuity(
    standalone_cli: tuple[CliRunner, Path],
) -> None:
    runner, _ = standalone_cli
    first = runner.invoke(cli.app, ["standalone", "init"])
    assert first.exit_code == 0

    private_key = Path(signing.inspect_key().private_key_path)
    private_key.unlink()
    replacement = signing.initialise_key()
    assert replacement.key_id != json.loads(first.stdout)["key_id"]

    repeated = runner.invoke(cli.app, ["standalone", "init"])
    assert repeated.exit_code == 1
    assert isinstance(repeated.exception, RuntimeError)
    assert str(repeated.exception) == "STANDALONE_LEDGER_ACTIVE_KEY_CONTINUITY_REQUIRED"


def test_v1_cli_complete_installed_lifecycle(
    standalone_cli: tuple[CliRunner, Path],
    tmp_path: Path,
) -> None:
    runner, _ = standalone_cli
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "worker.js").write_text("v1", encoding="utf-8")

    initialised = runner.invoke(cli.app, ["standalone", "init"])
    assert initialised.exit_code == 0
    initialised_payload = json.loads(initialised.stdout)
    assert initialised_payload["verdict"] == "PASS_STANDALONE_INITIALISED"

    added = runner.invoke(
        cli.app,
        [
            "standalone",
            "folder",
            "add",
            "--path",
            str(fixture),
            "--label",
            "fixture",
        ],
    )
    assert added.exit_code == 0
    folder_id = json.loads(added.stdout)["folder_id"]

    not_started = runner.invoke(cli.app, ["standalone", "status"])
    assert not_started.exit_code == 3
    not_started_payload = json.loads(not_started.stdout)
    assert "MONITOR_NOT_STARTED" in not_started_payload["blockers"]

    first_run = runner.invoke(
        cli.app, ["standalone", "run", "--iterations", "1"]
    )
    assert first_run.exit_code == 0
    assert json.loads(first_run.stdout)["verdict"] == "PASS_MONITOR_STOPPED_CLEANLY"

    old_key_id = initialised_payload["key_id"]
    rotated = runner.invoke(
        cli.app, ["key", "rotate", "--reason", "cli lifecycle"]
    )
    assert rotated.exit_code == 0
    assert json.loads(rotated.stdout)["new_key_id"] != old_key_id

    second_run = runner.invoke(
        cli.app, ["standalone", "run", "--iterations", "1"]
    )
    assert second_run.exit_code == 0
    status = runner.invoke(cli.app, ["standalone", "status"])
    assert status.exit_code == 0
    assert json.loads(status.stdout)["verdict"] == "PASS_STANDALONE_V1_READY"

    evidence_root = Path(initialised_payload["configuration"]["evidence_root"])
    bundle = evidence_root / "exports" / "cli.zip"
    exported = runner.invoke(
        cli.app,
        [
            "standalone",
            "evidence",
            "export",
            "--destination",
            str(bundle),
        ],
    )
    assert exported.exit_code == 0
    verified = runner.invoke(
        cli.app,
        [
            "standalone",
            "evidence",
            "verify",
            "--bundle",
            str(bundle),
            "--expected-trust-anchor-key-id",
            old_key_id,
        ],
    )
    assert verified.exit_code == 0
    assert json.loads(verified.stdout)["verdict"] == "PASS_EVIDENCE_BUNDLE_VERIFIED"

    removed = runner.invoke(
        cli.app,
        ["standalone", "folder", "remove", "--folder-id", folder_id],
    )
    assert removed.exit_code == 0
