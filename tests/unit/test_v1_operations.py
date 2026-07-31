import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

import kratos_guard.core.signing as signing
from kratos_guard.core.operations import (
    create_ledger_checkpoint,
    export_evidence_bundle,
    import_evidence_bundle,
    initialise_configuration,
    load_configuration,
    monitor_health,
    register_folder,
    remove_folder,
    run_monitor,
    verify_evidence_bundle,
    write_service_template,
)
from kratos_guard.core.standalone import append_ledger_entry, verify_ledger


@pytest.fixture
def safe_key_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "private" / "keys"
    monkeypatch.setattr(signing, "key_store_root", lambda: root)
    monkeypatch.setattr(
        signing,
        "_restrict_key_directory",
        lambda path: path.mkdir(parents=True, exist_ok=True),
    )
    original = signing.assess_key_storage

    def safe(path: Path | None = None):
        assessment = original(path or root)
        return assessment.model_copy(
            update={
                "exists": True,
                "restrictive_acl": True,
                "broadly_writable": False,
                "state": "TRUST_ROOT_PROVEN",
            }
        )

    monkeypatch.setattr(signing, "assess_key_storage", safe)
    signing.initialise_key()
    return root


def test_rotation_preserves_multi_key_ledger_verification(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    trust = tmp_path / "portable-trust"
    old = signing.inspect_key()
    append_ledger_entry(ledger, "guard.before-rotation", "standalone", {})

    new = signing.rotate_key(
        "scheduled lifecycle test",
        trust,
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert new.key_id != old.key_id
    assert not (safe_key_store / "rotated").exists()
    assert not list(safe_key_store.glob(".attestation-ed25519.*.next"))
    append_ledger_entry(ledger, "guard.after-rotation", "standalone", {})

    verification = verify_ledger(ledger, trust)
    assert verification.verdict == "PASS_LEDGER_VERIFIED"
    assert verification.entry_count == 2
    assert (
        trust / "rotations" / f"{old.key_id}-to-{new.key_id}.json"
    ).is_file()


def test_missing_rotation_record_blocks_key_transition(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    trust = tmp_path / "portable-trust"
    old = signing.inspect_key()
    append_ledger_entry(ledger, "guard.before-rotation", "standalone", {})
    new = signing.rotate_key("test", trust)
    append_ledger_entry(ledger, "guard.after-rotation", "standalone", {})
    (
        trust / "rotations" / f"{old.key_id}-to-{new.key_id}.json"
    ).unlink()

    verification = verify_ledger(ledger, trust)
    assert verification.verdict == "FAIL_LEDGER_VERIFICATION"
    assert verification.first_error == "KEY_TRANSITION_INVALID:2"


def test_revoked_historical_key_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    trust = tmp_path / "portable-trust"
    old = signing.inspect_key()
    append_ledger_entry(ledger, "guard.before-rotation", "standalone", {})
    signing.rotate_key("replace compromised key", trust)
    signing.revoke_key(old.key_id, "compromise confirmed", trust)

    verification = verify_ledger(ledger, trust)
    assert verification.verdict == "FAIL_LEDGER_VERIFICATION"
    assert verification.first_error == "ENTRY_SIGNER_REVOKED:1"


def test_tampered_revocation_record_fails_as_invalid_control_evidence(
    safe_key_store: Path, tmp_path: Path
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    trust = tmp_path / "portable-trust"
    old = signing.inspect_key()
    append_ledger_entry(ledger, "guard.before-rotation", "standalone", {})
    signing.rotate_key("replace key", trust)
    signing.revoke_key(old.key_id, "test revocation", trust)
    record_path = trust / "revocations" / f"{old.key_id}.json"
    payload = json.loads(record_path.read_text(encoding="utf-8"))
    payload["reason"] = "tampered"
    record_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    verification = verify_ledger(ledger, trust)
    assert verification.verdict == "FAIL_LEDGER_VERIFICATION"
    assert verification.first_error == "REVOCATION_RECORD_INVALID:1"


def test_existing_rotation_lock_preserves_current_key(
    safe_key_store: Path,
) -> None:
    before = signing.inspect_key()
    lock = safe_key_store / "rotation.lock"
    lock.write_text("another-writer\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="KEY_ROTATION_ALREADY_ACTIVE"):
        signing.rotate_key("must not race")

    assert signing.inspect_key().key_id == before.key_id
    assert lock.read_text(encoding="utf-8") == "another-writer\n"


def test_configuration_monitor_and_portable_evidence_lifecycle(
    safe_key_store: Path, tmp_path: Path
) -> None:
    trust_anchor_key_id = signing.inspect_key().key_id
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    observed = tmp_path / "observed"
    observed.mkdir()
    (observed / "worker.js").write_text("v1\n", encoding="utf-8")
    folder = register_folder(configuration_path, observed, "fixture")

    result = run_monitor(configuration_path, iterations=1)
    assert result.verdict == "PASS_MONITOR_STOPPED_CLEANLY"
    assert result.completed_iterations == 1
    loaded = load_configuration(configuration_path)
    ledger = verify_ledger(
        Path(loaded.ledger_path), Path(loaded.trust_directory)
    )
    assert ledger.verdict == "PASS_LEDGER_VERIFIED"
    assert ledger.entry_count == 3
    checkpoint = create_ledger_checkpoint(configuration_path)
    assert checkpoint["checkpoint_sequence"] == 4

    bundle = (
        Path(configuration.evidence_root) / "exports" / "standalone-evidence.zip"
    )
    export_evidence_bundle(configuration_path, bundle)
    unpinned = verify_evidence_bundle(bundle)
    assert unpinned.verdict == "FAIL_EVIDENCE_BUNDLE_VERIFICATION"
    assert unpinned.blockers == ["EXTERNAL_TRUST_ANCHOR_REQUIRED"]
    verification = verify_evidence_bundle(
        bundle,
        expected_trust_anchor_key_id=trust_anchor_key_id,
    )
    assert verification.verdict == "PASS_EVIDENCE_BUNDLE_VERIFIED"
    assert verification.ledger_entry_count == 4
    assert verification.trust_anchor_state == "PINNED_MATCH"
    imported = import_evidence_bundle(
        configuration_path,
        bundle,
        trust_anchor_key_id,
    )
    assert imported.is_file()
    with pytest.raises(FileExistsError, match="EVIDENCE_BUNDLE_ALREADY_IMPORTED"):
        import_evidence_bundle(
            configuration_path,
            bundle,
            trust_anchor_key_id,
        )

    removed = remove_folder(configuration_path, folder.folder_id)
    assert removed.folder_id == folder.folder_id
    assert load_configuration(configuration_path).folders == []


def test_monitor_persists_signed_baseline_across_clean_restarts(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    observed = tmp_path / "observed"
    observed.mkdir()
    target = observed / "worker.js"
    target.write_text("before\n", encoding="utf-8")
    folder = register_folder(configuration_path, observed, "fixture")
    run_monitor(configuration_path, iterations=1)

    target.write_text("after\n", encoding="utf-8")
    run_monitor(configuration_path, iterations=1)

    entries = [
        json.loads(line)
        for line in Path(configuration.ledger_path).read_text(encoding="utf-8").splitlines()
    ]
    drift = [entry for entry in entries if entry["event_type"] == "folder.drift.detected"]
    assert len(drift) == 1
    assert drift[0]["subject"] == folder.folder_id
    assert drift[0]["payload"]["changed"] == ["worker.js"]


def test_tampered_persisted_baseline_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    observed = tmp_path / "observed"
    observed.mkdir()
    (observed / "worker.js").write_text("before\n", encoding="utf-8")
    folder = register_folder(configuration_path, observed, "fixture")
    run_monitor(configuration_path, iterations=1)
    baseline_path = (
        Path(configuration.evidence_root) / "baselines" / f"{folder.folder_id}.json"
    )
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    payload["snapshot"]["manifest_sha256"] = "f" * 64
    baseline_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="BASELINE_SIGNATURE_INVALID"):
        run_monitor(configuration_path, iterations=1)
    assert monitor_health(configuration_path).state == "FAILED"


def test_configuration_rejects_evidence_overlap(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    evidence = Path(configuration.evidence_root)
    evidence.mkdir(parents=True, exist_ok=True)

    with pytest.raises(ValueError, match="MONITORED_FOLDER_OVERLAPS_GUARD_STATE"):
        register_folder(configuration_path, evidence, "unsafe")


def test_corrupt_monitor_state_is_reported_without_process_action(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    state = Path(configuration.evidence_root) / "monitor-state.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text("{not-json", encoding="utf-8")

    health = monitor_health(configuration_path)
    assert health.state == "CORRUPT"
    assert health.blockers == ["MONITOR_STATE_CORRUPT"]
    assert health.verdict == "FAIL_MONITOR_STATE"


def test_corrupt_configuration_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    initialise_configuration(configuration_path)
    configuration_path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(ValueError):
        load_configuration(configuration_path)


def test_evidence_bundle_path_traversal_fails_closed(
    safe_key_store: Path, tmp_path: Path
) -> None:
    bundle = tmp_path / "malicious.zip"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("../escape", "bad")
        archive.writestr(
            "manifest.json",
            json.dumps(
                {
                    "schema_version": "kratos-guard.evidence-bundle.v1",
                    "files": {},
                }
            ),
        )

    result = verify_evidence_bundle(bundle)
    assert result.verdict == "FAIL_EVIDENCE_BUNDLE_VERIFICATION"
    assert result.blockers == ["BUNDLE_PATH_TRAVERSAL"]


def test_evidence_bundle_rejects_wrong_external_anchor(
    safe_key_store: Path, tmp_path: Path
) -> None:
    configuration_path = tmp_path / "installed" / "config.json"
    configuration = initialise_configuration(configuration_path)
    observed = tmp_path / "observed"
    observed.mkdir()
    (observed / "worker.js").write_text("v1\n", encoding="utf-8")
    register_folder(configuration_path, observed, "fixture")
    run_monitor(configuration_path, iterations=1)
    bundle = Path(configuration.evidence_root) / "exports" / "anchor.zip"
    export_evidence_bundle(configuration_path, bundle)

    result = verify_evidence_bundle(
        bundle,
        expected_trust_anchor_key_id="ed25519-not-the-pinned-key",
    )
    assert result.verdict == "FAIL_EVIDENCE_BUNDLE_VERIFICATION"
    assert result.trust_anchor_state == "MISMATCH"
    assert result.blockers == ["EXTERNAL_TRUST_ANCHOR_MISMATCH"]


def test_service_templates_are_packaged_and_written_explicitly(tmp_path: Path) -> None:
    systemd = write_service_template("systemd", tmp_path / "guard.service")
    windows = write_service_template("windows", tmp_path / "register.ps1")
    assert "ProtectSystem=strict" in systemd.read_text(encoding="utf-8")
    assert "Register-ScheduledTask" in windows.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="SERVICE_TEMPLATE_KIND_INVALID"):
        write_service_template("unknown", tmp_path / "unknown")
