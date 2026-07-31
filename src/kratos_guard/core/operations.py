"""Installed standalone configuration, monitoring, and portable evidence operations."""

import json
import os
import secrets
import shutil
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from hashlib import sha256
from importlib.resources import files
from pathlib import Path, PurePosixPath

import psutil

import kratos_guard.core.signing as signing
from kratos_guard.core.path_security import contains
from kratos_guard.core.standalone import (
    ZERO_HASH,
    _exclusive_lock,
    append_ledger_entry,
    canonical_json_bytes,
    compare_folder_snapshots,
    snapshot_folder,
    verify_ledger,
)
from kratos_guard.models.standalone import (
    EvidenceBundleVerification,
    FolderSnapshot,
    GuardConfiguration,
    LedgerEntry,
    MonitoredFolder,
    MonitorHealth,
    PersistedFolderBaseline,
)

MAX_BUNDLE_MEMBERS = 10_000
MAX_BUNDLE_UNCOMPRESSED_BYTES = 100_000_000


def application_data_root() -> Path:
    return signing.key_store_root().parent


def default_configuration_path() -> Path:
    return application_data_root() / "config.json"


def _configuration_owned_paths(
    configuration: GuardConfiguration,
    configuration_path: Path,
) -> list[Path]:
    return [
        application_data_root().resolve(),
        Path(configuration.evidence_root).resolve(),
        Path(configuration.ledger_path).resolve(),
        Path(configuration.trust_directory).resolve(),
        configuration_path.resolve(),
    ]


def _require_safe_monitored_path(
    configuration: GuardConfiguration,
    configuration_path: Path,
    monitored: Path,
) -> None:
    if not monitored.is_absolute():
        raise ValueError("MONITORED_FOLDER_PATH_NOT_ABSOLUTE")
    resolved = monitored.resolve()
    for owned in _configuration_owned_paths(configuration, configuration_path):
        if contains(resolved, owned) or contains(owned, resolved):
            raise ValueError("MONITORED_FOLDER_OVERLAPS_GUARD_STATE")


def _atomic_json_write(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    rendered = (
        payload.model_dump_json(indent=2)
        if hasattr(payload, "model_dump_json")
        else json.dumps(payload, indent=2, sort_keys=True)
    )
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def initialise_configuration(path: Path | None = None) -> GuardConfiguration:
    destination = (path or default_configuration_path()).resolve()
    with _exclusive_lock(destination.with_suffix(destination.suffix + ".lock")):
        if destination.is_file():
            return load_configuration(destination)
        root = application_data_root().resolve()
        signing.restrict_private_directory(root)
        configuration = GuardConfiguration(
            evidence_root=str(root / "evidence"),
            ledger_path=str(root / "evidence" / "ledger.jsonl"),
            trust_directory=str(root / "trust-export"),
        )
        Path(configuration.evidence_root).mkdir(parents=True, exist_ok=True)
        signing.export_trust_bundle(Path(configuration.trust_directory))
        _atomic_json_write(destination, configuration)
        return configuration


def load_configuration(path: Path | None = None) -> GuardConfiguration:
    source = (path or default_configuration_path()).resolve()
    configuration = GuardConfiguration.model_validate_json(source.read_text(encoding="utf-8"))
    for value in (
        configuration.evidence_root,
        configuration.ledger_path,
        configuration.trust_directory,
    ):
        if not Path(value).is_absolute():
            raise ValueError("CONFIGURATION_PATH_NOT_ABSOLUTE")
    if not contains(
        Path(configuration.evidence_root),
        Path(configuration.ledger_path),
    ):
        raise ValueError("LEDGER_OUTSIDE_EVIDENCE_ROOT")
    folder_paths: set[str] = set()
    folder_labels: set[str] = set()
    folder_ids: set[str] = set()
    for folder in configuration.folders:
        _require_safe_monitored_path(configuration, source, Path(folder.path))
        normalised_path = os.path.normcase(str(Path(folder.path).resolve()))
        normalised_label = folder.label.casefold()
        if (
            normalised_path in folder_paths
            or normalised_label in folder_labels
            or folder.folder_id in folder_ids
        ):
            raise ValueError("MONITORED_FOLDER_CONFIGURATION_DUPLICATE")
        folder_paths.add(normalised_path)
        folder_labels.add(normalised_label)
        folder_ids.add(folder.folder_id)
    return configuration


def register_folder(
    configuration_path: Path,
    folder: Path,
    label: str,
    *,
    max_files: int = 5000,
    max_file_bytes: int = 10_000_000,
    max_total_bytes: int = 500_000_000,
) -> MonitoredFolder:
    configuration_path = configuration_path.resolve()
    with _exclusive_lock(
        configuration_path.with_suffix(configuration_path.suffix + ".lock")
    ):
        configuration = load_configuration(configuration_path)
        resolved = folder.resolve(strict=True)
        if not resolved.is_dir() or folder.is_symlink():
            raise ValueError("MONITORED_FOLDER_INVALID")
        _require_safe_monitored_path(configuration, configuration_path, resolved)
        if any(Path(item.path).resolve() == resolved for item in configuration.folders):
            raise ValueError("MONITORED_FOLDER_ALREADY_REGISTERED")
        if any(
            item.label.casefold() == label.strip().casefold()
            for item in configuration.folders
        ):
            raise ValueError("MONITORED_FOLDER_LABEL_ALREADY_REGISTERED")
        record = MonitoredFolder(
            folder_id=sha256(str(resolved).encode("utf-8")).hexdigest()[:16],
            label=label.strip(),
            path=str(resolved),
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        configuration.folders.append(record)
        _atomic_json_write(configuration_path, configuration)
        return record


def remove_folder(configuration_path: Path, folder_id: str) -> MonitoredFolder:
    configuration_path = configuration_path.resolve()
    with _exclusive_lock(
        configuration_path.with_suffix(configuration_path.suffix + ".lock")
    ):
        configuration = load_configuration(configuration_path)
        matches = [item for item in configuration.folders if item.folder_id == folder_id]
        if not matches:
            raise KeyError("MONITORED_FOLDER_NOT_FOUND")
        configuration.folders = [
            item for item in configuration.folders if item.folder_id != folder_id
        ]
        _atomic_json_write(configuration_path, configuration)
        return matches[0]


def write_service_template(kind: str, destination: Path) -> Path:
    names = {
        "systemd": "kratos-agent-guard.service",
        "windows": "Register-KratosAgentGuardTask.ps1",
    }
    if kind not in names:
        raise ValueError("SERVICE_TEMPLATE_KIND_INVALID")
    packaged_template = files("kratos_guard").joinpath("templates").joinpath(names[kind])
    try:
        content = packaged_template.read_text(encoding="utf-8")
    except FileNotFoundError:
        source_subdirectory = "systemd" if kind == "systemd" else "windows"
        source_template = (
            Path(__file__).resolve().parents[3]
            / "packaging"
            / source_subdirectory
            / names[kind]
        )
        content = source_template.read_text(encoding="utf-8")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(content.replace("\r\n", "\n"))
        stream.flush()
        os.fsync(stream.fileno())
    return destination


def _monitor_state_path(configuration: GuardConfiguration) -> Path:
    return Path(configuration.evidence_root) / "monitor-state.json"


def _baseline_path(configuration: GuardConfiguration, folder_id: str) -> Path:
    return Path(configuration.evidence_root) / "baselines" / f"{folder_id}.json"


def _baseline_signing_bytes(
    folder_id: str,
    snapshot: FolderSnapshot,
) -> bytes:
    return canonical_json_bytes(
        {
            "folder_id": folder_id,
            "schema_version": "kratos-guard.persisted-folder-baseline.v1",
            "snapshot": snapshot.model_dump(mode="json"),
        }
    )


def _load_baseline(
    configuration: GuardConfiguration,
    folder: MonitoredFolder,
) -> FolderSnapshot | None:
    path = _baseline_path(configuration, folder.folder_id)
    if not path.is_file():
        return None
    baseline = PersistedFolderBaseline.model_validate_json(
        path.read_text(encoding="utf-8")
    )
    if baseline.folder_id != folder.folder_id:
        raise ValueError("BASELINE_FOLDER_ID_INVALID")
    if Path(baseline.snapshot.root).resolve() != Path(folder.path).resolve():
        raise ValueError("BASELINE_ROOT_INVALID")
    revocation = signing.key_revocation_state(
        baseline.signing_key_id, signing.local_trust_directory()
    )
    if revocation != "NOT_REVOKED":
        raise ValueError("BASELINE_SIGNER_REVOKED_OR_INVALID")
    verification = signing.verify_local_payload_signature(
        _baseline_signing_bytes(baseline.folder_id, baseline.snapshot),
        baseline.signature,
        baseline.signing_key_id,
    )
    if (
        verification.signature_state != "SIGNATURE_VALID"
        or verification.signer_trust_state != "TRUST_ROOT_PROVEN"
    ):
        raise ValueError("BASELINE_SIGNATURE_INVALID")
    return baseline.snapshot


def _write_baseline(
    configuration: GuardConfiguration,
    folder: MonitoredFolder,
    snapshot: FolderSnapshot,
) -> None:
    identity, signature = signing.sign_payload_bytes(
        _baseline_signing_bytes(folder.folder_id, snapshot)
    )
    baseline = PersistedFolderBaseline(
        folder_id=folder.folder_id,
        snapshot=snapshot,
        signing_key_id=identity.key_id,
        signature=signature,
    )
    _atomic_json_write(
        _baseline_path(configuration, folder.folder_id),
        baseline,
    )


def monitor_health(configuration_path: Path) -> MonitorHealth:
    configuration = load_configuration(configuration_path)
    state_path = _monitor_state_path(configuration)
    if not state_path.is_file():
        return MonitorHealth(
            state_path=str(state_path),
            configured_folder_count=len(configuration.folders),
            completed_iterations=0,
            state="NOT_STARTED",
            blockers=["MONITOR_NOT_STARTED"],
            verdict="BLOCKED_MONITOR_NOT_STARTED",
        )
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
        process_id = int(payload["process_id"])
        started_at = datetime.fromisoformat(str(payload["started_at"]))
        heartbeat_at = datetime.fromisoformat(str(payload["heartbeat_at"]))
        completed_iterations = int(payload["completed_iterations"])
        state = str(payload["state"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return MonitorHealth(
            state_path=str(state_path),
            configured_folder_count=len(configuration.folders),
            completed_iterations=0,
            state="CORRUPT",
            blockers=["MONITOR_STATE_CORRUPT"],
            verdict="FAIL_MONITOR_STATE",
        )
    blockers: list[str] = []
    if state == "RUNNING":
        if not psutil.pid_exists(process_id):
            blockers.append("MONITOR_PROCESS_MISSING")
        age = (datetime.now(UTC) - heartbeat_at.astimezone(UTC)).total_seconds()
        if age > configuration.stale_after_seconds:
            blockers.append("MONITOR_HEARTBEAT_STALE")
    verdict = (
        "PASS_MONITOR_RUNNING"
        if state == "RUNNING" and not blockers
        else (
            "PASS_MONITOR_STOPPED_CLEANLY"
            if state == "STOPPED_CLEANLY"
            else "BLOCKED_MONITOR_HEALTH"
        )
    )
    return MonitorHealth(
        state_path=str(state_path),
        process_id=process_id,
        started_at=started_at,
        heartbeat_at=heartbeat_at,
        configured_folder_count=len(configuration.folders),
        completed_iterations=completed_iterations,
        state=state,
        blockers=blockers,
        verdict=verdict,
    )


def run_monitor(
    configuration_path: Path,
    *,
    iterations: int | None = None,
) -> MonitorHealth:
    configuration = load_configuration(configuration_path)
    if not configuration.folders:
        raise ValueError("NO_MONITORED_FOLDERS_CONFIGURED")
    evidence_root = Path(configuration.evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)
    state_path = _monitor_state_path(configuration)
    lock_path = evidence_root / "monitor.lock"
    started_at = datetime.now(UTC)
    process_id = os.getpid()
    completed = 0
    baselines: dict[str, FolderSnapshot] = {}
    with _exclusive_lock(
        lock_path, stale_after_seconds=configuration.stale_after_seconds
    ):
        try:
            for folder in configuration.folders:
                if folder.enabled:
                    baseline = _load_baseline(configuration, folder)
                    if baseline is not None:
                        baselines[folder.folder_id] = baseline
            append_ledger_entry(
                Path(configuration.ledger_path),
                "monitor.started",
                "standalone",
                {"folder_count": len(configuration.folders), "process_id": process_id},
            )
            while iterations is None or completed < iterations:
                for folder in configuration.folders:
                    if not folder.enabled:
                        continue
                    root = Path(folder.path)
                    current = snapshot_folder(
                        root,
                        max_files=folder.max_files,
                        max_file_bytes=folder.max_file_bytes,
                        max_total_bytes=folder.max_total_bytes,
                    )
                    previous = baselines.get(folder.folder_id)
                    if previous is None:
                        append_ledger_entry(
                            Path(configuration.ledger_path),
                            "folder.baseline.observed",
                            folder.folder_id,
                            {
                                "label": folder.label,
                                "manifest_sha256": current.manifest_sha256,
                                "file_count": current.file_count,
                            },
                        )
                    else:
                        comparison = compare_folder_snapshots(previous, current)
                        if comparison.verdict != "PASS_NO_FOLDER_DRIFT":
                            append_ledger_entry(
                                Path(configuration.ledger_path),
                                "folder.drift.detected",
                                folder.folder_id,
                                comparison.model_dump(mode="json"),
                            )
                    baselines[folder.folder_id] = current
                    _write_baseline(configuration, folder, current)
                completed += 1
                heartbeat_at = datetime.now(UTC)
                _atomic_json_write(
                    state_path,
                    {
                        "process_id": process_id,
                        "started_at": started_at.isoformat(),
                        "heartbeat_at": heartbeat_at.isoformat(),
                        "completed_iterations": completed,
                        "state": "RUNNING",
                    },
                )
                if iterations is None or completed < iterations:
                    time.sleep(configuration.interval_seconds)
        except BaseException:
            _atomic_json_write(
                state_path,
                {
                    "process_id": process_id,
                    "started_at": started_at.isoformat(),
                    "heartbeat_at": datetime.now(UTC).isoformat(),
                    "completed_iterations": completed,
                    "state": "FAILED",
                },
            )
            raise
        _atomic_json_write(
            state_path,
            {
                "process_id": process_id,
                "started_at": started_at.isoformat(),
                "heartbeat_at": datetime.now(UTC).isoformat(),
                "completed_iterations": completed,
                "state": "STOPPED_CLEANLY",
            },
        )
        append_ledger_entry(
            Path(configuration.ledger_path),
            "monitor.stopped",
            "standalone",
            {"completed_iterations": completed, "process_id": process_id},
        )
    return monitor_health(configuration_path)


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _first_ledger_signer(ledger: Path) -> str:
    for line in ledger.read_text(encoding="utf-8").splitlines():
        if line:
            return LedgerEntry.model_validate_json(line).signing_key_id
    raise ValueError("LEDGER_EMPTY")


def export_evidence_bundle(configuration_path: Path, destination: Path) -> Path:
    configuration = load_configuration(configuration_path)
    evidence_root = Path(configuration.evidence_root).resolve()
    destination = destination.resolve()
    if not contains(evidence_root, destination):
        raise ValueError("BUNDLE_DESTINATION_OUTSIDE_EVIDENCE_ROOT")
    ledger = Path(configuration.ledger_path)
    if not ledger.is_file():
        raise FileNotFoundError("LEDGER_MISSING")
    trust_anchor_key_id = _first_ledger_signer(ledger)
    trust_export = evidence_root / "portable-trust"
    signing.export_trust_bundle(trust_export)
    files: dict[str, Path] = {"ledger.jsonl": ledger}
    for path in sorted(item for item in trust_export.rglob("*") if item.is_file()):
        files[f"trust/{path.relative_to(trust_export).as_posix()}"] = path
    state = _monitor_state_path(configuration)
    if state.is_file():
        files["monitor-state.json"] = state
    manifest = {
        "schema_version": "kratos-guard.evidence-bundle.v1",
        "created_at": datetime.now(UTC).isoformat(),
        "trust_anchor_key_id": trust_anchor_key_id,
        "files": {
            name: {"sha256": _file_sha256(path), "byte_count": path.stat().st_size}
            for name, path in files.items()
        },
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    try:
        with zipfile.ZipFile(temporary, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, path in files.items():
                archive.write(path, name)
            archive.writestr(
                "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
        verification = verify_evidence_bundle(
            temporary,
            expected_trust_anchor_key_id=trust_anchor_key_id,
        )
        if verification.verdict != "PASS_EVIDENCE_BUNDLE_VERIFIED":
            raise ValueError(
                "EXPORTED_EVIDENCE_BUNDLE_INVALID:"
                + ",".join(verification.blockers)
            )
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def create_ledger_checkpoint(configuration_path: Path) -> dict[str, object]:
    configuration = load_configuration(configuration_path)
    ledger_path = Path(configuration.ledger_path)
    verification = verify_ledger(ledger_path, Path(configuration.trust_directory))
    if verification.verdict != "PASS_LEDGER_VERIFIED":
        raise ValueError(verification.first_error or verification.verdict)
    entry = append_ledger_entry(
        ledger_path,
        "ledger.checkpoint",
        "standalone",
        {
            "verified_entry_count": verification.entry_count,
            "verified_head_hash": verification.head_hash,
        },
    )
    return {
        "checkpoint_sequence": entry.sequence,
        "checkpoint_entry_hash": entry.entry_hash,
        "previous_verified_head_hash": verification.head_hash,
        "verdict": "PASS_LEDGER_CHECKPOINT_CREATED",
    }


def import_evidence_bundle(
    configuration_path: Path,
    bundle: Path,
    expected_trust_anchor_key_id: str,
) -> Path:
    verification = verify_evidence_bundle(
        bundle,
        expected_trust_anchor_key_id=expected_trust_anchor_key_id,
    )
    if verification.verdict != "PASS_EVIDENCE_BUNDLE_VERIFIED":
        raise ValueError("EVIDENCE_BUNDLE_UNVERIFIED")
    configuration = load_configuration(configuration_path)
    imports = Path(configuration.evidence_root) / "imports"
    imports.mkdir(parents=True, exist_ok=True)
    source_digest = _file_sha256(bundle)
    destination = imports / f"{source_digest[:16]}-{bundle.name}"
    if destination.exists():
        raise FileExistsError("EVIDENCE_BUNDLE_ALREADY_IMPORTED")
    temporary = destination.with_name(f".{destination.name}.{secrets.token_hex(8)}.tmp")
    try:
        shutil.copyfile(bundle, temporary)
        if _file_sha256(temporary) != source_digest:
            raise OSError("EVIDENCE_BUNDLE_COPY_MISMATCH")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def verify_evidence_bundle(
    bundle: Path,
    *,
    expected_trust_anchor_key_id: str | None = None,
) -> EvidenceBundleVerification:
    blockers: list[str] = []
    file_count = 0
    ledger_count = 0
    ledger_head = ZERO_HASH
    manifest_state = "UNPROVEN"
    ledger_state = "UNPROVEN"
    trust_anchor_key_id = ""
    trust_anchor_state = "UNPROVEN"
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            names = archive.namelist()
            if len(names) > MAX_BUNDLE_MEMBERS:
                raise ValueError("BUNDLE_MEMBER_LIMIT_EXCEEDED")
            if len(names) != len(set(names)):
                raise ValueError("BUNDLE_DUPLICATE_MEMBER")
            total_size = sum(item.file_size for item in archive.infolist())
            if total_size > MAX_BUNDLE_UNCOMPRESSED_BYTES:
                raise ValueError("BUNDLE_SIZE_LIMIT_EXCEEDED")
            for name in names:
                pure = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or pure.is_absolute()
                    or ".." in pure.parts
                    or (pure.parts and ":" in pure.parts[0])
                ):
                    raise ValueError("BUNDLE_PATH_TRAVERSAL")
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("schema_version") != "kratos-guard.evidence-bundle.v1":
                raise ValueError("BUNDLE_SCHEMA_INVALID")
            trust_anchor_key_id = str(manifest.get("trust_anchor_key_id", ""))
            if not trust_anchor_key_id:
                raise ValueError("BUNDLE_TRUST_ANCHOR_MISSING")
            expected_files = manifest.get("files")
            if not isinstance(expected_files, dict):
                raise ValueError("BUNDLE_MANIFEST_INVALID")
            if set(names) != set(expected_files) | {"manifest.json"}:
                raise ValueError("BUNDLE_MEMBER_SET_INVALID")
            file_count = len(expected_files)
            for name, identity in expected_files.items():
                if not isinstance(name, str) or not isinstance(identity, dict):
                    raise ValueError("BUNDLE_MANIFEST_INVALID")
                content = archive.read(name)
                if sha256(content).hexdigest() != identity["sha256"]:
                    raise ValueError(f"BUNDLE_HASH_INVALID:{name}")
                if len(content) != identity["byte_count"]:
                    raise ValueError(f"BUNDLE_SIZE_INVALID:{name}")
            manifest_state = "MANIFEST_VALID"
            with tempfile.TemporaryDirectory(prefix="kratos-guard-verify-") as temporary:
                root = Path(temporary)
                archive.extractall(root)
                first_signer = _first_ledger_signer(root / "ledger.jsonl")
                if first_signer != trust_anchor_key_id:
                    blockers.append("BUNDLE_TRUST_ANCHOR_LEDGER_MISMATCH")
                    trust_anchor_state = "MISMATCH"
                elif expected_trust_anchor_key_id is None:
                    blockers.append("EXTERNAL_TRUST_ANCHOR_REQUIRED")
                    trust_anchor_state = "UNPROVEN"
                elif expected_trust_anchor_key_id != trust_anchor_key_id:
                    blockers.append("EXTERNAL_TRUST_ANCHOR_MISMATCH")
                    trust_anchor_state = "MISMATCH"
                else:
                    trust_anchor_state = "PINNED_MATCH"
                verification = verify_ledger(root / "ledger.jsonl", root / "trust")
                ledger_count = verification.entry_count
                ledger_head = verification.head_hash
                ledger_state = verification.verdict
                if verification.verdict != "PASS_LEDGER_VERIFIED":
                    blockers.append(verification.first_error or verification.verdict)
    except (
        FileNotFoundError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
        zipfile.BadZipFile,
    ) as error:
        blockers.append(str(error))
        if manifest_state == "UNPROVEN":
            manifest_state = "MANIFEST_INVALID"
    verdict = (
        "PASS_EVIDENCE_BUNDLE_VERIFIED"
        if not blockers
        and manifest_state == "MANIFEST_VALID"
        and ledger_state == "PASS_LEDGER_VERIFIED"
        else "FAIL_EVIDENCE_BUNDLE_VERIFICATION"
    )
    return EvidenceBundleVerification(
        bundle_path=str(bundle.resolve()),
        file_count=file_count,
        ledger_entry_count=ledger_count,
        ledger_head_hash=ledger_head,
        manifest_state=manifest_state,
        ledger_state=ledger_state,
        trust_anchor_key_id=trust_anchor_key_id,
        trust_anchor_state=trust_anchor_state,
        blockers=blockers,
        verdict=verdict,
    )
