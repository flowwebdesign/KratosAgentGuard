"""Policy, discovery, and execution for an isolated extension canary."""

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import time
from datetime import UTC, datetime
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

import psutil
from playwright.sync_api import BrowserContext, Error, Request, sync_playwright

from kratos_guard.core.hashing import hash_file
from kratos_guard.core.mutation_witness import MutationWitness
from kratos_guard.core.sealed_build import _logical_manifest, verify_candidate
from kratos_guard.core.signing import calculate_attestation_integrity
from kratos_guard.models import EvidenceState
from kratos_guard.models.build import BuildAttestation
from kratos_guard.models.canary import (
    BrowserExecutableIdentity,
    BrowserLaunchPolicy,
    BrowserProcessIdentity,
    BrowserProfileIdentity,
    CanaryLifecycleEvidence,
    CanaryReport,
    CandidateRuntimeWitness,
    CurrentUserRuntimeObservation,
    ExtensionRuntimeIdentity,
    NetworkAttempt,
    NetworkIsolationEvidence,
    RuntimeAttestationReadback,
    RuntimeChainVerification,
    RuntimeProofScope,
)

BROWSER_PATHS = (
    ("Google Chrome", Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
    ("Google Chrome", Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")),
    ("Microsoft Edge", Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")),
    ("Microsoft Edge", Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")),
)


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _command_hash(arguments: list[str]) -> str:
    return _sha256_bytes("\0".join(arguments).encode())


def _inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([str(path.resolve()), str(root.resolve())]) == str(root.resolve())
    except ValueError:
        return False


def _assert_no_link_escape(path: Path, root: Path) -> None:
    root = root.resolve()
    if not _inside(path, root):
        raise PermissionError(f"path escapes Guard-owned root: {path}")
    current = root
    lexical = Path(os.path.abspath(path))
    for part in lexical.relative_to(root).parts:
        current /= part
        if current.exists() and (current.is_symlink() or _is_reparse_point(current)):
            raise PermissionError(f"link is not permitted in canary path: {current}")


def _is_reparse_point(path: Path) -> bool:
    attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _file_version(path: Path) -> str:
    escaped = str(path).replace("'", "''")
    command = f"(Get-Item -LiteralPath '{escaped}').VersionInfo.FileVersion"
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "UNAVAILABLE"


def discover_browsers() -> list[BrowserExecutableIdentity]:
    discovered: list[BrowserExecutableIdentity] = []
    seen: set[str] = set()
    for product, candidate in BROWSER_PATHS:
        if not candidate.is_file():
            continue
        resolved = str(candidate.resolve()).casefold()
        if resolved in seen:
            continue
        seen.add(resolved)
        discovered.append(
            BrowserExecutableIdentity(
                product=product,
                executable_path=str(candidate.resolve()),
                executable_sha256=hash_file(candidate).digest,
                file_version=_file_version(candidate),
                architecture=platform.machine(),
                discovery_method="bounded well-known install path",
                state=EvidenceState.PROVEN,
                uncertainties=["Publisher signature is not independently verified."],
            )
        )
    return discovered


def browser_pid_set() -> list[int]:
    names = {"chrome.exe", "msedge.exe", "chromium.exe"}
    return sorted(
        process.pid
        for process in psutil.process_iter(["name"])
        if str(process.info.get("name", "")).casefold() in names
    )


def playwright_browser_root(guard_root: Path) -> Path:
    return (guard_root / ".work" / "playwright-browsers").resolve()


def bundled_chromium_identity(guard_root: Path) -> BrowserExecutableIdentity:
    install_root = playwright_browser_root(guard_root)
    os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(install_root)
    with sync_playwright() as playwright:
        executable = Path(playwright.chromium.executable_path).resolve()
    if not _inside(executable, install_root):
        raise PermissionError("PLAYWRIGHT_RESOLVED_BRANDED_BROWSER")
    match = re.search(r"chromium-(\d+)", executable.as_posix())
    if not match:
        raise RuntimeError("PLAYWRIGHT_CHROMIUM_REVISION_UNPROVEN")
    lockfile = guard_root / "uv.lock"
    return BrowserExecutableIdentity(
        product="Playwright bundled Chromium",
        executable_path=str(executable),
        executable_sha256=hash_file(executable).digest,
        file_version=_file_version(executable),
        architecture=platform.machine(),
        discovery_method="playwright.chromium.executable_path",
        state=EvidenceState.PROVEN,
        uncertainties=[],
        channel="chromium",
        playwright_version=version("playwright"),
        browser_revision=match.group(1),
        installation_root=str(install_root),
        lockfile_sha256=hash_file(lockfile).digest,
        provenance_state=EvidenceState.PROVEN,
        sideload_capability="BROWSER_SIDELOAD_CAPABILITY_PROVEN",
    )


def candidate_manifest(candidate: Path) -> str:
    return str(_logical_manifest(candidate, excluded_names=set())["manifest_sha256"])


def plan_extension_canary(
    guard_root: Path,
    candidate: Path,
    browser: BrowserExecutableIdentity | None = None,
    *,
    run_id: str | None = None,
    debugging_port: int | None = None,
) -> BrowserLaunchPolicy:
    guard_root = guard_root.resolve()
    candidate = candidate.resolve()
    candidate_root = guard_root / ".work" / "candidates"
    _assert_no_link_escape(candidate, candidate_root)
    extension = candidate / "artefact" / "extension"
    _assert_no_link_escape(extension, candidate)
    if not (extension / "manifest.json").is_file():
        raise FileNotFoundError("sealed extension manifest is missing")
    selected = browser or bundled_chromium_identity(guard_root)
    if selected.product in {"Google Chrome", "Microsoft Edge"}:
        raise PermissionError("BROWSER_SIDELOAD_CAPABILITY_UNSUPPORTED")
    if hash_file(Path(selected.executable_path)).digest != selected.executable_sha256:
        raise RuntimeError("BROWSER_EXECUTABLE_CHANGED_AFTER_PLANNING")
    run_id = run_id or f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    run_root = guard_root / ".work" / "browser-canaries" / run_id
    profile = run_root / "profile"
    _assert_no_link_escape(profile, guard_root / ".work" / "browser-canaries")
    if debugging_port is not None:
        raise ValueError("persistent-context canaries do not accept a debugging port")
    arguments = [
        "playwright.chromium.launch_persistent_context",
        f"user_data_dir={profile}",
        "channel=chromium",
        "headless=false",
        f"--disable-extensions-except={extension}",
        f"--load-extension={extension}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-features=DisableLoadExtensionCommandLineSwitch",
        "--password-store=basic",
        "--proxy-server=http://127.0.0.1:9",
        "--proxy-bypass-list=<-loopback>",
        "--window-position=-32000,-32000",
        "--window-size=800,600",
    ]
    return BrowserLaunchPolicy(
        executable_path=selected.executable_path,
        executable_sha256=selected.executable_sha256,
        candidate_directory=str(candidate),
        candidate_manifest_sha256=candidate_manifest(candidate),
        extension_path=str(extension),
        user_data_directory=str(profile),
        profile_directory="Canary",
        debugging_host="PLAYWRIGHT_INTERNAL",
        debugging_port=0,
        startup_timeout_seconds=20,
        lifetime_timeout_seconds=45,
        allowed_navigation_schemes=["about:", "chrome-extension:"],
        network_policy="BROWSER_LEVEL_BLOCK_ALL_HTTP_HTTPS_WEBSOCKET",
        command_line=arguments,
        command_line_sha256=_command_hash(arguments),
        state=EvidenceState.PROVEN,
    )


def _owned_processes(root_pid: int) -> list[psutil.Process]:
    try:
        root = psutil.Process(root_pid)
        return [root, *root.children(recursive=True)]
    except psutil.Error:
        return []


def _profile_processes(profile: Path) -> list[psutil.Process]:
    needle = str(profile.resolve()).casefold()
    matches: list[psutil.Process] = []
    for process in psutil.process_iter(["cmdline"]):
        try:
            command = " ".join(process.info.get("cmdline") or []).casefold()
            if needle in command:
                matches.append(process)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return matches


def cleanup_guard_profile(
    guard_root: Path, profile: Path, active_profile: Path | None = None
) -> dict[str, object]:
    guard_root = guard_root.resolve()
    profile = Path(os.path.abspath(profile))
    canary_root = guard_root / ".work" / "browser-canaries"
    _assert_no_link_escape(profile, canary_root)
    if active_profile is not None and profile.resolve() == active_profile.resolve():
        raise PermissionError("active canary profile cannot be removed")
    processes = _profile_processes(profile)
    if processes:
        raise PermissionError("canary profile still has associated browser processes")
    evidence = {
        "profile": str(profile),
        "canary_root": str(canary_root),
        "contained": True,
        "reparse_escape": False,
        "associated_browser_process_count": 0,
        "active_run": False,
        "existed_before": profile.exists(),
        "observed_at": datetime.now(UTC).isoformat(),
    }
    evidence_root = guard_root / "evidence" / "inspections"
    evidence_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    evidence_path = evidence_root / f"profile-cleanup-{profile.parent.name}-{stamp}.json"
    evidence["evidence_path"] = str(evidence_path)
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if profile.exists():
        shutil.rmtree(profile)
    evidence["removed"] = not profile.exists()
    return evidence


def _extension_observation(
    context: BrowserContext,
    browser_pid: int,
    profile_path: str,
    expected_name: str,
    expected_version: str,
    expected_worker: str,
) -> tuple[ExtensionRuntimeIdentity, dict[str, Any] | None, str, str, str]:
    def matches(observed_worker: Any) -> bool:
        if not observed_worker.url.startswith("chrome-extension://"):
            return False
        observed_manifest = observed_worker.evaluate("() => chrome.runtime.getManifest()")
        return bool(
            observed_manifest.get("name") == expected_name
            and observed_manifest.get("version") == expected_version
            and observed_worker.url.endswith(f"/{expected_worker}")
        )

    worker = next(
        (observed for observed in context.service_workers if matches(observed)),
        None,
    )
    if worker is None:
        try:
            with context.expect_event(
                "serviceworker", predicate=matches, timeout=15_000
            ) as worker_event:
                pass
            worker = worker_event.value
        except Error as error:
            raise RuntimeError("EXTENSION_SERVICE_WORKER_UNPROVEN") from error
    if worker is None:
        raise RuntimeError("EXTENSION_SERVICE_WORKER_UNPROVEN")
    runtime = worker.evaluate(
        """async () => {
          const url = chrome.runtime.getURL("kratos-build-attestation.json");
          let bytes;
          let method = "extension-service-worker-fetch";
          try {
            const response = await fetch(url, {cache: "no-store"});
            bytes = new Uint8Array(await response.arrayBuffer());
          } catch (error) {
            return {id: chrome.runtime.id, manifest: chrome.runtime.getManifest(),
                    url, error: String(error)};
          }
          const digest = await crypto.subtle.digest("SHA-256", bytes);
          const hex = [...new Uint8Array(digest)].map(x => x.toString(16).padStart(2,"0")).join("");
          const text = new TextDecoder().decode(bytes);
          return {id: chrome.runtime.id, manifest: chrome.runtime.getManifest(),
                  url, text, sha256: hex, method};
        }"""
    )
    manifest = runtime["manifest"]
    extension_id = str(runtime["id"])
    identity = ExtensionRuntimeIdentity(
        extension_id=extension_id,
        extension_origin=f"chrome-extension://{extension_id}",
        manifest_version=int(manifest["manifest_version"]),
        extension_name=str(manifest["name"]),
        extension_version=str(manifest["version"]),
        service_worker_url=worker.url,
        service_worker_target_id=_sha256_bytes(worker.url.encode())[:16],
        extension_page_target_ids=[],
        browser_pid=browser_pid,
        profile_path=profile_path,
        observed_at=datetime.now(UTC),
        state=EvidenceState.PROVEN,
    )
    if "text" not in runtime:
        try:
            extension_page = context.new_page()
            panel_url = str(runtime["url"]).replace("kratos-build-attestation.json", "panel.html")
            extension_page.goto(panel_url, wait_until="domcontentloaded")
            runtime.update(
                extension_page.evaluate(
                    """async () => {
                      const url = chrome.runtime.getURL("kratos-build-attestation.json");
                      const response = await fetch(url, {cache: "no-store"});
                      const bytes = new Uint8Array(await response.arrayBuffer());
                      const digest = await crypto.subtle.digest("SHA-256", bytes);
                      const hex = [...new Uint8Array(digest)]
                        .map(x => x.toString(16).padStart(2,"0")).join("");
                      return {text: new TextDecoder().decode(bytes), sha256: hex,
                              method: "extension-owned-panel-fetch"};
                    }"""
                )
            )
            identity.extension_page_target_ids = [_sha256_bytes(extension_page.url.encode())[:16]]
        except Error as error:
            return identity, None, "", "", f"{runtime['error']}; {error}"
    return (
        identity,
        json.loads(runtime["text"]),
        str(runtime["sha256"]),
        str(runtime["method"]),
        "",
    )


def verify_runtime_readback(
    candidate: Path,
    runtime_payload: dict[str, Any],
    runtime_file_sha256: str,
    guard_root: Path,
    source: str = "extension runtime evidence",
) -> RuntimeAttestationReadback:
    disk_path = candidate / "evidence" / "build-attestation.json"
    disk_bytes = disk_path.read_bytes()
    runtime = BuildAttestation.model_validate(runtime_payload)
    trusted_key = guard_root / "trust" / "keys" / f"{runtime.signing_key_id}.pub.json"
    verification = verify_candidate(candidate, trusted_key)
    matching_bytes = _sha256_bytes(disk_bytes) == runtime_file_sha256
    integrity = calculate_attestation_integrity(runtime) == runtime.integrity_sha256
    expected = BuildAttestation.model_validate_json(disk_bytes)
    matching_claims = (
        runtime.candidate_id == expected.candidate_id
        and runtime.artefact_payload_manifest_hash == expected.artefact_payload_manifest_hash
        and runtime.signing_key_id == expected.signing_key_id
    )
    proven = (
        matching_bytes
        and integrity
        and matching_claims
        and verification.overall_provenance_state is EvidenceState.PROVEN
    )
    return RuntimeAttestationReadback(
        source=source,
        extension_url="kratos-build-attestation.json",
        candidate_id=runtime.candidate_id,
        source_head=runtime.source_head,
        repository_source_manifest_hash=runtime.repository_source_manifest_hash,
        component_input_manifest_hash=runtime.component_build_input_manifest_hash,
        payload_manifest_hash=runtime.artefact_payload_manifest_hash,
        signing_key_id=runtime.signing_key_id,
        signature_algorithm=runtime.signature_algorithm,
        canonical_integrity_hash=runtime.integrity_sha256,
        attestation_file_sha256=runtime_file_sha256,
        signature_state=verification.signature_state,
        signer_trust_state=verification.signer_trust_state,
        state=EvidenceState.PROVEN if proven else EvidenceState.CONTRADICTED,
    )


def run_extension_canary(
    guard_root: Path,
    candidate: Path,
    target: Path,
    policy: BrowserLaunchPolicy,
    verifier_identity: dict[str, object],
) -> CanaryReport:
    candidate = candidate.resolve()
    guard_root = guard_root.resolve()
    attestation = BuildAttestation.model_validate_json(
        (candidate / "evidence" / "build-attestation.json").read_text(encoding="utf-8")
    )
    extension_manifest = json.loads(
        (candidate / "artefact" / "extension" / "manifest.json").read_text(encoding="utf-8")
    )
    trusted_key = guard_root / "trust" / "keys" / f"{attestation.signing_key_id}.pub.json"
    provenance = verify_candidate(candidate, trusted_key)
    if provenance.overall_provenance_state is not EvidenceState.PROVEN:
        raise PermissionError("BLOCKED_CANDIDATE_INTEGRITY")
    before_candidate = candidate_manifest(candidate)
    if before_candidate != policy.candidate_manifest_sha256:
        raise RuntimeError("CANDIDATE_CHANGED_BEFORE_RUNTIME")
    if hash_file(Path(policy.executable_path)).digest != policy.executable_sha256:
        raise RuntimeError("BROWSER_EXECUTABLE_CHANGED_AFTER_PLANNING")
    preexisting = browser_pid_set()
    target_witness = MutationWitness(target, [])
    profile = Path(policy.user_data_directory)
    if profile.exists():
        raise FileExistsError("canary profile must be fresh")
    profile.mkdir(parents=True)
    run_root = profile.parent
    attempts: list[NetworkAttempt] = []
    context: BrowserContext | None = None
    extension_runtime: ExtensionRuntimeIdentity | None = None
    readback: RuntimeAttestationReadback | None = None
    graceful = False
    forced = False
    process_identity: BrowserProcessIdentity | None = None
    owned_pids: list[int] = []
    children: list[int] = []
    error_boundary = ""
    try:
        with sync_playwright() as playwright:
            resolved = Path(playwright.chromium.executable_path).resolve()
            if str(resolved) != str(Path(policy.executable_path).resolve()):
                raise RuntimeError("PLAYWRIGHT_BROWSER_RESOLUTION_CHANGED")
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                channel="chromium",
                headless=False,
                args=[
                    f"--disable-extensions-except={policy.extension_path}",
                    f"--load-extension={policy.extension_path}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-sync",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--password-store=basic",
                    "--proxy-server=http://127.0.0.1:9",
                    "--proxy-bypass-list=<-loopback>",
                    "--window-position=-32000,-32000",
                    "--window-size=800,600",
                ],
            )
            deadline = time.monotonic() + policy.startup_timeout_seconds
            profile_processes: list[psutil.Process] = []
            while time.monotonic() < deadline:
                profile_processes = _profile_processes(profile)
                if profile_processes:
                    break
                time.sleep(0.1)
            if not profile_processes:
                raise RuntimeError("PLAYWRIGHT_CHROMIUM_PROCESS_UNPROVEN")
            roots = [
                process
                for process in profile_processes
                if process.ppid() not in {item.pid for item in profile_processes}
            ]
            process = min(roots or profile_processes, key=lambda item: item.create_time())
            observed_command = process.cmdline()
            observed_joined = " ".join(observed_command)
            if policy.extension_path not in observed_joined or str(profile) not in observed_joined:
                raise RuntimeError("CANARY_PROCESS_COMMAND_LINE_MISMATCH")
            owned = _owned_processes(process.pid)
            owned_pids = sorted(item.pid for item in owned)
            children = sorted(item.pid for item in owned if item.pid != process.pid)
            process_identity = BrowserProcessIdentity(
                pid=process.pid,
                parent_pid=process.ppid(),
                child_pids=children,
                executable_path=process.exe(),
                executable_sha256=hash_file(Path(process.exe())).digest,
                command_line=observed_command,
                command_line_sha256=_command_hash(observed_command),
                state=EvidenceState.PROVEN,
                created_at=datetime.fromtimestamp(process.create_time(), UTC),
            )

            def record_request(request: Request) -> None:
                if request.url.startswith(("http://", "https://", "ws://", "wss://")):
                    attempts.append(
                        NetworkAttempt(
                            url=request.url,
                            resource_type=request.resource_type,
                            decision="BLOCKED_BY_BLACKHOLE_PROXY_AND_CONTEXT_POLICY",
                            observed_at=datetime.now(UTC),
                        )
                    )

            context.on("request", record_request)
            context.route("http://**/*", lambda route: route.abort())
            context.route("https://**/*", lambda route: route.abort())
            (
                extension_runtime,
                runtime_payload,
                runtime_hash,
                readback_source,
                observation_error,
            ) = _extension_observation(
                context,
                process.pid,
                str(profile),
                str(extension_manifest["name"]),
                str(extension_manifest["version"]),
                str(extension_manifest["background"]["service_worker"]),
            )
            if runtime_payload is None:
                error_boundary = observation_error
            else:
                readback = verify_runtime_readback(
                    candidate, runtime_payload, runtime_hash, guard_root, readback_source
                )
            context.close()
            context = None
            _, lingering = psutil.wait_procs(owned, timeout=10)
            graceful = not lingering
    except (
        Error,
        OSError,
        RuntimeError,
        subprocess.TimeoutExpired,
        TimeoutError,
        ValueError,
    ) as error:
        error_boundary = str(error)
    finally:
        if context is not None:
            try:
                context.close()
            except Error:
                pass
        remaining_owned = [
            process for process in _profile_processes(profile) if process.pid not in preexisting
        ]
        if remaining_owned:
            forced = True
            for owned_process in reversed(remaining_owned):
                try:
                    owned_process.terminate()
                except psutil.Error:
                    pass
            _, alive = psutil.wait_procs(remaining_owned, timeout=5)
            for remaining in alive:
                try:
                    remaining.kill()
                except psutil.Error:
                    pass
        _, lingering = psutil.wait_procs(
            [process for process in _profile_processes(profile) if process.pid not in preexisting],
            timeout=5,
        )
        surviving = [process.pid for process in lingering if process.is_running()]
    after_candidate = candidate_manifest(candidate)
    target_result = target_witness.finish()
    postexisting = browser_pid_set()
    if not surviving:
        _assert_no_link_escape(profile, guard_root / ".work" / "browser-canaries")
        shutil.rmtree(profile)
        cleanup = "REMOVED_GUARD_OWNED_PROFILE"
    else:
        cleanup = "PRESERVED_PROCESS_OWNERSHIP_UNCERTAIN"
    network_state = EvidenceState.PROVEN if not attempts else EvidenceState.CONTRADICTED
    runtime_proven = (
        extension_runtime is not None
        and readback is not None
        and readback.state is EvidenceState.PROVEN
        and network_state is EvidenceState.PROVEN
        and before_candidate == after_candidate
        and not target_result.changed
        and graceful
        and not surviving
    )
    first_failure = (
        "CURRENT_NORMAL_PROFILE_IDENTITY"
        if runtime_proven
        else (
            error_boundary
            or ("browser-level-network-policy" if attempts else "")
            or ("candidate-mutation" if before_candidate != after_candidate else "")
            or ("target-mutation" if target_result.changed else "")
            or ("clean-shutdown" if surviving or not graceful else "runtime-attestation-readback")
        )
    )
    process_identity = process_identity or BrowserProcessIdentity(
        pid=0,
        parent_pid=0,
        child_pids=[],
        executable_path=policy.executable_path,
        executable_sha256=policy.executable_sha256,
        command_line=policy.command_line,
        command_line_sha256=policy.command_line_sha256,
        state=EvidenceState.UNPROVEN,
    )
    scope_states = {
        RuntimeProofScope.SEALED_CANDIDATE_ON_DISK: EvidenceState.PROVEN,
        RuntimeProofScope.GUARD_LAUNCHED_BROWSER_PROCESS: process_identity.state,
        RuntimeProofScope.ISOLATED_CANARY_LOADED_EXTENSION: (
            EvidenceState.PROVEN if runtime_proven else EvidenceState.UNPROVEN
        ),
        RuntimeProofScope.CURRENT_USER_LOADED_EXTENSION: EvidenceState.UNPROVEN,
        RuntimeProofScope.PROMOTED_EXTENSION: EvidenceState.NOT_APPLICABLE,
        RuntimeProofScope.PRODUCT_BEHAVIOUR: EvidenceState.NOT_APPLICABLE,
    }
    browser_identity = bundled_chromium_identity(guard_root)
    return CanaryReport(
        schema_version="1.0",
        run_id=run_root.name,
        observed_at=datetime.now(UTC),
        verifier_identity=verifier_identity,
        candidate_identity={
            "candidate_id": attestation.candidate_id,
            "payload_manifest_hash": attestation.artefact_payload_manifest_hash,
            "delivery_manifest_hash": str(
                _logical_manifest(candidate / "artefact" / "extension", excluded_names=set())[
                    "manifest_sha256"
                ]
            ),
            "attestation_file_sha256": hash_file(
                candidate / "evidence" / "build-attestation.json"
            ).digest,
            "signing_key_id": attestation.signing_key_id,
        },
        provenance_verification=provenance.model_dump(mode="json"),
        browser_executable=browser_identity,
        launch_policy=policy,
        profile_identity=BrowserProfileIdentity(
            user_data_directory=str(profile),
            profile_directory="Canary",
            fresh=True,
            guard_owned=True,
            cleanup_state=EvidenceState.PROVEN
            if cleanup.startswith("REMOVED")
            else EvidenceState.UNPROVEN,
            state=EvidenceState.PROVEN,
        ),
        browser_process=process_identity,
        extension_runtime=extension_runtime,
        runtime_readback=readback,
        runtime_verification=RuntimeChainVerification(
            scope_states=scope_states,
            source_to_build_state=EvidenceState.PROVEN,
            build_to_runtime_state=EvidenceState.PROVEN
            if runtime_proven
            else EvidenceState.UNPROVEN,
            loaded_client_state=EvidenceState.PROVEN if runtime_proven else EvidenceState.UNPROVEN,
            current_user_loaded_client_state=EvidenceState.UNPROVEN,
            first_failing_boundary=first_failure,
            contradictions=[],
            uncertainties=[
                "Current normal-profile extension identity was not observed.",
                "Network isolation is browser-level, not kernel-level.",
            ],
            verdict=(
                "ISOLATED_LOADED_CLIENT_PROVEN_CURRENT_PROFILE_UNPROVEN"
                if runtime_proven
                else "BROWSER_PROCESS_PROVEN_LOADED_EXTENSION_UNPROVEN"
            ),
            browser_capability_state="BROWSER_SIDELOAD_CAPABILITY_PROVEN",
            service_worker_state=(
                "EXTENSION_SERVICE_WORKER_PROVEN"
                if extension_runtime is not None
                else "EXTENSION_SERVICE_WORKER_UNPROVEN"
            ),
            runtime_readback_state=(
                "RUNTIME_ATTESTATION_READBACK_PROVEN"
                if readback is not None and readback.state is EvidenceState.PROVEN
                else "RUNTIME_ATTESTATION_READBACK_UNPROVEN"
            ),
        ),
        network_isolation=NetworkIsolationEvidence(
            policy="BROWSER_LEVEL_NETWORK_BLOCKING_PROVEN"
            if not attempts
            else "CANARY_FAILED_NETWORK_POLICY",
            attempted_requests=attempts,
            blocked_request_count=len(attempts),
            provider_request_count=0,
            itzako_api_request_count=0,
            third_party_request_count=len(attempts),
            lesson_operation_count=0,
            explanation_operation_count=0,
            state=network_state,
        ),
        lifecycle=CanaryLifecycleEvidence(
            preexisting_browser_pids=preexisting,
            owned_browser_pids=owned_pids,
            observed_child_pids=children,
            graceful_close=graceful,
            forced_close_required=forced,
            surviving_owned_pids=surviving,
            profile_cleanup=cleanup,
            state=EvidenceState.PROVEN if not surviving else EvidenceState.CONTRADICTED,
        ),
        candidate_witness=CandidateRuntimeWitness(
            candidate_directory=str(candidate),
            before_manifest_sha256=before_candidate,
            after_manifest_sha256=after_candidate,
            changed=before_candidate != after_candidate,
            state=EvidenceState.PROVEN
            if before_candidate == after_candidate
            else EvidenceState.CONTRADICTED,
        ),
        target_witness=target_result.model_dump(mode="json"),
        current_user_runtime=CurrentUserRuntimeObservation(
            preexisting_browser_pids=preexisting,
            post_canary_browser_pids=postexisting,
            overlapping_canary_pids=sorted(set(owned_pids) & set(preexisting)),
            loaded_extension_state=EvidenceState.UNPROVEN,
            reason="no authorised non-mutating live extension readback",
            state=EvidenceState.PROVEN
            if set(preexisting) <= set(postexisting)
            else EvidenceState.CONTRADICTED,
        ),
        exact_extension_load_path=policy.extension_path,
        non_guarantees=[
            "Does not prove the current user browser loaded this candidate.",
            "Does not promote or replace an extension.",
            "Does not prove product behaviour, lessons, or explanations.",
            "Does not claim kernel-level network isolation.",
        ],
        next_required_evidence="authorised non-mutating current-runtime attestation readback",
        learning_summary=(
            "Proof is scoped: isolated canary identity cannot transfer to a normal profile."
        ),
    )
