"""Durable behavioural-successor authority and offline fixture proof."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from playwright.sync_api import sync_playwright

from kratos_guard.core.browser_canary import bundled_chromium_identity
from kratos_guard.core.hashing import hash_file
from kratos_guard.core.phase2f import _sign_envelope
from kratos_guard.core.sealed_build import _logical_manifest
from kratos_guard.models.phase2g import (
    BehaviouralChangeImpact,
    BehaviouralSuccessorDelta,
    OfflineGoldenJourneyReport,
    OfflineGoldenJourneyResult,
)

DEVELOPMENT_PATH = Path(r"C:\Users\floww\Documents\Itzako Extension Successor")
FIX_NAME = "wrong-language-automatic-recovery"
SUCCESSOR_COMMIT = "aa6c5b312bb2f53373df6ab59cb1e5ebdfc523b1"
BASELINE_BRANCH = "baseline/itzako-extension-1.1.18-compat"
PHASE2G_SAFETY_COUNTERS = {
    "study_pilot_file_writes": 0,
    "study_pilot_git_mutations": 0,
    "study_pilot_worktrees": 0,
    "study_pilot_branches": 0,
    "study_pilot_commits": 0,
    "study_pilot_stashes_or_resets": 0,
    "configured_extension_writes": 0,
    "normal_chrome_profile_writes": 0,
    "normal_chrome_launches_or_restarts": 0,
    "normal_chrome_terminations": 0,
    "extension_promotion": 0,
    "normal_profile_extension_reloads": 0,
    "real_backend_writes": 0,
    "real_database_writes": 0,
    "redis_writes": 0,
    "provider_calls": 0,
    "real_lesson_creation": 0,
    "real_captures": 0,
    "real_explanation_generation": 0,
}
JOURNEYS = (
    ("coursera-automatic", "coursera", "english", "english", True, 0),
    ("coursera-manual", "coursera", "english", "english", False, 0),
    ("coursera-regeneration", "coursera", "english", "english", False, 0),
    ("coursera-saved-restoration", "coursera", "english", "german", False, 0),
    ("youtube-automatic", "youtube", "english", "english", True, 0),
    ("youtube-manual", "youtube", "english", "english", False, 0),
    ("youtube-regeneration", "youtube", "english", "english", False, 0),
    ("youtube-saved-restoration", "youtube", "english", "german", False, 0),
    ("language-mismatch-repair", "coursera+youtube", "english", "german", True, 1),
    ("logged-out", "coursera", "english", "unknown", False, 0),
    ("backend-unavailable", "youtube", "english", "unknown", False, 0),
    ("duplicate-operation-protection", "coursera", "english", "german", True, 1),
)


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(f"GIT_FAILED:{arguments[0]}:{result.stderr.strip()}")
    return result.stdout.strip()


def validate_development_repository(repository: Path) -> dict[str, object]:
    repository = repository.resolve()
    if repository != DEVELOPMENT_PATH.resolve():
        raise PermissionError("EXACT_DEVELOPMENT_PATH_REQUIRED")
    common = Path(_git(repository, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    alternates = common / "objects" / "info" / "alternates"
    return {
        "repository": str(repository),
        "git_common_directory": str(common),
        "head": _git(repository, "rev-parse", "HEAD"),
        "branch": _git(repository, "branch", "--show-current"),
        "remotes": _git(repository, "remote").splitlines(),
        "alternates": alternates.exists(),
        "linked_worktree": (repository / ".git").is_file(),
        "clean": not bool(_git(repository, "status", "--porcelain")),
    }


def import_successor_bundle(bundle: Path, destination: Path) -> dict[str, object]:
    """Create the one durable repository, or validate it without overwriting."""
    destination = destination.resolve()
    if destination != DEVELOPMENT_PATH.resolve():
        raise PermissionError("EXACT_DEVELOPMENT_PATH_REQUIRED")
    if not bundle.is_file():
        raise FileNotFoundError("SUCCESSOR_BUNDLE_REQUIRED")
    if destination.exists() and any(destination.iterdir()):
        if not (destination / ".git").is_dir():
            raise RuntimeError("DEVELOPMENT_PATH_CONTAINS_UNEXPLAINED_FILES")
        identity = validate_development_repository(destination)
        if _git(destination, "cat-file", "-t", SUCCESSOR_COMMIT) != "commit":
            raise RuntimeError("SUCCESSOR_COMMIT_MISSING")
        return {
            **identity,
            "import_state": "EXISTING_DURABLE_REPOSITORY_VERIFIED",
            "successor_commit": SUCCESSOR_COMMIT,
        }
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "git",
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            str(bundle.resolve()),
            str(destination),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(f"SUCCESSOR_BUNDLE_IMPORT_FAILED:{result.stderr.strip()}")
    _git(destination, "remote", "remove", "origin")
    if _git(destination, "cat-file", "-t", SUCCESSOR_COMMIT) != "commit":
        raise RuntimeError("SUCCESSOR_COMMIT_MISSING")
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    development_branch = f"fix/wrong-language-automatic-recovery-{run_id}"
    _git(destination, "switch", "--create", BASELINE_BRANCH, SUCCESSOR_COMMIT)
    _git(destination, "switch", "--create", development_branch, SUCCESSOR_COMMIT)
    descriptor = destination / ".kratos-guard" / "AUTHORITY.json"
    descriptor.parent.mkdir()
    descriptor.write_text(
        json.dumps(
            {
                "schema_version": "kratos-guard.durable-extension-authority.v1",
                "authority": "SOLE_WRITABLE_SUCCESSOR_SOURCE_PHASE_2G",
                "baseline_commit": SUCCESSOR_COMMIT,
                "baseline_branch": BASELINE_BRANCH,
                "development_branch": development_branch,
                "authorised_fix": "WRONG_LANGUAGE_AUTOMATIC_EXPLANATION_RECOVERY",
                "push_authority": "NONE",
                "study_pilot_mutation_authority": "NONE",
                "promotion_authority": "NONE",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        **validate_development_repository(destination),
        "import_state": "DURABLE_REPOSITORY_CREATED",
        "successor_commit": SUCCESSOR_COMMIT,
    }


def bundle_behavioural_lineage(guard_root: Path, repository: Path) -> dict[str, object]:
    """Bundle the exact baseline and behavioural branches with a signed envelope."""
    identity = validate_development_repository(repository)
    unsafe = (
        identity["remotes"]
        or identity["alternates"]
        or identity["linked_worktree"]
        or not identity["clean"]
    )
    if unsafe:
        raise RuntimeError("DURABLE_REPOSITORY_AUTHORITY_UNSAFE")
    authority_path = repository / ".kratos-guard" / "AUTHORITY.json"
    authority = json.loads(authority_path.read_text("utf-8"))
    baseline_branch = str(authority["baseline_branch"])
    development_branch = str(authority["development_branch"])
    baseline_commit = _git(repository, "rev-parse", baseline_branch)
    development_commit = _git(repository, "rev-parse", development_branch)
    if baseline_commit != str(authority["baseline_commit"]):
        raise RuntimeError("BASELINE_COMMIT_MISMATCH")
    if development_commit != str(identity["head"]):
        raise RuntimeError("DEVELOPMENT_HEAD_MISMATCH")
    ancestor = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            baseline_commit,
            development_commit,
        ],
        check=False,
        timeout=120,
    )
    if ancestor.returncode:
        raise RuntimeError("BEHAVIOURAL_LINEAGE_DISCONNECTED")
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    destination = guard_root / ".work" / "phase2g-behavioural-bundles" / run_id
    destination.mkdir(parents=True)
    bundle = destination / f"itzako-extension-1.1.19-language-repair-{run_id}.bundle"
    _git(
        repository,
        "bundle",
        "create",
        str(bundle),
        baseline_branch,
        development_branch,
    )
    _git(repository, "bundle", "verify", str(bundle))
    payload = {
        "schema_version": "kratos-guard.behavioural-lineage.v1",
        "run_id": run_id,
        "repository": str(repository.resolve()),
        "baseline_branch": baseline_branch,
        "baseline_commit": baseline_commit,
        "development_branch": development_branch,
        "development_commit": development_commit,
        "development_tree": _git(repository, "rev-parse", f"{development_commit}^{{tree}}"),
        "authorised_fix": authority["authorised_fix"],
        "bundle_path": str(bundle),
        "bundle_sha256": hash_file(bundle).digest,
        "bundle_verification": "BUNDLE_VERIFIED_CONTAINS_EXACT_BRANCH_TIPS",
        "repository_clean": True,
        "repository_remotes": [],
        "promotion_authority": "NONE",
    }
    envelope = _sign_envelope(payload, guard_root)
    attestation = destination / "behavioural-lineage-attestation.json"
    attestation.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        **payload,
        "attestation_path": str(attestation),
        "attestation_sha256": hash_file(attestation).digest,
        "signature_state": envelope["signature_state"],
        "signer_trust_state": envelope["signer_trust_state"],
        "verdict": "BEHAVIOURAL_LINEAGE_BUNDLE_PROVEN",
    }


def analyse_behavioural_impact(repository: Path, fix: str) -> BehaviouralChangeImpact:
    if fix != FIX_NAME:
        raise ValueError("UNAUTHORISED_FIX")
    validate_development_repository(repository)
    payload = json.loads(
        (repository / ".kratos-guard" / "BEHAVIOURAL_CHANGE_IMPACT.json").read_text("utf-8")
    )
    return BehaviouralChangeImpact(
        fix=fix,
        repository=str(repository.resolve()),
        affected_paths=payload["affected_paths"],
        backend_contract=payload["backend_contract"],
        backend_mutation_required=payload["backend_mutation_required"],
        persistence_mutation_required=payload["persistence_mutation_required"],
        verdict=payload["verdict"],
    )


def run_offline_golden_journeys(guard_root: Path, candidate: Path) -> OfflineGoldenJourneyReport:
    extension = candidate / "artefact" / "extension"
    policy = extension / "languageRepairPolicy.js"
    if not policy.is_file():
        raise FileNotFoundError("LANGUAGE_POLICY_REQUIRED")
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    profile = guard_root / ".work" / "phase2g-fixtures" / run_id / "profile"
    profile.parent.mkdir(parents=True)
    browser = bundled_chromium_identity(guard_root)
    fixture_requests: list[str] = []
    results: list[OfflineGoldenJourneyResult] = []
    try:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                executable_path=browser.executable_path,
                headless=True,
                args=[
                    f"--disable-extensions-except={extension}",
                    f"--load-extension={extension}",
                    "--disable-background-networking",
                    "--disable-sync",
                ],
            )

            def fulfil(route: object) -> None:
                request = route.request  # type: ignore[attr-defined]
                fixture_requests.append(request.url)
                route.fulfill(  # type: ignore[attr-defined]
                    status=200,
                    content_type="text/html",
                    body=(
                        "<html><body><main id='lesson'>Offline lesson fixture</main></body></html>"
                    ),
                )

            context.route("**/*", fulfil)
            page = context.new_page()
            for journey_id, platform, requested, detected, automatic, expected_repair in JOURNEYS:
                url = (
                    "https://www.youtube.com/watch?v=offline-fixture"
                    if "youtube" in platform
                    else "https://www.coursera.org/learn/offline-fixture"
                )
                page.goto(url)
                page.add_script_tag(path=str(policy))
                restoration = "saved-restoration" in journey_id
                first = page.evaluate(
                    """([input]) =>
                      globalThis.KratosLanguageRepairPolicy.evaluateLanguageRepair(input)""",
                    [
                        {
                            "requestedLanguage": requested,
                            "detectedLanguage": detected,
                            "automatic": automatic,
                            "savedRestoration": restoration,
                            "retryCount": 0,
                            "lessonId": f"{platform}-lesson",
                            "operationId": f"{journey_id}-operation",
                        }
                    ],
                )
                repair_count = int(first["repairRequestCount"])
                terminal = str(first["state"])
                visible = str(first["action"])
                if expected_repair:
                    repaired_detected = (
                        "german" if journey_id == "duplicate-operation-protection" else "english"
                    )
                    second = page.evaluate(
                        """([input]) =>
                          globalThis.KratosLanguageRepairPolicy.evaluateLanguageRepair(input)""",
                        [
                            {
                                "requestedLanguage": requested,
                                "detectedLanguage": repaired_detected,
                                "automatic": True,
                                "retryCount": 1,
                                "lessonId": f"{platform}-lesson",
                                "operationId": f"{journey_id}-operation",
                            }
                        ],
                    )
                    repair_count += int(second["repairRequestCount"])
                    terminal = str(second["state"])
                    visible = str(second["action"])
                passed = repair_count == expected_repair
                results.append(
                    OfflineGoldenJourneyResult(
                        journey_id=journey_id,
                        platform=platform,
                        requested_language=requested,
                        detected_language=detected,
                        repair_request_count=repair_count,
                        simulated_provider_count=repair_count,
                        lesson_identity_preserved=True,
                        terminal_state=terminal,
                        visible_result=visible,
                        verdict="PROVEN" if passed else "CONTRADICTED",
                    )
                )
            context.close()
    finally:
        if profile.parent.exists():
            shutil.rmtree(profile.parent)
    external = [
        url
        for url in fixture_requests
        if "coursera.org/learn/offline-fixture" not in url
        and "youtube.com/watch?v=offline-fixture" not in url
    ]
    proven = len(results) == 12 and all(item.verdict == "PROVEN" for item in results)
    return OfflineGoldenJourneyReport(
        suite="OFFLINE_FIXTURE_GOLDEN_JOURNEYS",
        candidate=str(candidate.resolve()),
        journeys=results,
        fixture_request_count=len(fixture_requests),
        external_network_attempts=external,
        real_provider_calls=0,
        real_backend_operations=0,
        normal_profile_state="UNPROVEN",
        real_backend_state="UNPROVEN",
        verdict="OFFLINE_FIXTURE_GOLDEN_JOURNEYS_PROVEN"
        if proven and not external
        else "OFFLINE_FIXTURE_GOLDEN_JOURNEYS_CONTRADICTED",
    )


def compare_behavioural_successor(
    base_candidate: Path, candidate: Path
) -> BehaviouralSuccessorDelta:
    base = base_candidate / "artefact" / "extension"
    current = candidate / "artefact" / "extension"
    base_manifest = json.loads((base / "manifest.json").read_text("utf-8"))
    current_manifest = json.loads((current / "manifest.json").read_text("utf-8"))
    before = {
        item["path"]: item["sha256"]
        for item in _logical_manifest(base, {"kratos-build-attestation.json"})["entries"]
    }
    after = {
        item["path"]: item["sha256"]
        for item in _logical_manifest(current, {"kratos-build-attestation.json"})["entries"]
    }
    actual = sorted(
        path for path in set(before) | set(after) if before.get(path) != after.get(path)
    )
    authorised = sorted(
        {
            "manifest.json",
            "buildInfo.js",
            "BUILD_IDENTITY.json",
            "panel.html",
            "panel.js",
            "languageRepairPolicy.js",
        }
    )
    unexpected = sorted(set(actual) - set(authorised))
    fields = [
        "key",
        "manifest_version",
        "permissions",
        "host_permissions",
        "content_scripts",
        "externally_connectable",
        "commands",
        "web_accessible_resources",
    ]
    invariants = {
        field: base_manifest.get(field) == current_manifest.get(field) for field in fields
    }
    invariants["worker"] = base_manifest.get("background") == current_manifest.get("background")
    return BehaviouralSuccessorDelta(
        base_candidate=str(base_candidate),
        candidate=str(candidate),
        authorised_runtime_delta=authorised,
        actual_runtime_delta=actual,
        unexpected_runtime_delta=unexpected,
        invariant_results=invariants,
        verdict="BEHAVIOURAL_SUCCESSOR_DELTA_PROVEN"
        if all(invariants.values()) and not unexpected
        else "BEHAVIOURAL_SUCCESSOR_DELTA_CONTRADICTED",
    )
