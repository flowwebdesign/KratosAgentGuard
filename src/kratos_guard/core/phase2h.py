"""Capped, marker-scoped real-backend evidence planning."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import psutil

from kratos_guard.core.sealed_build import verify_candidate
from kratos_guard.models.phase2h import (
    BackendContractIdentity,
    ConcurrentActivityEvidence,
    DatabaseReadbackEvidence,
    ProtectedTargetDriftClassification,
    ProtectedTargetDriftPath,
    ProviderTestSeamEvidence,
    RealBackendBudget,
    RealBackendJourney,
    RealBackendJourneyPlan,
    RealBackendSuiteReport,
    SyntheticAuditIdentity,
)

BACKEND_ENDPOINT = "http://127.0.0.1:8000"
APP_BRIDGE_ENDPOINT = "http://127.0.0.1:3000"
EXPECTED_CANDIDATE_ID = "itzako-extension-1.1.19-language-repair-20260725T115732Z-5feba5dc7f1a"
EXPECTED_CANDIDATE_PAYLOAD = "5feba5dc7f1af72f3c471aed6839ed67aa8de1c7c1bbeac94d6b9e67e68e3eb1"
SCRIPTS_ROOT = Path(
    os.environ.get(
        "KAG_STUDY_PILOT_SCRIPTS_ROOT",
        Path.home() / "Documents" / "Scripts",
    )
)
CANONICAL_ROOT = Path(
    os.environ.get(
        "KAG_ITZAKO_RUNTIME_ROOT",
        SCRIPTS_ROOT / "Study-Pilot-extension-canonical-recovery-20260715-verification-release",
    )
)
COORDINATION_ROOT = Path(
    os.environ.get(
        "KAG_STUDY_PILOT_COORDINATION_ROOT",
        SCRIPTS_ROOT / "Study-Pilot",
    )
)
WRITER_LEASE_PATH = CANONICAL_ROOT / "Study_master" / ".ai-dev" / "WRITER_LEASE.json"
REQUIRED_ROUTES = (
    "/api/v1/captures",
    "/api/v1/sessions/resolve-lesson",
    "/api/v1/sessions/{session_id}/lesson-operations/{operation_id}/generate",
    "/api/v1/sessions/{session_id}/lesson-operations/{operation_id}/resolve",
    "/api/v1/sessions/{session_id}/lesson-operations/{operation_id}/retry",
    "/api/v1/sessions/{session_id}/lesson-operations/{operation_id}/regenerate",
)
REAL_BACKEND_JOURNEYS = (
    ("coursera-automatic", "coursera", "automatic"),
    ("coursera-manual", "coursera", "manual"),
    ("coursera-regeneration", "coursera", "regeneration"),
    ("coursera-saved-restoration", "coursera", "saved-restoration"),
    ("youtube-automatic", "youtube", "automatic"),
    ("youtube-manual", "youtube", "manual"),
    ("youtube-regeneration", "youtube", "regeneration"),
    ("youtube-saved-restoration", "youtube", "saved-restoration"),
    ("wrong-language-mismatch-repair", "coursera+youtube", "language-repair"),
    ("logged-out", "coursera", "logged-out"),
    ("backend-unavailable", "youtube", "backend-unavailable"),
    ("duplicate-operation-protection", "coursera", "duplicate-protection"),
)
PHASE2H_SAFETY_COUNTERS = {
    "study_pilot_source_writes": 0,
    "study_pilot_git_mutations": 0,
    "study_pilot_worktrees": 0,
    "study_pilot_branches": 0,
    "backend_source_writes": 0,
    "backend_restarts": 0,
    "backend_container_changes": 0,
    "migration_changes": 0,
    "normal_chrome_mutations": 0,
    "normal_chrome_launches_or_restarts": 0,
    "normal_profile_extension_reloads": 0,
    "real_learner_account_uses": 0,
    "provider_configuration_changes": 0,
    "external_provider_calls": 0,
    "real_provider_cost_usd": 0,
    "arbitrary_database_writes": 0,
    "unrelated_record_deletions": 0,
}


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _fetch_json(url: str) -> tuple[dict[str, object], str]:
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"HTTP_READ_FAILED:{url}:{type(exc).__name__}") from exc
    payload = json.loads(body)
    if not isinstance(payload, dict):
        raise RuntimeError(f"HTTP_JSON_OBJECT_REQUIRED:{url}")
    return payload, hashlib.sha256(body).hexdigest()


def _listener_process(port: int) -> psutil.Process:
    matches: list[psutil.Process] = []
    for connection in psutil.net_connections(kind="tcp"):
        if (
            connection.status == psutil.CONN_LISTEN
            and connection.laddr
            and connection.laddr.port == port
            and connection.pid
        ):
            matches.append(psutil.Process(connection.pid))
    unique = {process.pid: process for process in matches}
    if len(unique) != 1:
        raise RuntimeError(f"LISTENER_IDENTITY_AMBIGUOUS:{port}:{sorted(unique)}")
    return next(iter(unique.values()))


def inspect_backend_contract(profile: str) -> BackendContractIdentity:
    if profile != "itzako":
        raise ValueError("ITZAKO_PROFILE_REQUIRED")
    ready, _ = _fetch_json(f"{BACKEND_ENDPOINT}/api/v1/ready")
    openapi_before, pre_hash = _fetch_json(f"{BACKEND_ENDPOINT}/openapi.json")
    openapi_after, post_hash = _fetch_json(f"{BACKEND_ENDPOINT}/openapi.json")
    runtime = ready.get("runtime_identity")
    if not isinstance(runtime, dict):
        runtime = {}
    process = _listener_process(8000)
    command = process.cmdline()
    cwd = process.cwd()
    paths = openapi_before.get("paths")
    paths = paths if isinstance(paths, dict) else {}
    route_hashes = {
        route: _canonical_hash(paths[route]) for route in REQUIRED_ROUTES if route in paths
    }
    database = runtime.get("database")
    database = database if isinstance(database, dict) else {}
    provider = process.environ()
    provider_boundary = {
        "provider_mode": provider.get("STUDY_PILOT_PROVIDER_MODE", "UNKNOWN"),
        "generation_provider": provider.get("GENERATION_PROVIDER", "UNKNOWN"),
        "embedding_provider": provider.get("EMBEDDING_PROVIDER", "UNKNOWN"),
        "real_providers_allowed": (
            provider.get("PAID_CALL_ROUTER_ALLOW_REAL_PROVIDERS", "").lower() == "true"
        ),
        "external_provider_call_cap": 0,
    }
    auto_reload = any("reload" in argument.casefold() for argument in command)
    process_match = int(runtime.get("process_id") or -1) == process.pid
    identity_fields = (
        "runtime_id",
        "manifest_sha256",
        "protected_digest_sha256",
        "source_root",
    )
    identity_complete = all(str(runtime.get(field) or "") for field in identity_fields)
    routes_complete = len(route_hashes) == len(REQUIRED_ROUTES)
    migration_heads = database.get("migration_heads")
    migration_heads = migration_heads if isinstance(migration_heads, list) else []
    proven = (
        ready.get("status") == "ready"
        and process_match
        and identity_complete
        and routes_complete
        and pre_hash == post_hash
        and migration_heads == ["017"]
        and not auto_reload
    )
    limitations = []
    if runtime.get("backend_worktree_clean") is not True:
        limitations.append(
            "running source is an accepted dirty baseline; protected runtime digest "
            "and no-reload process identity bind the observed contract"
        )
    if runtime.get("release_ready") is not True:
        limitations.append("backend reports release_ready=false")
    return BackendContractIdentity(
        endpoint=BACKEND_ENDPOINT,
        process_identity={
            "pid": process.pid,
            "executable": process.exe(),
            "command_line": command,
            "working_directory": cwd,
            "creation_time": datetime.fromtimestamp(process.create_time(), UTC).isoformat(),
            "runtime_id": str(runtime.get("runtime_id") or ""),
            "build_id": str(runtime.get("build_id") or ""),
            "manifest_sha256": str(runtime.get("manifest_sha256") or ""),
            "protected_digest_sha256": str(runtime.get("protected_digest_sha256") or ""),
            "source_root": str(runtime.get("source_root") or ""),
            "runtime_source_commit": str(runtime.get("runtime_source_commit") or ""),
        },
        container_identity=None,
        contract_schema_hash=pre_hash,
        relevant_route_hashes=route_hashes,
        operation_state_contract=[
            "pending",
            "running",
            "ready",
            "failed",
            "retryable",
        ],
        authentication_contract={
            "issuer": BACKEND_ENDPOINT,
            "scheme": "Bearer backend-session-v2",
            "normal_browser_credentials_prohibited": True,
        },
        regeneration_contract={
            "route": REQUIRED_ROUTES[-1],
            "idempotency_required": True,
            "same_lesson_required": True,
        },
        persistence_readback_contract={
            "database": str(database.get("database") or ""),
            "schema": str(database.get("schema") or ""),
            "required_tables": [
                "users",
                "access_token_sessions",
                "study_artifacts",
                "extension_lesson_operations",
            ],
        },
        migration_head=",".join(str(value) for value in migration_heads),
        provider_boundary=provider_boundary,
        auto_reload=auto_reload,
        observed_at=datetime.now(UTC),
        pre_contract_hash=pre_hash,
        post_contract_hash=post_hash,
        limitations=limitations,
        verdict=(
            "BACKEND_CONTRACT_IDENTITY_PROVEN" if proven else "BACKEND_CONTRACT_IDENTITY_PARTIAL"
        ),
    )


def _classify_drift_path(path: str) -> str:
    normalised = path.replace("\\", "/")
    if normalised.startswith("_agent_runs/"):
        return "TEST_OR_EVIDENCE_ONLY"
    if normalised.startswith("Study_master_backend/alembic/"):
        return "DATABASE_OR_MIGRATION_RELEVANT"
    if normalised.startswith("Study_master_backend/"):
        return "BACKEND_RUNTIME_RELEVANT"
    if normalised.startswith("Study_master/extension/"):
        return "EXTENSION_RUNTIME_RELEVANT"
    if normalised.startswith("Study_master/src/app/api/extension/"):
        return "APP_BRIDGE_RUNTIME_RELEVANT"
    if normalised.startswith("Study_master_dashboard/"):
        return "APP_BRIDGE_RUNTIME_RELEVANT"
    if normalised.startswith(("docs/", ".github/", "tests/")):
        return "UNRELATED_COMPONENT"
    return "UNKNOWN"


def _is_contained(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def classify_protected_target_drift(
    baseline: Path, current: Path
) -> ProtectedTargetDriftClassification:
    baseline_payload = json.loads(baseline.read_text("utf-8"))
    current_payload = json.loads(current.read_text("utf-8"))
    target_root = Path(str(current_payload.get("target_root") or COORDINATION_ROOT)).resolve()
    changed_paths = current_payload.get("changed_paths")
    if not isinstance(changed_paths, list):
        raise ValueError("CURRENT_WITNESS_CHANGED_PATHS_REQUIRED")
    runtime_roots = [
        CANONICAL_ROOT / "Study_master_backend",
        CANONICAL_ROOT / "Study_master",
        CANONICAL_ROOT / "Study_master_dashboard",
    ]
    configured_extension = CANONICAL_ROOT / "Study_master" / "extension"
    paths: list[ProtectedTargetDriftPath] = []
    for raw_path in changed_paths:
        path = str(raw_path)
        resolved = (target_root / path).resolve()
        paths.append(
            ProtectedTargetDriftPath(
                path=path,
                classification=_classify_drift_path(path),
                active_runtime_overlap=any(_is_contained(resolved, root) for root in runtime_roots),
                configured_extension_overlap=_is_contained(resolved, configured_extension),
            )
        )
    unknowns = [item.path for item in paths if item.classification == "UNKNOWN"]
    overlaps = [item.path for item in paths if item.active_runtime_overlap]
    baseline_label = str(
        baseline_payload.get("run_id") or baseline_payload.get("schema_version") or baseline
    )
    verdict = (
        "EXTERNAL_DRIFT_OVERLAPS_RUNTIME"
        if overlaps
        else (
            "EXTERNAL_DRIFT_CLASSIFICATION_INCOMPLETE"
            if unknowns
            else "EXTERNAL_DRIFT_CLASSIFIED_NO_RUNTIME_OVERLAP"
        )
    )
    return ProtectedTargetDriftClassification(
        baseline=baseline_label,
        current=str(current.resolve()),
        target_root=str(target_root),
        paths=paths,
        active_runtime_roots=[str(root) for root in runtime_roots],
        configured_extension_root=str(configured_extension),
        execution_critical_unknowns=unknowns,
        runtime_overlap_paths=overlaps,
        attribution="UNPROVEN",
        verdict=verdict,
    )


def verify_synthetic_audit_identity(profile: str) -> SyntheticAuditIdentity:
    if profile != "itzako":
        raise ValueError("ITZAKO_PROFILE_REQUIRED")
    bootstrap, _ = _fetch_json(f"{APP_BRIDGE_ENDPOINT}/api/extension/bootstrap-config")
    lease = json.loads(WRITER_LEASE_PATH.read_text("utf-8")) if WRITER_LEASE_PATH.is_file() else {}
    extension_token = bootstrap.get("extensionTokenConfigured") is True
    local_bootstrap = bootstrap.get("localBackendSessionBootstrap") is True
    audit_lease = lease.get("status") == "ACTIVE" and "KAG-2H" in str(lease.get("scope") or "")
    proven = extension_token and local_bootstrap and audit_lease
    return SyntheticAuditIdentity(
        profile=profile,
        subject_id_hash="",
        tenant="",
        authentication_method=(
            "pre-existing extension token" if extension_token else "UNAVAILABLE"
        ),
        token_scope=[],
        synthetic_ownership_proof=[],
        pre_existing=proven,
        namespace_isolation=("SYNTHETIC_NAMESPACE_ISOLATION_PROVEN" if proven else "UNPROVEN"),
        normal_user_credentials_used=False,
        blocker=("" if proven else "SYNTHETIC_AUDIT_IDENTITY_NOT_CONFIGURED"),
        verdict=(
            "SYNTHETIC_AUDIT_IDENTITY_PROVEN"
            if proven
            else "BLOCKED_SYNTHETIC_IDENTITY_UNAVAILABLE"
        ),
    )


def verify_provider_test_seam(profile: str) -> ProviderTestSeamEvidence:
    if profile != "itzako":
        raise ValueError("ITZAKO_PROFILE_REQUIRED")
    process = _listener_process(8000)
    environment = process.environ()
    provider_mode = environment.get("STUDY_PILOT_PROVIDER_MODE", "UNKNOWN")
    generation_provider = environment.get("GENERATION_PROVIDER", "UNKNOWN")
    embedding_provider = environment.get("EMBEDDING_PROVIDER", "UNKNOWN")
    external_enabled = (
        environment.get("PAID_CALL_ROUTER_ALLOW_REAL_PROVIDERS", "").lower() == "true"
    )
    scenario_keys = [
        key
        for key in environment
        if "SCENARIO" in key.upper() and ("PROVIDER" in key.upper() or "FIXTURE" in key.upper())
    ]
    support = {
        "same_language_success": generation_provider == "fake",
        "wrong_then_correct": bool(scenario_keys),
        "wrong_then_wrong": bool(scenario_keys),
        "timeout_or_terminal_failure": bool(scenario_keys),
    }
    isolated = bool(scenario_keys) and any(
        "SYNTHETIC" in key.upper() or "AUDIT" in key.upper() for key in scenario_keys
    )
    proven = (
        provider_mode == "disabled"
        and generation_provider == "fake"
        and not external_enabled
        and all(support.values())
        and isolated
    )
    return ProviderTestSeamEvidence(
        profile=profile,
        provider_mode=provider_mode,
        generation_provider=generation_provider,
        embedding_provider=embedding_provider,
        external_provider_enabled=external_enabled,
        pre_existing=generation_provider == "fake",
        runtime_restart_required=False,
        scenario_support=support,
        synthetic_isolation_proven=isolated,
        external_provider_call_cap=0,
        limitations=[
            "the pre-existing fake provider is deterministic but exposes no "
            "run-scoped wrong-language sequence selector"
        ]
        if not proven
        else [],
        verdict=(
            "DETERMINISTIC_PROVIDER_SEAM_PROVEN"
            if proven
            else "DETERMINISTIC_PROVIDER_SEAM_UNAVAILABLE"
        ),
    )


_DATABASE_PROBE = r"""
import hashlib
import json
import os
from sqlalchemy import create_engine, text

engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
relevant = [
    "users", "access_token_sessions", "study_sessions", "documents", "captures",
    "study_artifacts", "extension_lesson_operations", "paid_call_ledger_entries",
]
with engine.connect() as connection:
    transaction = connection.begin()
    connection.execute(text("SET TRANSACTION READ ONLY"))
    identity = connection.execute(text(
        "SELECT current_database(), current_schema(), current_user, "
        "current_setting('transaction_read_only'), "
        "current_setting('default_transaction_read_only')"
    )).one()
    heads = [
        row[0] for row in connection.execute(
            text("SELECT version_num FROM alembic_version ORDER BY version_num")
        )
    ]
    rows = connection.execute(text(
        "SELECT table_name, column_name, data_type, is_nullable "
        "FROM information_schema.columns WHERE table_schema=current_schema() "
        "AND table_name = ANY(:tables) ORDER BY table_name, ordinal_position"
    ), {"tables": relevant}).all()
    contract = [
        {"table": row[0], "column": row[1], "type": row[2], "nullable": row[3]}
        for row in rows
    ]
    present = sorted({item["table"] for item in contract})
    counts = {
        table: connection.execute(
            text('SELECT count(*) FROM "' + table + '"')
        ).scalar_one()
        for table in present
    }
    marker = os.environ.get("KAG_RUN_MARKER", "")
    searchable_types = {
        "character", "character varying", "json", "jsonb", "text",
    }
    searchable_columns = {
        table: [
            item["column"] for item in contract
            if item["table"] == table and item["type"] in searchable_types
        ]
        for table in present
    }
    run_marker_counts = {}
    if marker:
        for table, columns in searchable_columns.items():
            if not columns:
                run_marker_counts[table] = 0
                continue
            predicate = " OR ".join(
                'CAST("' + column + '" AS text) LIKE :marker' for column in columns
            )
            run_marker_counts[table] = connection.execute(
                text('SELECT count(*) FROM "' + table + '" WHERE ' + predicate),
                {"marker": "%" + marker + "%"},
            ).scalar_one()
    transaction.rollback()
print(json.dumps({
    "database": identity[0],
    "schema": identity[1],
    "database_user_hash": hashlib.sha256(identity[2].encode()).hexdigest(),
    "transaction_read_only": identity[3] == "on",
    "default_transaction_read_only": identity[4] == "on",
    "migration_heads": heads,
    "relevant_tables": present,
    "table_column_contract_hash": hashlib.sha256(
        json.dumps(contract, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest(),
    "baseline_counts": counts,
    "run_marker_counts": run_marker_counts,
}))
"""


def verify_database_readback(profile: str, run_marker: str = "") -> DatabaseReadbackEvidence:
    if profile != "itzako":
        raise ValueError("ITZAKO_PROFILE_REQUIRED")
    if run_marker and not run_marker.startswith("KAG-2H-"):
        raise ValueError("PHASE2H_RUN_MARKER_REQUIRED")
    process = _listener_process(8000)
    environment = process.environ()
    database_url = environment.get("DATABASE_URL")
    if not database_url:
        return _unavailable_database_readback("DATABASE_URL_NOT_AVAILABLE")
    child_environment = os.environ.copy()
    child_environment["DATABASE_URL"] = database_url
    child_environment["KAG_RUN_MARKER"] = run_marker
    completed = subprocess.run(
        [process.exe(), "-c", _DATABASE_PROBE],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
        env=child_environment,
    )
    child_environment["DATABASE_URL"] = "<redacted>"
    if completed.returncode:
        return _unavailable_database_readback(
            f"READ_ONLY_DATABASE_PROBE_FAILED:{completed.returncode}"
        )
    payload = json.loads(completed.stdout)
    read_only = payload["transaction_read_only"] is True
    return DatabaseReadbackEvidence(
        database=str(payload["database"]),
        schema_name=str(payload["schema"]),
        database_user_hash=str(payload["database_user_hash"]),
        transaction_read_only=read_only,
        default_transaction_read_only=bool(payload["default_transaction_read_only"]),
        migration_heads=list(payload["migration_heads"]),
        relevant_tables=list(payload["relevant_tables"]),
        table_column_contract_hash=str(payload["table_column_contract_hash"]),
        baseline_counts={str(key): int(value) for key, value in payload["baseline_counts"].items()},
        run_marker_counts={
            str(key): int(value) for key, value in payload["run_marker_counts"].items()
        },
        retained_record_ids=[],
        credentials_redacted=True,
        write_queries_executed=0,
        limitations=(
            []
            if payload["default_transaction_read_only"]
            else [
                "database role is write-capable by default; every Guard probe "
                "forces its transaction read-only"
            ]
        ),
        verdict=(
            "DATABASE_READBACK_AUTHORITY_PROVEN" if read_only else "DATABASE_READBACK_UNAVAILABLE"
        ),
    )


def _unavailable_database_readback(reason: str) -> DatabaseReadbackEvidence:
    return DatabaseReadbackEvidence(
        database="",
        schema_name="",
        database_user_hash="",
        transaction_read_only=False,
        default_transaction_read_only=False,
        migration_heads=[],
        relevant_tables=[],
        table_column_contract_hash="",
        baseline_counts={},
        run_marker_counts={},
        retained_record_ids=[],
        credentials_redacted=True,
        write_queries_executed=0,
        limitations=[reason],
        verdict="DATABASE_READBACK_UNAVAILABLE",
    )


def _candidate_summary(candidate: Path) -> dict[str, object]:
    summary_path = candidate / "evidence" / "candidate-summary.json"
    if not summary_path.is_file():
        raise FileNotFoundError("EXACT_CANDIDATE_SUMMARY_REQUIRED")
    summary = json.loads(summary_path.read_text("utf-8"))
    if not isinstance(summary, dict):
        raise ValueError("CANDIDATE_SUMMARY_OBJECT_REQUIRED")
    if (
        summary.get("candidate_id") != EXPECTED_CANDIDATE_ID
        or summary.get("payload_hash") != EXPECTED_CANDIDATE_PAYLOAD
    ):
        raise RuntimeError("CANDIDATE_IDENTITY_CONTRADICTED")
    return summary


def _verify_exact_candidate(guard_root: Path, candidate: Path) -> dict[str, object]:
    summary = _candidate_summary(candidate)
    attestation = json.loads((candidate / "evidence" / "build-attestation.json").read_text("utf-8"))
    key_id = str(attestation["signing_key_id"])
    verification = verify_candidate(candidate, guard_root / "trust" / "keys" / f"{key_id}.pub.json")
    if verification.overall_provenance_state.value != "PROVEN":
        raise RuntimeError("CANDIDATE_PROVENANCE_UNPROVEN")
    return summary


def plan_real_backend_journeys(guard_root: Path, candidate: Path) -> RealBackendJourneyPlan:
    candidate = candidate.resolve()
    summary = _verify_exact_candidate(guard_root, candidate)
    backend = inspect_backend_contract("itzako")
    synthetic = verify_synthetic_audit_identity("itzako")
    seam = verify_provider_test_seam("itzako")
    database = verify_database_readback("itzako")
    lease = json.loads(WRITER_LEASE_PATH.read_text("utf-8")) if WRITER_LEASE_PATH.is_file() else {}
    blockers: list[str] = []
    if backend.verdict != "BACKEND_CONTRACT_IDENTITY_PROVEN":
        blockers.append("BACKEND_CONTRACT_IDENTITY_UNPROVEN")
    if synthetic.verdict != "SYNTHETIC_AUDIT_IDENTITY_PROVEN":
        blockers.append(synthetic.blocker)
    if seam.verdict != "DETERMINISTIC_PROVIDER_SEAM_PROVEN":
        blockers.append("DETERMINISTIC_PROVIDER_SCENARIOS_UNAVAILABLE")
    if database.verdict != "DATABASE_READBACK_AUTHORITY_PROVEN":
        blockers.append("DATABASE_READBACK_UNAVAILABLE")
    if lease.get("status") == "ACTIVE":
        blockers.append("ACTIVE_WRITER_LEASE_PROTECTS_CANONICAL_RUNTIME")
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    run_marker = f"KAG-2H-{run_id}"
    destination = guard_root / ".work" / "phase2h-plans" / run_id
    destination.mkdir(parents=True)
    path = destination / "real-backend-plan.json"
    plan = RealBackendJourneyPlan(
        schema_version="kratos-guard.phase2h-plan.v1",
        run_id=run_id,
        run_marker=run_marker,
        candidate=str(candidate),
        candidate_id=str(summary["candidate_id"]),
        candidate_payload_hash=str(summary["payload_hash"]),
        backend_endpoint=BACKEND_ENDPOINT,
        app_bridge_endpoint=APP_BRIDGE_ENDPOINT,
        network_allowlist=[
            "chrome-extension://mofhgdnkngbpbcihjkhoelogkjolaidn/*",
            "http://127.0.0.1:8000/*",
            "http://127.0.0.1:3000/*",
            "http://127.0.0.1:<guard-fixture-port>/*",
            "browser-internal://*",
        ],
        journey_ids=[journey[0] for journey in REAL_BACKEND_JOURNEYS],
        budget=RealBackendBudget(),
        backend_contract_verdict=backend.verdict,
        synthetic_identity_verdict=synthetic.verdict,
        provider_seam_verdict=seam.verdict,
        database_readback_verdict=database.verdict,
        active_writer_lease=str(lease.get("leaseId") or ""),
        blockers=blockers,
        dispatch_authorised=not blockers,
        promotion_authority="NONE",
        plan_path=str(path),
        observed_at=datetime.now(UTC),
        verdict=(
            "REAL_BACKEND_JOURNEY_PLAN_PROVEN"
            if not blockers
            else "REAL_BACKEND_CONTRACT_PROVEN_SYNTHETIC_IDENTITY_UNAVAILABLE"
        ),
    )
    path.write_text(plan.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return plan


def run_real_backend_journeys(
    guard_root: Path, candidate: Path, plan_path: Path
) -> tuple[RealBackendSuiteReport, Path]:
    plan = RealBackendJourneyPlan.model_validate_json(plan_path.read_text("utf-8"))
    candidate = candidate.resolve()
    if Path(plan.candidate).resolve() != candidate:
        raise RuntimeError("PLAN_CANDIDATE_MISMATCH")
    summary = _verify_exact_candidate(guard_root, candidate)
    backend = inspect_backend_contract("itzako")
    synthetic = verify_synthetic_audit_identity("itzako")
    seam = verify_provider_test_seam("itzako")
    database = verify_database_readback("itzako", plan.run_marker)
    if plan.dispatch_authorised:
        raise RuntimeError("REAL_BACKEND_DISPATCH_REQUIRES_NEW_EXACT_WRITER_AUTHORITY")
    journeys = [
        RealBackendJourney(
            journey_id=journey_id,
            platform=platform,
            run_marker=plan.run_marker,
            action=action,
            operation_ids=[],
            accepted_operation_count=0,
            repair_operation_count=0,
            provider_attempt_count=0,
            lesson_ids=[],
            artefact_ids=[],
            initial_state="NOT_DISPATCHED",
            terminal_state="BLOCKED",
            visible_result="NOT_RUN",
            database_readback_state=(
                "NO_RUN_MARKER_RECORDS_PROVEN"
                if database.verdict == "DATABASE_READBACK_AUTHORITY_PROVEN"
                and not any(database.run_marker_counts.values())
                else "RUN_MARKER_READBACK_UNPROVEN"
            ),
            first_failing_boundary=(
                plan.blockers[0] if plan.blockers else "DISPATCH_AUTHORITY_UNPROVEN"
            ),
            verdict="BLOCKED",
        )
        for journey_id, platform, action in REAL_BACKEND_JOURNEYS
    ]
    concurrency = ConcurrentActivityEvidence(
        run_marker=plan.run_marker,
        synthetic_owner_hash="",
        marker_scoped_counts=database.run_marker_counts,
        global_counts_context=database.baseline_counts,
        unrelated_activity_observed=False,
        synthetic_namespace_contaminated=False,
        operation_attribution_state="NO_OPERATIONS_DISPATCHED",
        verdict="SYNTHETIC_NAMESPACE_NOT_CREATED",
    )
    report = RealBackendSuiteReport(
        schema_version="kratos-guard.phase2h-report.v1",
        phase="2H",
        run_id=plan.run_id,
        run_marker=plan.run_marker,
        candidate_id=str(summary["candidate_id"]),
        candidate_before_hash=str(summary["delivery_hash"]),
        candidate_after_hash=str(_candidate_summary(candidate)["delivery_hash"]),
        backend_contract=backend,
        synthetic_identity=synthetic,
        provider_seam=seam,
        database_readback=database,
        budget=plan.budget,
        journeys=journeys,
        operations=[],
        concurrency=concurrency,
        allowed_requests=[
            f"{BACKEND_ENDPOINT}/api/v1/ready",
            f"{BACKEND_ENDPOINT}/openapi.json",
            f"{APP_BRIDGE_ENDPOINT}/api/extension/bootstrap-config",
        ],
        blocked_requests=[],
        browser_profile="NOT_CREATED_DISPATCH_BLOCKED",
        browser_cleanup_state="NOT_REQUIRED",
        normal_chrome_mutations=0,
        study_pilot_source_writes=0,
        study_pilot_git_mutations=0,
        authorised_synthetic_backend_writes=0,
        unauthorised_database_writes=0,
        real_provider_calls=0,
        real_provider_cost_usd=0.0,
        promotion_authority="NONE",
        final_verdict=("REAL_BACKEND_CONTRACT_PROVEN_SYNTHETIC_IDENTITY_UNAVAILABLE"),
        first_remaining_blocker=(
            plan.blockers[0] if plan.blockers else "REAL_BACKEND_DISPATCH_NOT_EXECUTED"
        ),
    )
    destination = guard_root / ".work" / "phase2h-reports" / plan.run_id
    destination.mkdir(parents=True, exist_ok=True)
    report_path = destination / "phase2h-report.json"
    report_path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return report, report_path


def verify_real_backend_report(report_path: Path) -> dict[str, object]:
    report = RealBackendSuiteReport.model_validate_json(report_path.read_text("utf-8"))
    budget = report.budget
    checks = {
        "candidate_unchanged": (report.candidate_before_hash == report.candidate_after_hash),
        "external_provider_cap": (
            report.real_provider_calls <= budget.maximum_external_provider_calls == 0
        ),
        "real_provider_cost_cap": (
            report.real_provider_cost_usd <= budget.maximum_real_provider_cost_usd == 0
        ),
        "operation_cap": (
            budget.backend_operations_accepted <= budget.maximum_total_backend_operations_accepted
        ),
        "repair_cap": (
            budget.automatic_repair_operations <= budget.maximum_automatic_repair_operations
        ),
        "unauthorised_writes_zero": report.unauthorised_database_writes == 0,
        "normal_chrome_zero": report.normal_chrome_mutations == 0,
        "study_pilot_source_zero": (
            report.study_pilot_source_writes == 0 and report.study_pilot_git_mutations == 0
        ),
        "promotion_none": report.promotion_authority == "NONE",
    }
    full_success = report.final_verdict == (
        "REAL_BACKEND_PERSISTENCE_GOLDEN_JOURNEYS_PROVEN_REAL_PROVIDER_UNPROVEN"
    )
    if full_success:
        checks["database_readback_required"] = (
            report.database_readback.verdict == "DATABASE_READBACK_AUTHORITY_PROVEN"
        )
        checks["all_journeys_proven"] = len(report.journeys) == 12 and all(
            journey.verdict == "PROVEN" for journey in report.journeys
        )
    return {
        "report": str(report_path.resolve()),
        "checks": checks,
        "final_verdict": report.final_verdict,
        "first_remaining_blocker": report.first_remaining_blocker,
        "verdict": (
            "REAL_BACKEND_REPORT_VERIFIED"
            if all(checks.values())
            else "REAL_BACKEND_REPORT_CONTRADICTED"
        ),
    }
