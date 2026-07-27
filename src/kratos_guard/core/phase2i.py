"""Phase 2I isolated backend audit authority and runtime controls."""

# ruff: noqa: E501

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import psutil
from cryptography.exceptions import InvalidSignature

from kratos_guard.core.secret_store import inspect_secret, load_secret
from kratos_guard.core.signing import load_trusted_public_key
from kratos_guard.models.phase2i import (
    AuditDatabaseIdentity,
    AuditRoleIdentity,
    AuditScenarioDefinition,
    AuditWriterLease,
    BackendAuditAuthority,
    BackendAuditBuildIdentity,
    BackendAuditRuntimeIdentity,
    SyntheticAuditTokenIdentity,
)

EXPECTED_BASELINE_COMMIT = "de4f09113388aac14b7b0f062878c8fb62c2e67f"
EXPECTED_CANDIDATE_ID = "itzako-extension-1.1.19-language-repair-20260725T115732Z-5feba5dc7f1a"
EXPECTED_DATABASE = "studypilot_kag_audit"
EXPECTED_AUDIT_SCHEMA = "kag_audit"
EXPECTED_MIGRATION = "017"
EXPECTED_SUBJECT = "kag-phase2i"
EXPECTED_TENANT = "kag-audit"
EXPECTED_ISSUER = "kratos-agent-guard-phase2i"
EXPECTED_AUDIENCE = "itzako-kag-audit"
EXPECTED_SCOPE = "audit:golden-journeys"
EXPECTED_RUNTIME_ENDPOINT = "http://127.0.0.1:18000"
SECRET_NAMESPACE = "phase2i-audit-authority"
AUDIT_PYTHON_DEFAULT = Path(r"C:\Python314\python.exe")

SCENARIO_DEFINITIONS = (
    AuditScenarioDefinition(
        name="same_language_success",
        scenario_version="kag-audit-scenarios.v1",
        maximum_provider_attempts=1,
        output_sequence=["english"],
        terminal_state="succeeded",
    ),
    AuditScenarioDefinition(
        name="wrong_then_correct",
        scenario_version="kag-audit-scenarios.v1",
        maximum_provider_attempts=2,
        output_sequence=["german", "english"],
        terminal_state="succeeded_after_repair",
    ),
    AuditScenarioDefinition(
        name="wrong_then_wrong",
        scenario_version="kag-audit-scenarios.v1",
        maximum_provider_attempts=2,
        output_sequence=["german", "german"],
        terminal_state="retryable_language_mismatch",
    ),
    AuditScenarioDefinition(
        name="terminal_timeout",
        scenario_version="kag-audit-scenarios.v1",
        maximum_provider_attempts=1,
        output_sequence=[],
        terminal_state="terminal_timeout",
    ),
    AuditScenarioDefinition(
        name="terminal_failure",
        scenario_version="kag-audit-scenarios.v1",
        maximum_provider_attempts=1,
        output_sequence=[],
        terminal_state="terminal_failure",
    ),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode:
        raise RuntimeError(
            f"GIT_COMMAND_FAILED:{arguments[0]}:{completed.returncode}:{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def inspect_backend_audit_authority(
    repository: Path,
    source_commit: str = EXPECTED_BASELINE_COMMIT,
) -> BackendAuditAuthority:
    """Prove an existing backend audit repository is independent and contained."""

    repository = repository.resolve()
    if source_commit != EXPECTED_BASELINE_COMMIT:
        raise ValueError("EXACT_CANONICAL_SOURCE_COMMIT_REQUIRED")
    root = Path(_git(repository, "rev-parse", "--show-toplevel")).resolve()
    if root != repository:
        raise RuntimeError("BACKEND_AUDIT_REPOSITORY_ROOT_MISMATCH")
    common_raw = _git(repository, "rev-parse", "--git-common-dir")
    common = (repository / common_raw).resolve()
    branch = _git(repository, "branch", "--show-current")
    head = _git(repository, "rev-parse", "HEAD")
    baseline_present = _git(repository, "cat-file", "-t", source_commit) == "commit"
    worktrees = _git(repository, "worktree", "list", "--porcelain").splitlines()
    linked = sum(1 for line in worktrees if line.startswith("worktree ")) != 1
    alternates_path = common / "objects" / "info" / "alternates"
    alternates = (
        [line for line in alternates_path.read_text("utf-8").splitlines() if line]
        if alternates_path.is_file()
        else []
    )
    object_files = [
        path
        for path in (common / "objects").rglob("*")
        if path.is_file() and path.name != "alternates"
    ]
    hardlinks = [str(path) for path in object_files if path.stat().st_nlink > 1]
    push_urls = (
        [
            line
            for line in _git(
                repository, "remote", "get-url", "--all", "--push", "origin"
            ).splitlines()
            if line
        ]
        if _git(repository, "remote")
        else []
    )
    dirty = [
        line[3:]
        for line in _git(
            repository, "status", "--porcelain=v1", "--untracked-files=all"
        ).splitlines()
        if line
    ]
    separate_git = common == repository / ".git" and common.is_dir()
    proven = (
        baseline_present
        and separate_git
        and not linked
        and not alternates
        and not hardlinks
        and not push_urls
        and not dirty
    )
    return BackendAuditAuthority(
        repository_path=str(repository),
        git_common_directory=str(common),
        branch=branch,
        head=head,
        baseline_commit=source_commit,
        baseline_present=baseline_present,
        separate_git_directory=separate_git,
        separate_object_database=separate_git and not alternates and not hardlinks,
        linked_worktree=linked,
        alternates=alternates,
        hardlinked_object_files=hardlinks,
        push_urls=push_urls,
        dirty_paths=dirty,
        normal_runtime_unchanged=True,
        mutation_authority="AUTHORISED_ISOLATED_ONLY",
        verdict=(
            "BACKEND_AUDIT_SOURCE_AUTHORITY_PROVEN"
            if proven
            else "BACKEND_AUDIT_SOURCE_AUTHORITY_UNPROVEN"
        ),
    )


def bundle_backend_audit_lineage(
    guard_root: Path,
    repository: Path,
    output_directory: Path,
) -> dict[str, object]:
    """Create and sign an exact two-branch backend audit lineage bundle."""

    from kratos_guard.core.phase2f import _sign_envelope

    authority = inspect_backend_audit_authority(repository)
    if authority.verdict != "BACKEND_AUDIT_SOURCE_AUTHORITY_PROVEN":
        raise RuntimeError("BACKEND_AUDIT_SOURCE_AUTHORITY_REQUIRED")
    if not authority.branch.startswith("audit/phase2i-synthetic-environment-"):
        raise RuntimeError("PHASE2I_AUDIT_BRANCH_REQUIRED")
    baseline_branch = "baseline/itzako-backend-de4f091"
    if _git(repository, "rev-parse", baseline_branch) != EXPECTED_BASELINE_COMMIT:
        raise RuntimeError("EXACT_BASELINE_BRANCH_REQUIRED")
    destination = output_directory.resolve()
    work_root = (guard_root.resolve() / ".work").resolve()
    if work_root not in destination.parents or destination.exists():
        raise RuntimeError("NEW_GUARD_WORK_OUTPUT_DIRECTORY_REQUIRED")
    destination.mkdir(parents=True)
    bundle = destination / "itzako-backend-audit-phase2i.bundle"
    _git(repository, "bundle", "create", str(bundle), baseline_branch, authority.branch)
    _git(repository, "bundle", "verify", str(bundle))
    heads = _git(repository, "bundle", "list-heads", str(bundle))
    if authority.head not in heads or EXPECTED_BASELINE_COMMIT not in heads:
        raise RuntimeError("BACKEND_AUDIT_BUNDLE_EXACT_TIPS_REQUIRED")
    payload = {
        "schema_version": "kag.backend-audit-lineage.v1",
        "baseline_branch": baseline_branch,
        "baseline_commit": EXPECTED_BASELINE_COMMIT,
        "audit_branch": authority.branch,
        "audit_commit": authority.head,
        "bundle_path": str(bundle),
        "bundle_sha256": _sha256_file(bundle),
        "bundle_verification": "COMPLETE_HISTORY_TWO_EXACT_BRANCH_TIPS",
        "push_authority": "NONE",
    }
    envelope = _sign_envelope(payload, guard_root)
    attestation = destination / "backend-lineage-attestation.json"
    attestation.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        **envelope,
        "attestation_path": str(attestation),
        "attestation_sha256": _sha256_file(attestation),
        "verdict": "BACKEND_AUDIT_LINEAGE_BUNDLE_PROVEN",
    }


def inspect_backend_audit_build(
    guard_root: Path,
    attestation_path: Path,
    lineage_attestation_path: Path,
) -> BackendAuditBuildIdentity:
    """Verify signed build and lineage envelopes against the Guard trust root."""

    attestation_path = attestation_path.resolve()
    lineage_attestation_path = lineage_attestation_path.resolve()
    envelope = json.loads(attestation_path.read_text("utf-8"))
    lineage = json.loads(lineage_attestation_path.read_text("utf-8"))
    key_id = str(envelope["signing_key_id"])
    if lineage.get("signing_key_id") != key_id:
        raise RuntimeError("BACKEND_BUILD_LINEAGE_SIGNER_MISMATCH")
    trust_path = guard_root / "trust" / "keys" / f"{key_id}.pub.json"
    trust, public_key = load_trusted_public_key(trust_path)
    signature_states: list[str] = []
    for candidate in (envelope, lineage):
        payload = _canonical(candidate["payload"])
        canonical_equal = _sha256_bytes(payload) == candidate["canonical_sha256"]
        try:
            public_key.verify(base64.b64decode(candidate["signature"]), payload)
            signature_valid = canonical_equal
        except (InvalidSignature, ValueError):
            signature_valid = False
        signature_states.append("PROVEN" if signature_valid else "UNPROVEN")
    payload = envelope["payload"]
    lineage_payload = lineage["payload"]
    bundle = Path(str(lineage_payload["bundle_path"])).resolve()
    bundle_hash = _sha256_file(bundle)
    bundle_valid = bundle_hash == lineage_payload["bundle_sha256"]
    source_commit = str(payload["source_commit"])
    build_valid = (
        source_commit == str(lineage_payload["audit_commit"])
        and payload["baseline_commit"] == EXPECTED_BASELINE_COMMIT
        and payload["application_migration_head"] == EXPECTED_MIGRATION
        and payload["external_provider_calls"] == 0
        and payload["promotion_authority"] == "NONE"
        and payload["reproducibility"] == "BIT_FOR_BIT_SDIST_AND_WHEEL_PROVEN"
        and bundle_valid
        and all(state == "PROVEN" for state in signature_states)
        and trust.state == "TRUST_ROOT_PROVEN"
    )
    return BackendAuditBuildIdentity(
        build_id=str(payload["backend_audit_build_id"]),
        source_commit=source_commit,
        source_manifest_sha256=str(payload["source_manifest_sha256"]),
        build_input_sha256=str(payload["build_input_sha256"]),
        contract_sha256=str(payload["backend_contract_sha256"]),
        audit_schema_sha256=str(payload["audit_schema_sha256"]),
        attestation_path=str(attestation_path),
        attestation_sha256=_sha256_file(attestation_path),
        signing_key_id=key_id,
        signature_state=("PROVEN" if all(s == "PROVEN" for s in signature_states) else "UNPROVEN"),
        signer_trust_state=trust.state,
        reproducibility=str(payload["reproducibility"]),
        lineage_bundle_path=str(bundle),
        lineage_bundle_sha256=bundle_hash,
        verdict=("BACKEND_AUDIT_BUILD_PROVEN" if build_valid else "BACKEND_AUDIT_BUILD_UNPROVEN"),
    )


def _audit_python() -> Path:
    path = Path(os.environ.get("KAG_AUDIT_PYTHON", str(AUDIT_PYTHON_DEFAULT))).resolve()
    if not path.is_file():
        raise FileNotFoundError("AUDIT_PYTHON_REQUIRED")
    return path


def _run_db_script(script: str, extra_environment: dict[str, str]) -> dict[str, Any]:
    environment = os.environ.copy()
    environment.update(extra_environment)
    completed = subprocess.run(
        [str(_audit_python()), "-c", script],
        capture_output=True,
        text=True,
        check=False,
        timeout=45,
        env=environment,
    )
    for key in extra_environment:
        if "PASSWORD" in key or "TOKEN" in key or "SECRET" in key:
            environment[key] = "<redacted>"
    if completed.returncode:
        raise RuntimeError(
            f"AUDIT_DATABASE_PROBE_FAILED:{completed.returncode}:{completed.stderr.strip()}"
        )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError("AUDIT_DATABASE_PROBE_OBJECT_REQUIRED")
    return payload


_DATABASE_IDENTITY_SCRIPT = r"""
import hashlib, json, os, psycopg2
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_admin",password=os.environ["KAG_DB_PASSWORD"])
try:
  with connection.cursor() as cursor:
    cursor.execute("SELECT current_database(), version_num FROM alembic_version")
    database,migration=cursor.fetchone()
    cursor.execute("SELECT table_name,column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
    public=[list(row) for row in cursor.fetchall()]
    cursor.execute("SELECT table_name,column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema='kag_audit' ORDER BY table_name,ordinal_position")
    audit=[list(row) for row in cursor.fetchall()]
    roles={}
    for role in ("kag_audit_backend","kag_audit_readonly"):
      cursor.execute("SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication FROM pg_roles WHERE rolname=%s",(role,))
      flags=cursor.fetchone()
      cursor.execute("SELECT has_database_privilege(%s,'studypilot_kag_audit','CONNECT'),has_database_privilege(%s,'postgres','CONNECT')",(role,role))
      connects=cursor.fetchone()
      cursor.execute("SELECT coalesce(bool_and(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'SELECT')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'INSERT')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'UPDATE')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'DELETE')),false) FROM pg_tables WHERE schemaname=%s",(role,role,role,role,'public'))
      public_priv=cursor.fetchone()
      cursor.execute("SELECT coalesce(bool_and(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'SELECT')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'INSERT')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'UPDATE')),false),coalesce(bool_or(has_table_privilege(%s,format('%%I.%%I',schemaname,tablename),'DELETE')),false) FROM pg_tables WHERE schemaname=%s",(role,role,role,role,'kag_audit'))
      audit_priv=cursor.fetchone()
      cursor.execute("SELECT coalesce(bool_or(cfg='default_transaction_read_only=on'),false) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole CROSS JOIN LATERAL unnest(s.setconfig) cfg WHERE r.rolname=%s",(role,))
      default_readonly=cursor.fetchone()[0]
      roles[role]={"flags":flags,"connects":connects,"public":public_priv,"audit":audit_priv,"default_readonly":default_readonly}
    cursor.execute("SELECT status,count(*) FROM kag_audit.writer_leases GROUP BY status")
    lease_counts=dict(cursor.fetchall())
  print(json.dumps({"database":database,"migration":migration,"public":public,"audit":audit,"roles":roles,"lease_counts":lease_counts},default=str))
finally:
  connection.close()
"""


def verify_backend_audit_database(
    container_name: str = "kag-phase2i-postgres",
) -> tuple[AuditDatabaseIdentity, list[AuditRoleIdentity]]:
    """Verify database, schemas, and least-privilege role boundaries."""

    completed = subprocess.run(
        ["docker", "inspect", container_name],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    if completed.returncode:
        raise RuntimeError("AUDIT_DATABASE_CONTAINER_UNAVAILABLE")
    container = json.loads(completed.stdout)[0]
    payload = _run_db_script(
        _DATABASE_IDENTITY_SCRIPT,
        {"KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "postgres_admin_password")},
    )
    public = payload["public"]
    audit = payload["audit"]
    audit_tables = sorted({str(row[0]) for row in audit})
    public_hash = _sha256_bytes(json.dumps(public, separators=(",", ":")).encode())
    audit_hash = _sha256_bytes(json.dumps(audit, separators=(",", ":")).encode())
    database_proven = (
        payload["database"] == EXPECTED_DATABASE
        and payload["migration"] == EXPECTED_MIGRATION
        and audit_tables
        == ["scenario_events", "scenario_runs", "synthetic_identities", "writer_leases"]
        and container["State"]["Status"] == "running"
        and container["State"].get("Health", {}).get("Status") == "healthy"
    )
    database = AuditDatabaseIdentity(
        container_id=str(container["Id"]),
        container_state=(
            f"{container['State']['Status']}|"
            f"{container['State'].get('Health', {}).get('Status', 'no-healthcheck')}"
        ),
        endpoint="postgresql://127.0.0.1:15432/studypilot_kag_audit",
        database=str(payload["database"]),
        application_schema="public",
        application_migration_head=str(payload["migration"]),
        application_schema_sha256=public_hash,
        application_table_count=len({str(row[0]) for row in public}),
        audit_schema=EXPECTED_AUDIT_SCHEMA,
        audit_schema_sha256=audit_hash,
        audit_tables=audit_tables,
        external_database_access=False,
        verdict=(
            "AUDIT_DATABASE_ISOLATION_PROVEN"
            if database_proven
            else "AUDIT_DATABASE_ISOLATION_UNPROVEN"
        ),
    )
    roles: list[AuditRoleIdentity] = []
    for name in ("kag_audit_backend", "kag_audit_readonly"):
        raw = payload["roles"][name]
        flags = raw["flags"]
        connects = raw["connects"]
        public_priv = raw["public"]
        audit_priv = raw["audit"]
        readonly = name == "kag_audit_readonly"
        proven = (
            flags == [True, False, False, False, False]
            and connects == [True, False]
            and bool(public_priv[0])
            and bool(audit_priv[0])
            and not bool(public_priv[3])
            and not bool(audit_priv[3])
            and (
                bool(raw["default_readonly"])
                and not any(bool(value) for value in (*public_priv[1:], *audit_priv[1:]))
                if readonly
                else (
                    not bool(raw["default_readonly"])
                    and bool(public_priv[1])
                    and bool(public_priv[2])
                    and bool(audit_priv[1])
                    and bool(audit_priv[2])
                )
            )
        )
        roles.append(
            AuditRoleIdentity(
                role=name,
                login=bool(flags[0]),
                superuser=bool(flags[1]),
                create_database=bool(flags[2]),
                create_role=bool(flags[3]),
                replication=bool(flags[4]),
                audit_database_connect=bool(connects[0]),
                other_database_connect=bool(connects[1]),
                transaction_read_only_default=bool(raw["default_readonly"]),
                application_select=bool(public_priv[0]),
                application_insert=bool(public_priv[1]),
                application_update=bool(public_priv[2]),
                application_delete=bool(public_priv[3]),
                audit_select=bool(audit_priv[0]),
                audit_insert=bool(audit_priv[1]),
                audit_update=bool(audit_priv[2]),
                audit_delete=bool(audit_priv[3]),
                verdict=(
                    "AUDIT_READONLY_ROLE_PROVEN"
                    if proven and readonly
                    else ("AUDIT_BACKEND_ROLE_PROVEN" if proven else "AUDIT_ROLE_BOUNDARY_UNPROVEN")
                ),
            )
        )
    return database, roles


_SYNTHETIC_IDENTITY_SCRIPT = r"""
import json, os, psycopg2
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_admin",password=os.environ["KAG_DB_PASSWORD"])
try:
  with connection.cursor() as cursor:
    cursor.execute("SELECT subject,tenant,audience,scope,classification,database_name,token_fingerprint_sha256,created_at,metadata FROM kag_audit.synthetic_identities ORDER BY created_at")
    rows=cursor.fetchall()
  print(json.dumps({"count":len(rows),"row":rows[0] if len(rows)==1 else None},default=str))
finally:
  connection.close()
"""


def verify_phase2i_synthetic_audit_identity() -> SyntheticAuditTokenIdentity:
    """Verify the one synthetic identity and its DPAPI-held scoped token."""

    payload = _run_db_script(
        _SYNTHETIC_IDENTITY_SCRIPT,
        {"KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "postgres_admin_password")},
    )
    if payload["count"] != 1 or payload["row"] is None:
        raise RuntimeError("EXACTLY_ONE_SYNTHETIC_AUDIT_IDENTITY_REQUIRED")
    row = payload["row"]
    token = load_secret(SECRET_NAMESPACE, "synthetic_audit_token")
    encoded, separator, _signature = token.partition(".")
    if not separator:
        raise RuntimeError("SYNTHETIC_AUDIT_TOKEN_FORMAT_INVALID")
    padding = "=" * (-len(encoded) % 4)
    claims = json.loads(base64.urlsafe_b64decode(encoded + padding))
    fingerprint = inspect_secret(SECRET_NAMESPACE, "synthetic_audit_token").fingerprint_sha256
    metadata = row[8]
    proven = (
        row[0] == claims.get("sub") == EXPECTED_SUBJECT
        and row[1] == claims.get("tenant") == EXPECTED_TENANT
        and row[2] == claims.get("aud") == EXPECTED_AUDIENCE
        and row[3] in claims.get("scope", [])
        and row[3] == EXPECTED_SCOPE
        and row[4] == "SYNTHETIC_AUDIT_IDENTITY"
        and row[5] == EXPECTED_DATABASE
        and row[6] == fingerprint
        and claims.get("iss") == EXPECTED_ISSUER
        and metadata.get("external_integrations") is False
        and metadata.get("normal_browser_session") is False
    )
    return SyntheticAuditTokenIdentity(
        classification="SYNTHETIC_AUDIT_IDENTITY",
        subject="kag-phase2i",
        tenant="kag-audit",
        issuer="kratos-agent-guard-phase2i",
        audience="itzako-kag-audit",
        scope=[str(value) for value in claims.get("scope", [])],
        token_fingerprint_sha256=fingerprint,
        issued_at=datetime.fromtimestamp(int(claims["iat"]), UTC),
        expires_at=datetime.fromtimestamp(int(claims["exp"]), UTC),
        database="studypilot_kag_audit",
        secret_protection="WINDOWS_DPAPI_CURRENT_USER",
        normal_user_association=False,
        email_delivery=False,
        billing=False,
        invitation=False,
        production_membership=False,
        verdict=(
            "SYNTHETIC_AUDIT_IDENTITY_PROVEN" if proven else "SYNTHETIC_AUDIT_IDENTITY_UNPROVEN"
        ),
    )


def verify_audit_provider_scenarios(repository: Path) -> list[AuditScenarioDefinition]:
    """Verify the audit-only provider contains every bounded named scenario."""

    repository = repository.resolve()
    provider_path = repository / "Study_master_backend" / "app" / "audit" / "provider.py"
    authority_path = repository / "Study_master_backend" / "app" / "audit" / "authority.py"
    provider = provider_path.read_text("utf-8")
    authority = authority_path.read_text("utf-8")
    for definition in SCENARIO_DEFINITIONS:
        if definition.name not in authority:
            raise RuntimeError(f"AUDIT_SCENARIO_MISSING:{definition.name}")
    provider_contract = (
        'SCENARIO_VERSION = "kag-audit-scenarios.v1"',
        'scenario == "terminal_timeout"',
        'scenario == "terminal_failure"',
        'scenario == "same_language_success"',
        'scenario == "wrong_then_correct"',
        'language = "german"',
        "_record_attempt()",
        '"external_provider_calls":0',
    )
    missing_provider_contract = [value for value in provider_contract if value not in provider]
    if missing_provider_contract:
        raise RuntimeError("AUDIT_PROVIDER_CONTRACT_MISSING:" + ",".join(missing_provider_contract))
    required_guards = (
        "settings.kag_audit_mode",
        "AUDIT_BEARER_TOKEN_REQUIRED",
        "ACTIVE_AUDIT_WRITER_LEASE_REQUIRED",
        "PHASE2I_RUN_MARKER_REQUIRED",
        "UNSUPPORTED_AUDIT_SCENARIO",
    )
    combined = provider + authority
    missing = [guard for guard in required_guards if guard not in combined]
    if missing:
        raise RuntimeError(f"AUDIT_SCENARIO_GUARDS_MISSING:{','.join(missing)}")
    return list(SCENARIO_DEFINITIONS)


_LEASE_INSPECT_SCRIPT = r"""
import json, os, psycopg2
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_admin",password=os.environ["KAG_DB_PASSWORD"])
try:
  with connection.cursor() as cursor:
    cursor.execute("SELECT lease_id,run_marker,candidate_id,backend_build_id,database_name,synthetic_subject,acquired_at,expires_at,status,released_at,coalesce(terminal_outcome,''),expires_at>now() AND status='ACTIVE' FROM kag_audit.writer_leases ORDER BY acquired_at")
    rows=cursor.fetchall()
  print(json.dumps({"rows":rows},default=str))
finally:
  connection.close()
"""


def _lease_model(row: list[Any]) -> AuditWriterLease:
    valid = bool(row[11])
    return AuditWriterLease(
        lease_id=str(row[0]),
        run_marker=str(row[1]),
        candidate_id=str(row[2]),
        backend_build_id=str(row[3]),
        database="studypilot_kag_audit",
        synthetic_subject="kag-phase2i",
        acquired_at=datetime.fromisoformat(str(row[6])),
        expires_at=datetime.fromisoformat(str(row[7])),
        status=cast(Literal["ACTIVE", "RELEASED", "EXPIRED"], str(row[8])),
        released_at=(datetime.fromisoformat(str(row[9])) if row[9] else None),
        terminal_outcome=str(row[10]),
        valid_at_observation=valid,
        verdict=("AUDIT_WRITER_LEASE_PROVEN" if valid else "AUDIT_WRITER_LEASE_INACTIVE"),
    )


def inspect_audit_writer_leases() -> list[AuditWriterLease]:
    payload = _run_db_script(
        _LEASE_INSPECT_SCRIPT,
        {"KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "postgres_admin_password")},
    )
    return [_lease_model(row) for row in payload["rows"]]


_LEASE_ACQUIRE_SCRIPT = r"""
import json, os, psycopg2, uuid
from datetime import datetime, timezone, timedelta
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_admin",password=os.environ["KAG_DB_PASSWORD"])
lease_id=str(uuid.uuid4())
try:
  with connection:
    with connection.cursor() as cursor:
      cursor.execute("SELECT count(*) FROM kag_audit.writer_leases WHERE status='ACTIVE'")
      if cursor.fetchone()[0] != 0: raise RuntimeError("ACTIVE_AUDIT_WRITER_LEASE_EXISTS")
      cursor.execute("SELECT (SELECT count(*) FROM kag_audit.scenario_runs)+(SELECT count(*) FROM kag_audit.scenario_events)")
      activity=cursor.fetchone()[0]
      expected=int(os.environ["KAG_EXPECTED_ACTIVITY"])
      if activity != expected: raise RuntimeError(f"AUDIT_ACTIVITY_BASELINE_MISMATCH:{activity}:{expected}")
      expires=datetime.now(timezone.utc)+timedelta(seconds=int(os.environ["KAG_LEASE_TTL_SECONDS"]))
      cursor.execute("INSERT INTO kag_audit.writer_leases (lease_id,run_marker,candidate_id,backend_build_id,database_name,synthetic_subject,acquired_at,expires_at,status,metadata) VALUES (%s,%s,%s,%s,'studypilot_kag_audit','kag-phase2i',now(),%s,'ACTIVE',%s::jsonb) RETURNING lease_id,run_marker,candidate_id,backend_build_id,database_name,synthetic_subject,acquired_at,expires_at,status,released_at,coalesce(terminal_outcome,''),true",(lease_id,os.environ["KAG_RUN_MARKER"],os.environ["KAG_CANDIDATE_ID"],os.environ["KAG_BUILD_ID"],expires,json.dumps({"authority":"KratosAgentGuard","scope":"phase2i-golden-journeys"})))
      row=cursor.fetchone()
  print(json.dumps({"row":row},default=str))
finally:
  connection.close()
"""


def acquire_audit_writer_lease(
    candidate_id: str,
    run_marker: str,
    backend_build_id: str,
    *,
    ttl_seconds: int = 1800,
    expected_activity: int = 0,
) -> AuditWriterLease:
    if candidate_id != EXPECTED_CANDIDATE_ID:
        raise ValueError("EXACT_CANDIDATE_ID_REQUIRED")
    if not run_marker.startswith("KAG-2I-"):
        raise ValueError("PHASE2I_RUN_MARKER_REQUIRED")
    if not backend_build_id.startswith("backend-audit-"):
        raise ValueError("BACKEND_AUDIT_BUILD_ID_REQUIRED")
    if not 600 <= ttl_seconds <= 3600:
        raise ValueError("AUDIT_LEASE_TTL_OUT_OF_RANGE")
    payload = _run_db_script(
        _LEASE_ACQUIRE_SCRIPT,
        {
            "KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "postgres_admin_password"),
            "KAG_RUN_MARKER": run_marker,
            "KAG_CANDIDATE_ID": candidate_id,
            "KAG_BUILD_ID": backend_build_id,
            "KAG_LEASE_TTL_SECONDS": str(ttl_seconds),
            "KAG_EXPECTED_ACTIVITY": str(expected_activity),
        },
    )
    return _lease_model(payload["row"])


_LEASE_RELEASE_SCRIPT = r"""
import json, os, psycopg2
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_admin",password=os.environ["KAG_DB_PASSWORD"])
try:
  with connection:
    with connection.cursor() as cursor:
      cursor.execute("UPDATE kag_audit.writer_leases SET status='RELEASED',released_at=now(),terminal_outcome=%s WHERE lease_id=%s AND status='ACTIVE' RETURNING lease_id,run_marker,candidate_id,backend_build_id,database_name,synthetic_subject,acquired_at,expires_at,status,released_at,coalesce(terminal_outcome,''),false",(os.environ["KAG_TERMINAL_OUTCOME"],os.environ["KAG_LEASE_ID"]))
      row=cursor.fetchone()
      if row is None: raise RuntimeError("ACTIVE_AUDIT_WRITER_LEASE_NOT_FOUND")
  print(json.dumps({"row":row},default=str))
finally:
  connection.close()
"""


def release_audit_writer_lease(lease_id: str, terminal_outcome: str) -> AuditWriterLease:
    if not lease_id or not terminal_outcome:
        raise ValueError("LEASE_ID_AND_TERMINAL_OUTCOME_REQUIRED")
    payload = _run_db_script(
        _LEASE_RELEASE_SCRIPT,
        {
            "KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "postgres_admin_password"),
            "KAG_LEASE_ID": lease_id,
            "KAG_TERMINAL_OUTCOME": terminal_outcome,
        },
    )
    return _lease_model(payload["row"])


def _port_listener(port: int) -> psutil.Process | None:
    listeners = {
        connection.pid
        for connection in psutil.net_connections(kind="tcp")
        if connection.status == psutil.CONN_LISTEN
        and connection.laddr
        and connection.laddr.port == port
        and connection.pid
    }
    if not listeners:
        return None
    if len(listeners) != 1:
        raise RuntimeError(f"LISTENER_IDENTITY_AMBIGUOUS:{port}:{sorted(listeners)}")
    return psutil.Process(next(iter(listeners)))


def _fetch_json(url: str, timeout: float = 10) -> dict[str, object]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"AUDIT_RUNTIME_HTTP_READ_FAILED:{url}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("AUDIT_RUNTIME_JSON_OBJECT_REQUIRED")
    return payload


def inspect_backend_audit_runtime(
    build: BackendAuditBuildIdentity,
) -> BackendAuditRuntimeIdentity:
    identity = _fetch_json(f"{EXPECTED_RUNTIME_ENDPOINT}/__kag__/identity")
    process_payload = identity.get("process_identity")
    if not isinstance(process_payload, dict):
        raise RuntimeError("AUDIT_RUNTIME_PROCESS_IDENTITY_REQUIRED")
    process = _port_listener(18000)
    if process is None:
        raise RuntimeError("AUDIT_RUNTIME_LISTENER_REQUIRED")
    pid = int(process_payload.get("pid") or -1)
    command = process.cmdline()
    auto_reload = any("reload" in argument.casefold() for argument in command)
    proven = (
        pid == process.pid
        and identity.get("backend_audit_build_id") == build.build_id
        and identity.get("source_commit") == build.source_commit
        and identity.get("source_manifest_sha256") == build.source_manifest_sha256
        and identity.get("build_input_sha256") == build.build_input_sha256
        and identity.get("contract_sha256") == build.contract_sha256
        and identity.get("database") == EXPECTED_DATABASE
        and identity.get("public_migration_head") == EXPECTED_MIGRATION
        and identity.get("audit_schema_sha256") == build.audit_schema_sha256
        and identity.get("audit_mode") is True
        and identity.get("external_providers_disabled") is True
        and not auto_reload
    )
    return BackendAuditRuntimeIdentity(
        endpoint="http://127.0.0.1:18000",
        process_id=process.pid,
        executable=process.exe(),
        command=command,
        working_directory=process.cwd(),
        backend_build_id=str(identity.get("backend_audit_build_id") or ""),
        source_commit=str(identity.get("source_commit") or ""),
        source_manifest_sha256=str(identity.get("source_manifest_sha256") or ""),
        build_input_sha256=str(identity.get("build_input_sha256") or ""),
        contract_sha256=str(identity.get("contract_sha256") or ""),
        database=cast(Literal["studypilot_kag_audit"], str(identity.get("database") or "")),
        migration_head=cast(Literal["017"], str(identity.get("public_migration_head") or "")),
        audit_schema_sha256=str(identity.get("audit_schema_sha256") or ""),
        audit_mode=identity.get("audit_mode") is True,
        external_providers_disabled=identity.get("external_providers_disabled") is True,
        auto_reload=auto_reload,
        observed_at=datetime.now(UTC),
        verdict=(
            "BACKEND_AUDIT_RUNTIME_PROVEN" if proven else "BACKEND_AUDIT_RUNTIME_IDENTITY_MISMATCH"
        ),
    )


def start_backend_audit_runtime(
    guard_root: Path,
    build: BackendAuditBuildIdentity,
    runtime_directory: Path,
) -> tuple[BackendAuditRuntimeIdentity, Path]:
    """Install the sealed wheel and start one owned audit backend process."""

    if build.verdict != "BACKEND_AUDIT_BUILD_PROVEN":
        raise RuntimeError("PROVEN_BACKEND_AUDIT_BUILD_REQUIRED")
    if _port_listener(18000) is not None:
        raise RuntimeError("AUDIT_BACKEND_PORT_18000_NOT_FREE")
    runtime_directory = runtime_directory.resolve()
    runtime_directory.mkdir(parents=True, exist_ok=False)
    venv = runtime_directory / "venv"
    subprocess.run(
        [str(_audit_python()), "-m", "venv", "--system-site-packages", str(venv)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    runtime_python = venv / "Scripts" / "python.exe"
    attestation = json.loads(Path(build.attestation_path).read_text("utf-8"))
    package_names = [
        str(item["name"])
        for item in attestation["payload"]["package_artifacts"]
        if str(item["name"]).endswith(".whl")
    ]
    if len(package_names) != 1:
        raise RuntimeError("EXACTLY_ONE_BACKEND_WHEEL_REQUIRED")
    wheel = Path(build.attestation_path).parent / package_names[0]
    subprocess.run(
        [str(runtime_python), "-m", "pip", "install", "--no-deps", str(wheel)],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    environment = os.environ.copy()
    backend_password = load_secret(SECRET_NAMESPACE, "backend_password")
    environment.update(
        {
            "DATABASE_URL": (
                "postgresql://kag_audit_backend:"
                f"{urllib.parse.quote(backend_password, safe='')}"
                "@127.0.0.1:15432/studypilot_kag_audit"
            ),
            "OPENAI_API_KEY": "audit-provider-disabled",
            "SECRET_KEY": "kag-phase2i-isolated-runtime-not-for-normal-auth-0123456789",
            "KAG_AUDIT_MODE": "true",
            "KAG_AUDIT_DATABASE_NAME": EXPECTED_DATABASE,
            "KAG_AUDIT_TOKEN_SECRET": load_secret(SECRET_NAMESPACE, "audit_token_secret"),
            "KAG_AUDIT_CANDIDATE_ID": EXPECTED_CANDIDATE_ID,
            "KAG_AUDIT_BUILD_ID": build.build_id,
            "KAG_AUDIT_SOURCE_COMMIT": build.source_commit,
            "KAG_AUDIT_SOURCE_MANIFEST_SHA256": build.source_manifest_sha256,
            "KAG_AUDIT_BUILD_INPUT_SHA256": build.build_input_sha256,
            "KAG_AUDIT_TOKEN_SUBJECT": EXPECTED_SUBJECT,
            "KAG_AUDIT_TOKEN_TENANT": EXPECTED_TENANT,
            "KAG_AUDIT_TOKEN_ISSUER": EXPECTED_ISSUER,
            "KAG_AUDIT_TOKEN_AUDIENCE": EXPECTED_AUDIENCE,
            "KAG_AUDIT_TOKEN_SCOPE": EXPECTED_SCOPE,
            "GENERATION_PROVIDER": "fake",
            "EMBEDDING_PROVIDER": "fake",
            # The canonical generation owner must be reachable so the
            # audit-only deterministic provider can run. Every real-provider
            # switch remains disabled below, and the audit middleware still
            # requires the synthetic capability plus an active writer lease.
            "STUDY_PILOT_PROVIDER_MODE": "fake",
            "PAID_CALL_ROUTER_ALLOW_REAL_PROVIDERS": "false",
            "EXPERT_PACK_ENABLE_REAL_PROVIDERS": "false",
            "STANDARD_AUDIO_TTS_ENABLE_REAL_PROVIDER": "false",
            "DEBUG": "false",
            "CHROMA_PERSIST_DIRECTORY": str(runtime_directory / "chroma"),
            "PYTHONUNBUFFERED": "1",
        }
    )
    stdout_path = runtime_directory / "backend.stdout.log"
    stderr_path = runtime_directory / "backend.stderr.log"
    command = [
        str(runtime_python),
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "18000",
    ]
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=runtime_directory,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            creationflags=creationflags,
        )
    metadata_path = runtime_directory / "runtime-owner.json"
    metadata = {
        "schema_version": "kratos-guard.phase2i-runtime-owner.v1",
        "pid": process.pid,
        "command": command,
        "working_directory": str(runtime_directory),
        "build_id": build.build_id,
        "source_commit": build.source_commit,
        "endpoint": EXPECTED_RUNTIME_ENDPOINT,
        "canonical_runtime_authority": "NONE",
        "created_at": datetime.now(UTC).isoformat(),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", "utf-8")
    deadline = time.monotonic() + 45
    last_error = ""
    while time.monotonic() < deadline:
        if process.poll() is not None:
            last_error = f"PROCESS_EXITED:{process.returncode}"
            break
        try:
            runtime = inspect_backend_audit_runtime(build)
            if runtime.verdict == "BACKEND_AUDIT_RUNTIME_PROVEN":
                return runtime, metadata_path
            last_error = runtime.verdict
        except RuntimeError as exc:
            last_error = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f"AUDIT_RUNTIME_START_FAILED:{last_error}")


def stop_backend_audit_runtime(owner_path: Path) -> dict[str, object]:
    """Stop only the exact process recorded in a Guard runtime-owner file."""

    payload = json.loads(owner_path.read_text("utf-8"))
    if payload.get("schema_version") != "kratos-guard.phase2i-runtime-owner.v1":
        raise RuntimeError("AUDIT_RUNTIME_OWNER_SCHEMA_MISMATCH")
    pid = int(payload["pid"])
    if pid == 47612:
        raise RuntimeError("CANONICAL_BACKEND_PROCESS_PROTECTED")
    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return {"pid": pid, "state": "ALREADY_STOPPED", "survivors": []}
    if process.cwd() != str(Path(payload["working_directory"]).resolve()):
        raise RuntimeError("AUDIT_RUNTIME_OWNER_CWD_MISMATCH")
    if process.cmdline() != [str(value) for value in payload["command"]]:
        raise RuntimeError("AUDIT_RUNTIME_OWNER_COMMAND_MISMATCH")
    runtime_directory = str(Path(payload["working_directory"]).resolve())
    descendants = process.children(recursive=True)
    runtime_descendants: list[psutil.Process] = []
    expected_command = [str(value) for value in payload["command"]]
    for descendant in descendants:
        try:
            if descendant.pid == 47612:
                raise RuntimeError("CANONICAL_BACKEND_PROCESS_PROTECTED")
            if descendant.cwd() == runtime_directory and descendant.cmdline() == expected_command:
                runtime_descendants.append(descendant)
            elif descendant.name().casefold() != "conhost.exe":
                raise RuntimeError("AUDIT_RUNTIME_DESCENDANT_OWNERSHIP_MISMATCH")
        except psutil.NoSuchProcess:
            continue
    # A Windows venv launcher may delegate to the base interpreter. Snapshot
    # the exact owned tree first and terminate child-first so the listener can
    # never be orphaned when its launcher exits.
    for owned in [*reversed(runtime_descendants), process]:
        try:
            owned.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs([*runtime_descendants, process], timeout=15)
    if alive:
        raise RuntimeError(
            "AUDIT_RUNTIME_GRACEFUL_STOP_TIMEOUT:" + ",".join(str(item.pid) for item in alive)
        )
    listener = _port_listener(18000)
    stop_deadline = time.monotonic() + 15
    while listener is not None and time.monotonic() < stop_deadline:
        time.sleep(0.1)
        listener = _port_listener(18000)
    if listener is not None:
        raise RuntimeError(f"AUDIT_RUNTIME_SURVIVOR:{listener.pid}")
    return {
        "pid": pid,
        "owned_process_ids": sorted([pid, *(item.pid for item in runtime_descendants)]),
        "state": "STOPPED",
        "survivors": [],
    }
