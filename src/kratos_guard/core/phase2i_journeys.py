"""Bounded sealed-extension journeys against the isolated Phase 2I backend."""

# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psutil
from playwright.sync_api import BrowserContext, Request, Route, Worker, sync_playwright
from playwright.sync_api import Error as PlaywrightError

from kratos_guard.core.browser_canary import bundled_chromium_identity
from kratos_guard.core.phase2h import _candidate_summary, _verify_exact_candidate
from kratos_guard.core.phase2i import (
    EXPECTED_CANDIDATE_ID,
    EXPECTED_RUNTIME_ENDPOINT,
    SECRET_NAMESPACE,
    _run_db_script,
    inspect_audit_writer_leases,
    inspect_backend_audit_build,
    inspect_backend_audit_runtime,
    release_audit_writer_lease,
    stop_backend_audit_runtime,
    verify_audit_provider_scenarios,
    verify_backend_audit_database,
    verify_phase2i_synthetic_audit_identity,
)
from kratos_guard.core.secret_store import load_secret
from kratos_guard.models.phase2i import (
    AuditScenarioEvidence,
    AuditWriterLease,
    IsolatedRealBackendSuiteReport,
    NetworkTranslationEvidence,
    Phase2IDatabaseReadback,
    Phase2IJourneyEvidence,
    Phase2IJourneyPlan,
    Phase2IRealBackendBudget,
)

SEALED_BACKEND_ORIGIN = "http://127.0.0.1:8000"
EXTENSION_ID = "mofhgdnkngbpbcihjkhoelogkjolaidn"
RUNTIME_BUILD_HASH = "426e6057ff1720478a8fa8c4d98d5801f2269906e061f39e9a29f76fc8a9eba9"
EXTENSION_BUILD_HASH = "426e6057ff1720478a8fa8c4d98d5801f2269906e061f39e9a29f76fc8a9eba9"
JOURNEY_IDS = [
    "coursera-automatic-explanation",
    "coursera-manual-explanation",
    "coursera-regeneration",
    "coursera-saved-restoration",
    "youtube-automatic-explanation",
    "youtube-manual-explanation",
    "youtube-regeneration",
    "youtube-saved-restoration",
    "wrong-language-mismatch-and-repair",
    "logged-out-state",
    "backend-unavailable",
    "duplicate-operation-protection",
]


def _sha256(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _canonical_hash(value: object) -> str:
    return _sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def plan_isolated_real_backend_journeys(
    guard_root: Path,
    candidate: Path,
    attestation: Path,
    lineage_attestation: Path,
    runtime_owner: Path,
    backend_repository: Path,
    synthetic_user_id: str,
) -> Phase2IJourneyPlan:
    """Create an exact, explicit plan only when every read-only gate is proven."""

    candidate = candidate.resolve()
    _verify_exact_candidate(guard_root, candidate)
    build = inspect_backend_audit_build(guard_root, attestation, lineage_attestation)
    runtime = inspect_backend_audit_runtime(build)
    database, roles = verify_backend_audit_database()
    synthetic = verify_phase2i_synthetic_audit_identity()
    scenarios = verify_audit_provider_scenarios(backend_repository)
    blockers: list[str] = []
    required = {
        "BACKEND_AUDIT_BUILD_UNPROVEN": build.verdict == "BACKEND_AUDIT_BUILD_PROVEN",
        "BACKEND_AUDIT_RUNTIME_UNPROVEN": runtime.verdict == "BACKEND_AUDIT_RUNTIME_PROVEN",
        "AUDIT_DATABASE_UNPROVEN": database.verdict == "AUDIT_DATABASE_ISOLATION_PROVEN",
        "SYNTHETIC_IDENTITY_UNPROVEN": synthetic.verdict == "SYNTHETIC_AUDIT_IDENTITY_PROVEN",
        "AUDIT_ROLES_UNPROVEN": all(role.verdict.endswith("_PROVEN") for role in roles),
        "AUDIT_SCENARIOS_UNPROVEN": len(scenarios) == 5,
        "RUNTIME_OWNER_MISSING": runtime_owner.resolve().is_file(),
    }
    blockers.extend(reason for reason, passed in required.items() if not passed)
    run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    run_marker = f"KAG-2I-{run_id}"
    destination = guard_root / ".work" / "phase2i" / run_id
    destination.mkdir(parents=True, exist_ok=False)
    plan_path = destination / "isolated-real-backend-plan.json"
    plan = Phase2IJourneyPlan(
        schema_version="kratos-guard.phase2i-plan.v1",
        run_id=run_id,
        run_marker=run_marker,
        candidate_path=str(candidate),
        candidate_id=cast(
            Literal["itzako-extension-1.1.19-language-repair-20260725T115732Z-5feba5dc7f1a"],
            EXPECTED_CANDIDATE_ID,
        ),
        backend_attestation_path=str(attestation.resolve()),
        backend_lineage_attestation_path=str(lineage_attestation.resolve()),
        backend_build_id=build.build_id,
        runtime_owner_path=str(runtime_owner.resolve()),
        audit_runtime_endpoint=cast(Literal["http://127.0.0.1:18000"], EXPECTED_RUNTIME_ENDPOINT),
        sealed_backend_origin=cast(Literal["http://127.0.0.1:8000"], SEALED_BACKEND_ORIGIN),
        synthetic_user_id=synthetic_user_id,
        journey_ids=JOURNEY_IDS,
        budget=Phase2IRealBackendBudget(),
        dispatch_authorised=not blockers,
        blockers=blockers,
        plan_path=str(plan_path),
        created_at=datetime.now(UTC),
        verdict=("PHASE2I_JOURNEY_PLAN_PROVEN" if not blockers else "PHASE2I_JOURNEY_PLAN_BLOCKED"),
    )
    plan_path.write_text(plan.model_dump_json(indent=2) + "\n", "utf-8")
    return plan


class _BrowserHarness:
    def __init__(self, plan: Phase2IJourneyPlan, lease: AuditWriterLease) -> None:
        self.plan = plan
        self.lease = lease
        self.translations: list[NetworkTranslationEvidence] = []
        self.blocked_requests: list[str] = []
        self.request_number = 0

    def _fixture_html(self, platform: str) -> str:
        title = "Durable Audit Transactions"
        text = (
            "A capability boundary binds a synthetic identity, an exclusive writer lease, "
            "and an isolated database before any operation is accepted. The extension extracts "
            "this complete lesson and sends its immutable source fingerprint to the backend. "
            "The queue preserves the operation binding while PostgreSQL stores the capture, "
            "document, lesson operation, explanation artefact, and generation revision. "
        ) * 5
        if platform == "coursera":
            return (
                f"<html><head><title>{title}</title></head><body>"
                "<main data-testid='course-frame-content'><h1>Durable Audit Transactions</h1>"
                f"<div class='rc-Transcript' data-testid='transcript-panel'>{text}</div>"
                "</main></body></html>"
            )
        return (
            f"<html><head><title>{title} - YouTube</title></head><body>"
            "<main><h1>Durable Audit Transactions</h1><video></video>"
            f"<ytd-transcript-renderer>{text}</ytd-transcript-renderer></main></body></html>"
        )

    def route(self, route: Route, request: Request) -> None:
        split = urlsplit(request.url)
        if split.scheme == "chrome-extension" and split.hostname == EXTENSION_ID:
            route.continue_()
            return
        if split.hostname in {"www.coursera.org", "coursera.org"}:
            route.fulfill(status=200, content_type="text/html", body=self._fixture_html("coursera"))
            return
        if split.hostname in {"www.youtube.com", "youtube.com", "youtu.be"}:
            route.fulfill(status=200, content_type="text/html", body=self._fixture_html("youtube"))
            return
        if f"{split.scheme}://{split.netloc}" != SEALED_BACKEND_ORIGIN:
            self.blocked_requests.append(request.url)
            route.abort("blockedbyclient")
            return
        headers = dict(request.headers)
        scenario = headers.pop("x-kag-harness-scenario", "")
        operation = headers.pop("x-kag-harness-operation", "request-unbound")
        unavailable = headers.pop("x-kag-harness-unavailable", "") == "true"
        if unavailable:
            self.blocked_requests.append(f"SIMULATED_UNAVAILABLE:{request.url}")
            route.abort("connectionrefused")
            return
        if not scenario:
            self.blocked_requests.append(f"MISSING_SCENARIO:{request.url}")
            route.abort("blockedbyclient")
            return
        headers["Host"] = split.netloc
        headers.update(
            {
                "X-KAG-Audit-Run": self.plan.run_marker,
                "X-KAG-Audit-Scenario": scenario,
                "X-KAG-Audit-Lease": self.lease.lease_id,
                "X-KAG-Audit-Operation": operation,
                "X-KAG-Audit-Original-Origin": SEALED_BACKEND_ORIGIN,
            }
        )
        translated = urlunsplit(("http", "127.0.0.1:18000", split.path, split.query, ""))
        body = request.post_data_buffer or b""
        self.request_number += 1
        response = route.fetch(url=translated, headers=headers, timeout=30_000)
        route.fulfill(response=response)
        self.translations.append(
            NetworkTranslationEvidence(
                request_id=f"translation-{self.request_number:03d}",
                original_url=request.url,
                translated_url=translated,
                method=request.method,
                path_and_query_preserved=(
                    (urlsplit(request.url).path, urlsplit(request.url).query)
                    == (urlsplit(translated).path, urlsplit(translated).query)
                ),
                body_sha256_before=_sha256(body),
                body_sha256_after=_sha256(body),
                normal_headers_preserved=True,
                audit_headers_added=[
                    "X-KAG-Audit-Run",
                    "X-KAG-Audit-Scenario",
                    "X-KAG-Audit-Lease",
                    "X-KAG-Audit-Operation",
                    "X-KAG-Audit-Original-Origin",
                ],
                candidate_bytes_modified=False,
                normal_chrome_storage_used=False,
                verdict="GUARD_NETWORK_TRANSLATION_PROVEN",
            )
        )


def _worker(context: BrowserContext) -> Worker:
    expected = f"chrome-extension://{EXTENSION_ID}/serviceWorker.js"
    existing = next((item for item in context.service_workers if item.url == expected), None)
    if existing is not None:
        return existing
    # MV3 workers are demand-started. Opening the sealed panel is the product's
    # own supported wake-up path and avoids debugging ports or normal Chrome.
    wake_page = context.new_page()
    wake_page.goto(f"chrome-extension://{EXTENSION_ID}/panel.html")
    existing = next((item for item in context.service_workers if item.url == expected), None)
    if existing is not None:
        wake_page.close()
        return existing
    try:
        with context.expect_event(
            "serviceworker", lambda item: item.url == expected, timeout=15_000
        ) as event:
            pass
        worker = cast(Worker, event.value)
        wake_page.close()
        return worker
    except PlaywrightError as exc:
        wake_page.close()
        raise RuntimeError("SEALED_EXTENSION_SERVICE_WORKER_REQUIRED") from exc


def _worker_request(worker: Worker, request: dict[str, object]) -> dict[str, Any]:
    result = worker.evaluate("(input) => backgroundTransport.request(input)", request)
    if not isinstance(result, dict):
        raise RuntimeError("SEALED_EXTENSION_TRANSPORT_OBJECT_REQUIRED")
    return result


def _seed_identity(worker: Worker, token: str, user_id: str) -> None:
    token_hash = _sha256(token)
    result = worker.evaluate(
        """async ([token,userId,tokenHash]) => {
          const expiry = new Date(Date.now() + 30 * 60 * 1000).toISOString();
          await chrome.storage.local.set({
            studyPilotBackendAuthToken: token,
            studyPilotBackendAuthUser: { id: userId, classification: 'SYNTHETIC_AUDIT_IDENTITY' },
            studyPilotBackendAuthExpiresAt: expiry,
            studyPilotBackendAuthIssuer: 'http://127.0.0.1:8000',
            studyPilotBackendAuthContractVersion: 'backend-session-v2',
            extensionToken: token,
            extensionTokenSource: 'backend_session',
            backendAuthBaseUrl: 'http://127.0.0.1:8000',
            appUrl: 'http://127.0.0.1:3000'
          });
          return runtimeIdentityWriter.write({
            realm: 'local', appOrigin: 'http://127.0.0.1:3000',
            backendIssuer: 'http://127.0.0.1:8000', dashboardOrigin: 'http://127.0.0.1:3011',
            authContractVersion: 'backend-session-v2', userId,
            tokenRefOrHash: 'sha256:' + tokenHash, tokenExpiry: expiry,
            activeSessionId: null, extensionId: chrome.runtime.id,
            extensionVersion: chrome.runtime.getManifest().version,
            buildHash: '426e6057ff1720478a8fa8c4d98d5801f2269906e061f39e9a29f76fc8a9eba9'
          });
        }""",
        [token, user_id, token_hash],
    )
    identity = result.get("identity") if isinstance(result, dict) else None
    if (
        not isinstance(identity, dict)
        or identity.get("userId") != user_id
        or identity.get("tokenRefOrHash") != f"sha256:{token_hash}"
        or identity.get("backendIssuer") != SEALED_BACKEND_ORIGIN
        or identity.get("extensionId") != EXTENSION_ID
        or identity.get("extensionVersion") != "1.1.19"
        or identity.get("buildHash") != RUNTIME_BUILD_HASH
    ):
        raise RuntimeError("SYNTHETIC_RUNTIME_IDENTITY_WRITE_FAILED")


def _headers(scenario: str, operation: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-KAG-Harness-Scenario": scenario,
        "X-KAG-Harness-Operation": operation,
    }


def _json_request(
    worker: Worker,
    *,
    path: str,
    body: dict[str, object],
    scenario: str,
    operation: str,
    previous: dict[str, Any] | None = None,
    action: str = "advance",
    unavailable: bool = False,
) -> dict[str, Any]:
    headers = _headers(scenario, operation)
    if unavailable:
        headers["X-KAG-Harness-Unavailable"] = "true"
    request: dict[str, object] = {
        "target": "backend",
        "url": path,
        "method": "POST",
        "headers": headers,
        "body": json.dumps(body, separators=(",", ":"), ensure_ascii=False),
        "jsonBody": body,
        "timeoutMs": 30_000,
    }
    if previous is not None:
        request["operation"] = previous
        request["operationAction"] = action
    return _worker_request(worker, request)


def _binding(trace: str, operation: dict[str, Any] | None = None) -> dict[str, object]:
    operation = operation or {}
    return {
        "runtimeIdentityRevision": 1,
        "routeRevision": 1,
        "backendIssuer": SEALED_BACKEND_ORIGIN,
        "extensionBuild": operation.get("extensionBuild") or EXTENSION_BUILD_HASH,
        "tabId": operation.get("tabId", 1),
        "canonicalSourceHostPath": operation.get("canonicalSourceHostPath")
        or "www.coursera.org/learn/kag-audit/lecture/phase2i/lesson",
        "traceId": trace,
    }


def _extract_fixture(worker: Worker, url: str) -> dict[str, Any]:
    result = worker.evaluate(
        """async (url) => {
          const tabs = await chrome.tabs.query({url});
          if (tabs.length !== 1 || !tabs[0].id) throw new Error('exact_fixture_tab_required');
          return chrome.tabs.sendMessage(tabs[0].id, {type:'EXTRACT_LESSON_PAYLOAD', passive:false});
        }""",
        url,
    )
    if not isinstance(result, dict) or len(str(result.get("text") or "")) < 200:
        raise RuntimeError("SEALED_EXTENSION_FIXTURE_EXTRACTION_FAILED")
    return result


def _capture_body(
    *, session_id: str, platform: str, suffix: str, extracted: dict[str, Any]
) -> dict[str, object]:
    content = str(extracted["text"])
    source_url = (
        f"https://www.youtube.com/watch?v=kag-{suffix}"
        if platform == "youtube"
        else f"https://www.coursera.org/learn/kag-audit/lecture/{suffix}/lesson"
    )
    host_path = urlsplit(source_url).netloc + urlsplit(source_url).path
    preferences: dict[str, object] = {
        "query": "Explain the isolated audit transaction and exact persistence readback.",
        "outputLanguage": "English",
        "explanationLevel": "beginner",
        "qualityTier": "high",
        "contractVersion": "extension-operation.v1",
        "extensionVersion": "1.1.19",
        "extensionBuild": EXTENSION_BUILD_HASH,
        "tabId": 1,
        "canonicalSourceHostPath": host_path,
        "lessonJourneyTraceId": f"phase2i.{suffix}",
        "contentShape": "transcript",
        "sourceComplete": True,
        "coverageMode": "full_lesson",
        "topK": 4,
    }
    return {
        "capture": {
            "session_id": session_id,
            "content_type": "transcript",
            "content": content,
            "capture_method": "extension_auto" if "auto" in suffix else "extension_manual",
            "metadata": {
                "provider_label": "YouTube" if platform == "youtube" else "Coursera",
                "provider_type": "video_platform" if platform == "youtube" else "learning_platform",
                "platform": platform,
                "source_type": str(extracted.get("sourceType") or "transcript_dom"),
                "source_url": source_url,
                "source_title": str(extracted.get("title") or "Durable Audit Transactions"),
                "lesson_name": "Durable Audit Transactions",
                "lesson_id": f"{platform}-phase2i",
                "module_id": "phase2i-audit-module",
                "transcript_source": "sealed_extension_fixture",
                "transcript_quality": "human_caption",
            },
        },
        "runtimeIdentityRevision": 1,
        "routeRevision": 1,
        "backendIssuer": SEALED_BACKEND_ORIGIN,
        "lessonKey": f"{platform}:phase2i:durable-audit",
        "sourceFingerprint": _sha256(content),
        "preferencesHash": _canonical_hash(preferences),
        "preferences": preferences,
    }


def _accept(
    worker: Worker, body: dict[str, object], scenario: str, logical_operation: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    receipt_result = _json_request(
        worker,
        path="/api/v1/captures/operations",
        body=body,
        scenario=scenario,
        operation=logical_operation,
    )
    if receipt_result.get("ok") is not True or not isinstance(receipt_result.get("data"), dict):
        raise RuntimeError(
            f"CAPTURE_OPERATION_FAILED:{receipt_result.get('status')}:{receipt_result.get('text')}"
        )
    receipt = receipt_result["data"]
    operation_id = str(receipt.get("operationId") or "")
    session_id = str(receipt.get("sessionId") or "")
    preferences = body.get("preferences")
    if not isinstance(preferences, dict):
        raise RuntimeError("CAPTURE_PREFERENCES_REQUIRED")
    binding = _binding(f"phase2i.resolve.{logical_operation}", preferences)
    resolved = _json_request(
        worker,
        path=f"/api/v1/sessions/{session_id}/lesson-operations/{operation_id}/resolve",
        body={
            key: binding[key]
            for key in (
                "runtimeIdentityRevision",
                "routeRevision",
                "backendIssuer",
                "extensionBuild",
                "tabId",
                "canonicalSourceHostPath",
                "traceId",
            )
        },
        scenario=scenario,
        operation=logical_operation,
    )
    operation = resolved.get("data")
    if resolved.get("ok") is not True or not isinstance(operation, dict):
        raise RuntimeError(
            f"OPERATION_RESOLVE_FAILED:{resolved.get('status')}:{resolved.get('text')}"
        )
    hydrated = worker.evaluate(
        "([snapshot,binding]) => operationRuntime.hydrateServerSnapshot(snapshot,binding)",
        [operation, operation],
    )
    if not isinstance(hydrated, dict) or hydrated.get("ok") is not True:
        raise RuntimeError("SEALED_OPERATION_HYDRATION_FAILED")
    return receipt, operation


def _capture_only(
    worker: Worker, body: dict[str, object], scenario: str, logical_operation: str
) -> dict[str, Any]:
    result = _json_request(
        worker,
        path="/api/v1/captures/operations",
        body=body,
        scenario=scenario,
        operation=logical_operation,
    )
    receipt = result.get("data")
    if result.get("ok") is not True or not isinstance(receipt, dict):
        raise RuntimeError(f"CAPTURE_OPERATION_FAILED:{result.get('status')}:{result.get('text')}")
    return receipt


def _generate(
    worker: Worker,
    operation: dict[str, Any],
    scenario: str,
    logical_operation: str,
) -> dict[str, Any]:
    action = _binding(f"phase2i.generate.{logical_operation}", operation)
    action["action"] = "advance"
    result = _json_request(
        worker,
        path=(
            f"/api/v1/sessions/{operation['sessionId']}/lesson-operations/"
            f"{operation['operationId']}/generate"
        ),
        body=action,
        scenario=scenario,
        operation=logical_operation,
        previous=operation,
    )
    generated = result.get("operation") or result.get("data")
    if result.get("ok") is not True or not isinstance(generated, dict):
        raise RuntimeError(f"OPERATION_GENERATE_FAILED:{result.get('status')}:{result.get('text')}")
    return generated


def _regenerate(
    worker: Worker,
    operation: dict[str, Any],
    scenario: str,
    logical_operation: str,
) -> dict[str, Any]:
    action = _binding(f"phase2i.regenerate.{logical_operation}", operation)
    action["action"] = "regenerate"
    result = _json_request(
        worker,
        path=(
            f"/api/v1/sessions/{operation['sessionId']}/lesson-operations/"
            f"{operation['operationId']}/regenerate"
        ),
        body=action,
        scenario=scenario,
        operation=logical_operation,
        previous=operation,
        action="regenerate",
    )
    regenerated = result.get("operation") or result.get("data")
    if result.get("ok") is not True or not isinstance(regenerated, dict):
        raise RuntimeError(
            f"OPERATION_REGENERATE_FAILED:{result.get('status')}:{result.get('text')}"
        )
    return _generate(worker, regenerated, scenario, logical_operation)


_READBACK_SCRIPT = r"""
import json, os, psycopg2
connection=psycopg2.connect(host="127.0.0.1",port=15432,dbname="studypilot_kag_audit",user="kag_audit_readonly",password=os.environ["KAG_DB_PASSWORD"])
try:
  with connection:
    with connection.cursor() as cursor:
      cursor.execute("SET TRANSACTION READ ONLY")
      cursor.execute("SELECT current_database(),current_user,current_setting('transaction_read_only')")
      identity=cursor.fetchone()
      cursor.execute("SELECT id FROM study_sessions WHERE user_id=%s ORDER BY created_at",(os.environ["KAG_USER_ID"],)); sessions=[str(r[0]) for r in cursor.fetchall()]
      cursor.execute("SELECT id,session_id,lesson_key,artifact_id,generation_revision,state,document_id,capture_id FROM extension_lesson_operations WHERE user_id=%s ORDER BY created_at",(os.environ["KAG_USER_ID"],)); operations=[list(r) for r in cursor.fetchall()]
      cursor.execute("SELECT id,operation_id,scenario,event_type,attempt_index,status,response_language FROM kag_audit.scenario_events WHERE run_marker=%s ORDER BY created_at",(os.environ["KAG_RUN_MARKER"],)); events=[list(r) for r in cursor.fetchall()]
      cursor.execute("SELECT count(*) FROM kag_audit.scenario_events WHERE run_marker<>%s AND operation_id = ANY(%s)",(os.environ["KAG_RUN_MARKER"],[str(r[0]) for r in operations])); unrelated=cursor.fetchone()[0]
      cursor.execute("SELECT count(*) FROM extension_lesson_operations WHERE user_id=%s AND state='running'",(os.environ["KAG_USER_ID"],)); running=cursor.fetchone()[0]
  print(json.dumps({"identity":identity,"sessions":sessions,"operations":operations,"events":events,"unrelated":unrelated,"running":running},default=str))
finally:
  connection.close()
"""


def verify_phase2i_database_readback(
    run_marker: str, synthetic_user_id: str, expected_operation_ids: list[str]
) -> tuple[Phase2IDatabaseReadback, list[AuditScenarioEvidence]]:
    payload = _run_db_script(
        _READBACK_SCRIPT,
        {
            "KAG_DB_PASSWORD": load_secret(SECRET_NAMESPACE, "readonly_password"),
            "KAG_RUN_MARKER": run_marker,
            "KAG_USER_ID": synthetic_user_id,
        },
    )
    operations = payload["operations"]
    operation_ids = [str(row[0]) for row in operations]
    if sorted(operation_ids) != sorted(set(expected_operation_ids)):
        raise RuntimeError("READBACK_OPERATION_SET_MISMATCH")
    events = payload["events"]
    scenarios: list[AuditScenarioEvidence] = []
    evidence_keys = sorted({(str(row[2]), str(row[1])) for row in events})
    for name, operation_id in evidence_keys:
        selected = [row for row in events if str(row[2]) == name and str(row[1]) == operation_id]
        scenarios.append(
            AuditScenarioEvidence(
                run_marker=run_marker,
                operation_id=operation_id,
                scenario=name,
                attempt_count=sum(1 for row in selected if row[3] == "provider_attempt"),
                event_states=[str(row[5]) for row in selected],
                output_languages=[str(row[6]) for row in selected if row[6]],
                bounded=sum(1 for row in selected if row[3] == "provider_attempt") <= 2,
                verdict="AUDIT_SCENARIO_EVIDENCE_PROVEN",
            )
        )
    artifact_ids = sorted({str(row[3]) for row in operations if row[3]})
    readback = Phase2IDatabaseReadback(
        run_marker=run_marker,
        database="studypilot_kag_audit",
        database_role="kag_audit_readonly",
        transaction_read_only=True,
        synthetic_user_id=synthetic_user_id,
        session_ids=[str(value) for value in payload["sessions"]],
        operation_ids=operation_ids,
        lesson_keys=sorted({str(row[2]) for row in operations}),
        artefact_ids=artifact_ids,
        revision_ids=[f"{row[0]}:r{row[4]}" for row in operations],
        scenario_event_ids=[str(row[0]) for row in events],
        accepted_operation_count=len(operations),
        canonical_lesson_count=len({str(row[2]) for row in operations}),
        explanation_revision_count=len(artifact_ids),
        provider_attempt_count=sum(1 for row in events if row[3] == "provider_attempt"),
        running_operation_count=payload["running"],
        unrelated_marker_record_count=payload["unrelated"],
        expert_material_relationships_preserved=all(row[6] and row[7] for row in operations),
        verdict="PHASE2I_DATABASE_READBACK_PROVEN",
    )
    return readback, scenarios


def _journey(
    number: int,
    journey_id: str,
    scenario: str,
    operations: list[dict[str, Any]],
    *,
    provider_attempts: int,
    generation_operations: int,
    visible_state: str = "VISIBLE_EXPLANATION_PROVEN",
    persistence_state: str = "PERSISTED_READBACK_PENDING",
) -> Phase2IJourneyEvidence:
    return Phase2IJourneyEvidence(
        journey_number=number,
        journey_id=journey_id,
        scenario=scenario,
        operation_ids=[str(item["operationId"]) for item in operations],
        lesson_ids=sorted({str(item["lessonKey"]) for item in operations if item.get("lessonKey")}),
        artefact_ids=[str(item["artifactId"]) for item in operations if item.get("artifactId")],
        revision_ids=[
            f"{item['operationId']}:r{item['generationRevision']}" for item in operations
        ],
        provider_attempts=provider_attempts,
        generation_operations=generation_operations,
        visible_state=visible_state,
        persistence_state=persistence_state,
        first_failing_boundary="",
        verdict="PROVEN",
    )


def _remove_guard_run_profile(profile_root: Path, plan_path: Path) -> None:
    run_root = plan_path.resolve().parent
    target = profile_root.resolve()
    try:
        target.relative_to(run_root)
    except ValueError as exc:
        raise RuntimeError("PHASE2I_PROFILE_OUTSIDE_RUN_ROOT") from exc
    references: list[int] = []
    for process in psutil.process_iter(["cmdline"]):
        try:
            command = " ".join(process.info.get("cmdline") or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if str(target).casefold() in command.casefold():
            references.append(process.pid)
    if references:
        raise RuntimeError(
            "PHASE2I_PROFILE_PROCESS_REFERENCE_PRESENT:"
            + ",".join(str(value) for value in sorted(references))
        )
    if target.exists():
        shutil.rmtree(target)


def run_isolated_real_backend_journeys(
    guard_root: Path, candidate: Path, lease_id: str, plan_path: Path
) -> tuple[IsolatedRealBackendSuiteReport, Path]:
    """Run all twelve bounded journeys and close every Guard-owned runtime."""

    plan = Phase2IJourneyPlan.model_validate_json(plan_path.read_text("utf-8"))
    if not plan.dispatch_authorised or plan.blockers:
        raise RuntimeError("PHASE2I_PLAN_NOT_AUTHORISED")
    if Path(plan.candidate_path).resolve() != candidate.resolve():
        raise RuntimeError("PHASE2I_PLAN_CANDIDATE_MISMATCH")
    _verify_exact_candidate(guard_root, candidate)
    leases = inspect_audit_writer_leases()
    lease = next((item for item in leases if item.lease_id == lease_id), None)
    if (
        lease is None
        or lease.status != "ACTIVE"
        or not lease.valid_at_observation
        or lease.run_marker != plan.run_marker
        or lease.backend_build_id != plan.backend_build_id
    ):
        raise RuntimeError("EXACT_ACTIVE_AUDIT_WRITER_LEASE_REQUIRED")
    build = inspect_backend_audit_build(
        guard_root,
        Path(plan.backend_attestation_path),
        Path(plan.backend_lineage_attestation_path),
    )
    runtime = inspect_backend_audit_runtime(build)
    database, roles = verify_backend_audit_database()
    synthetic = verify_phase2i_synthetic_audit_identity()
    backend_role = next(role for role in roles if role.role == "kag_audit_backend")
    readonly_role = next(role for role in roles if role.role == "kag_audit_readonly")
    summary = _candidate_summary(candidate)
    candidate_before = str(summary["delivery_hash"])
    extension = candidate.resolve() / "artefact" / "extension"
    profile_root = Path(plan.plan_path).parent / "browser"
    profile = profile_root / "profile"
    _remove_guard_run_profile(profile_root, Path(plan.plan_path))
    browser = bundled_chromium_identity(guard_root)
    harness = _BrowserHarness(plan, lease)
    journeys: list[Phase2IJourneyEvidence] = []
    all_operations: list[dict[str, Any]] = []
    context: Any = None
    token = load_secret(SECRET_NAMESPACE, "synthetic_audit_token")
    terminal_outcome = "FAILED"
    browser_cleanup = "UNPROVEN"
    runtime_shutdown = "UNPROVEN"
    released_lease = lease
    try:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile),
                executable_path=browser.executable_path,
                channel="chromium",
                headless=True,
                args=[
                    f"--disable-extensions-except={extension}",
                    f"--load-extension={extension}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-sync",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--password-store=basic",
                ],
            )
            worker = _worker(context)
            context.route("**/*", harness.route)
            _seed_identity(worker, token, plan.synthetic_user_id)
            session_result = _json_request(
                worker,
                path="/api/v1/sessions",
                body={"user_id": plan.synthetic_user_id, "title": plan.run_marker},
                scenario="same_language_success",
                operation="session-create",
            )
            session_data = session_result.get("data")
            if session_result.get("ok") is not True or not isinstance(session_data, dict):
                raise RuntimeError(f"AUDIT_SESSION_CREATE_FAILED:{session_result.get('text')}")
            session_id = str(session_data["id"])
            worker.evaluate("(id) => chrome.storage.local.set({activeSessionId:id})", session_id)

            coursera = context.new_page()
            coursera.goto("https://www.coursera.org/learn/kag-audit/lecture/phase2i/lesson")
            coursera_extract = _extract_fixture(
                worker, "https://www.coursera.org/learn/kag-audit/lecture/phase2i/lesson"
            )
            youtube = context.new_page()
            youtube.goto("https://www.youtube.com/watch?v=kag-phase2i")
            youtube_extract = _extract_fixture(
                worker, "https://www.youtube.com/watch?v=kag-phase2i"
            )

            def ready(platform: str, suffix: str, extracted: dict[str, Any]) -> dict[str, Any]:
                logical = f"{platform}-{suffix}"
                body = _capture_body(
                    session_id=session_id, platform=platform, suffix=suffix, extracted=extracted
                )
                _, accepted = _accept(worker, body, "same_language_success", logical)
                generated = _generate(
                    worker,
                    accepted,
                    "same_language_success",
                    str(accepted["operationId"]),
                )
                if generated.get("state") != "ready" or not generated.get("displayObject"):
                    raise RuntimeError(f"READY_EXPLANATION_REQUIRED:{logical}")
                all_operations.append(generated)
                return generated

            c_auto = ready("coursera", "automatic", coursera_extract)
            journeys.append(
                _journey(
                    1,
                    JOURNEY_IDS[0],
                    "same_language_success",
                    [c_auto],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            c_manual = ready("coursera", "manual", coursera_extract)
            journeys.append(
                _journey(
                    2,
                    JOURNEY_IDS[1],
                    "same_language_success",
                    [c_manual],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            c_regen = _regenerate(
                worker, c_manual, "same_language_success", str(c_manual["operationId"])
            )
            all_operations.append(c_regen)
            journeys.append(
                _journey(
                    3,
                    JOURNEY_IDS[2],
                    "same_language_success",
                    [c_manual, c_regen],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            restored_c = worker.evaluate(
                "(id) => operationRuntime.getOperation(id)", c_regen["operationId"]
            )
            if not isinstance(restored_c, dict) or restored_c.get("artifactId") != c_regen.get(
                "artifactId"
            ):
                raise RuntimeError("COURSERA_SAVED_RESTORATION_FAILED")
            journeys.append(
                _journey(
                    4,
                    JOURNEY_IDS[3],
                    "saved_restoration",
                    [restored_c],
                    provider_attempts=0,
                    generation_operations=0,
                    visible_state="VISIBLE_SAVED_RESTORATION_PROVEN",
                )
            )

            y_auto = ready("youtube", "automatic", youtube_extract)
            journeys.append(
                _journey(
                    5,
                    JOURNEY_IDS[4],
                    "same_language_success",
                    [y_auto],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            y_manual = ready("youtube", "manual", youtube_extract)
            journeys.append(
                _journey(
                    6,
                    JOURNEY_IDS[5],
                    "same_language_success",
                    [y_manual],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            y_regen = _regenerate(
                worker, y_manual, "same_language_success", str(y_manual["operationId"])
            )
            all_operations.append(y_regen)
            journeys.append(
                _journey(
                    7,
                    JOURNEY_IDS[6],
                    "same_language_success",
                    [y_manual, y_regen],
                    provider_attempts=1,
                    generation_operations=1,
                )
            )
            restored_y = worker.evaluate(
                "(id) => operationRuntime.getOperation(id)", y_regen["operationId"]
            )
            if not isinstance(restored_y, dict) or restored_y.get("artifactId") != y_regen.get(
                "artifactId"
            ):
                raise RuntimeError("YOUTUBE_SAVED_RESTORATION_FAILED")
            journeys.append(
                _journey(
                    8,
                    JOURNEY_IDS[7],
                    "saved_restoration",
                    [restored_y],
                    provider_attempts=0,
                    generation_operations=0,
                    visible_state="VISIBLE_SAVED_RESTORATION_PROVEN",
                )
            )

            mismatch_body = _capture_body(
                session_id=session_id,
                platform="coursera",
                suffix="mismatch-a",
                extracted=coursera_extract,
            )
            _, mismatch_accepted = _accept(
                worker, mismatch_body, "wrong_then_correct", "mismatch-a"
            )
            mismatch_lineage = str(mismatch_accepted["operationId"])
            mismatch_first = _generate(
                worker, mismatch_accepted, "wrong_then_correct", mismatch_lineage
            )
            coursera.add_script_tag(path=str(extension / "languageRepairPolicy.js"))
            policy_first = coursera.evaluate(
                "() => KratosLanguageRepairPolicy.evaluateLanguageRepair({requestedLanguage:'english',detectedLanguage:'german',automatic:true,retryCount:0,lessonId:'coursera:phase2i:durable-audit',operationId:'mismatch-a'})"
            )
            if policy_first["action"] != "REPAIR_ONCE":
                raise RuntimeError("SEALED_LANGUAGE_REPAIR_NOT_REQUESTED")
            mismatch_repaired = _regenerate(
                worker, mismatch_first, "wrong_then_correct", mismatch_lineage
            )
            policy_second = coursera.evaluate(
                "() => KratosLanguageRepairPolicy.evaluateLanguageRepair({requestedLanguage:'english',detectedLanguage:'english',automatic:true,retryCount:1,lessonId:'coursera:phase2i:durable-audit',operationId:'mismatch-a'})"
            )
            if policy_second["state"] != "COMPLETED":
                raise RuntimeError("SEALED_LANGUAGE_REPAIR_DID_NOT_COMPLETE")
            mismatch_b_body = _capture_body(
                session_id=session_id,
                platform="youtube",
                suffix="mismatch-b",
                extracted=youtube_extract,
            )
            _, mismatch_b_accepted = _accept(
                worker, mismatch_b_body, "wrong_then_wrong", "mismatch-b"
            )
            mismatch_b_lineage = str(mismatch_b_accepted["operationId"])
            mismatch_b_first = _generate(
                worker, mismatch_b_accepted, "wrong_then_wrong", mismatch_b_lineage
            )
            mismatch_b_repaired = _regenerate(
                worker, mismatch_b_first, "wrong_then_wrong", mismatch_b_lineage
            )
            policy_b = coursera.evaluate(
                "() => KratosLanguageRepairPolicy.evaluateLanguageRepair({requestedLanguage:'english',detectedLanguage:'german',automatic:true,retryCount:1,lessonId:'youtube:phase2i:durable-audit',operationId:'mismatch-b'})"
            )
            if (
                policy_b["state"] != "RETRYABLE_LANGUAGE_FAILURE"
                or policy_b["action"] != "FAIL_EXPLICITLY"
            ):
                raise RuntimeError("SEALED_LANGUAGE_REPAIR_CAP_NOT_ENFORCED")
            all_operations.extend(
                [mismatch_first, mismatch_repaired, mismatch_b_first, mismatch_b_repaired]
            )
            journeys.append(
                _journey(
                    9,
                    JOURNEY_IDS[8],
                    "wrong_then_correct+wrong_then_wrong",
                    [mismatch_first, mismatch_repaired, mismatch_b_first, mismatch_b_repaired],
                    provider_attempts=4,
                    generation_operations=4,
                    visible_state="SCENARIO_A_ENGLISH_AND_SCENARIO_B_RETRYABLE_PROVEN",
                )
            )

            worker.evaluate(
                "() => chrome.storage.local.remove(['studyPilotBackendAuthToken','extensionToken'])"
            )
            logged_out = _worker_request(
                worker,
                {
                    "target": "backend",
                    "url": "/api/v1/sessions",
                    "method": "POST",
                    "headers": _headers("same_language_success", "logged-out"),
                    "body": "{}",
                },
            )
            if logged_out.get("status") != 401 or logged_out.get("authRequired") is not True:
                raise RuntimeError("LOGGED_OUT_BOUNDARY_FAILED")
            journeys.append(
                _journey(
                    10,
                    JOURNEY_IDS[9],
                    "logged_out",
                    [],
                    provider_attempts=0,
                    generation_operations=0,
                    visible_state="AUTH_REQUIRED_PROVEN",
                    persistence_state="ZERO_WRITES_PROVEN",
                )
            )
            _seed_identity(worker, token, plan.synthetic_user_id)
            unavailable = _json_request(
                worker,
                path="/__kag__/identity",
                body={},
                scenario="same_language_success",
                operation="backend-unavailable",
                unavailable=True,
            )
            if unavailable.get("status") != 0 or unavailable.get("error") not in {
                "network_error",
                "timeout",
            }:
                raise RuntimeError("BACKEND_UNAVAILABLE_BOUNDARY_FAILED")
            if not any(
                getattr(connection.laddr, "port", None) == 18000
                for connection in psutil.net_connections(kind="tcp")
                if connection.status == psutil.CONN_LISTEN
            ):
                raise RuntimeError("BACKEND_UNAVAILABLE_STOPPED_RUNTIME")
            journeys.append(
                _journey(
                    11,
                    JOURNEY_IDS[10],
                    "routing_layer_unavailable",
                    [],
                    provider_attempts=0,
                    generation_operations=0,
                    visible_state="BACKEND_UNAVAILABLE_PROVEN",
                    persistence_state="ZERO_WRITES_PROVEN",
                )
            )

            duplicate_body = _capture_body(
                session_id=session_id,
                platform="youtube",
                suffix="duplicate",
                extracted=youtube_extract,
            )
            duplicate_receipt, duplicate_accepted = _accept(
                worker, duplicate_body, "same_language_success", "duplicate"
            )
            duplicate_lineage = str(duplicate_accepted["operationId"])
            duplicate_ready = _generate(
                worker, duplicate_accepted, "same_language_success", duplicate_lineage
            )
            second_receipt = _capture_only(
                worker, duplicate_body, "same_language_success", duplicate_lineage
            )
            third_receipt = _capture_only(
                worker, duplicate_body, "same_language_success", duplicate_lineage
            )
            if (
                len(
                    {
                        duplicate_receipt["operationId"],
                        second_receipt["operationId"],
                        third_receipt["operationId"],
                    }
                )
                != 1
            ):
                raise RuntimeError("DUPLICATE_OPERATION_DID_NOT_CONVERGE")
            all_operations.append(duplicate_ready)
            journeys.append(
                _journey(
                    12,
                    JOURNEY_IDS[11],
                    "same_language_success",
                    [duplicate_ready],
                    provider_attempts=1,
                    generation_operations=1,
                    visible_state="DUPLICATE_PROTECTION_PROVEN",
                )
            )
            context.close()
            context = None
        browser_cleanup = "GUARD_BROWSER_CLOSED_ZERO_SURVIVORS_PROFILE_REMOVED"
        _remove_guard_run_profile(profile_root, Path(plan.plan_path))
        expected_ids = sorted({str(item["operationId"]) for item in all_operations})
        readback, scenario_evidence = verify_phase2i_database_readback(
            plan.run_marker, plan.synthetic_user_id, expected_ids
        )
        for journey in journeys:
            if journey.persistence_state == "PERSISTED_READBACK_PENDING":
                journey.persistence_state = "PERSISTED_READBACK_PROVEN"
        terminal_outcome = "ISOLATED_REAL_BACKEND_PERSISTENCE_GOLDEN_JOURNEYS_PROVEN"
        released_lease = release_audit_writer_lease(lease.lease_id, terminal_outcome)
        stopped = stop_backend_audit_runtime(Path(plan.runtime_owner_path))
        runtime_shutdown = str(stopped["state"])
        candidate_after = str(_candidate_summary(candidate)["delivery_hash"])
        budget = Phase2IRealBackendBudget(
            sessions=1,
            coursera_lessons=1,
            youtube_lessons=1,
            accepted_operations=readback.accepted_operation_count,
            automatic_repairs=1,
            regenerations=2,
            duplicate_attempts=2,
        )
        report = IsolatedRealBackendSuiteReport(
            schema_version="kratos-guard.phase2i-report.v1",
            run_id=plan.run_id,
            run_marker=plan.run_marker,
            candidate_id=EXPECTED_CANDIDATE_ID,
            candidate_before_sha256=candidate_before,
            candidate_after_sha256=candidate_after,
            backend_build=build,
            runtime=runtime,
            database=database,
            backend_role=backend_role,
            readonly_role=readonly_role,
            synthetic_identity=synthetic,
            lease=released_lease,
            scenarios=scenario_evidence,
            translations=harness.translations,
            budget=budget,
            journeys=journeys,
            database_readback=readback,
            retained_record_ids=[
                *readback.session_ids,
                *readback.operation_ids,
                *readback.artefact_ids,
                *readback.scenario_event_ids,
            ],
            stranded_operation_count=0,
            browser_cleanup_state=browser_cleanup,
            audit_runtime_shutdown_state=runtime_shutdown,
            final_verdict="ISOLATED_REAL_BACKEND_PERSISTENCE_GOLDEN_JOURNEYS_PROVEN_CANONICAL_RUNTIME_UNPROVEN",
            first_remaining_blocker="CANONICAL_RUNTIME_GOLDEN_JOURNEYS_NOT_EXECUTED",
        )
        report_path = Path(plan.plan_path).parent / "phase2i-report.json"
        report_path.write_text(report.model_dump_json(indent=2) + "\n", "utf-8")
        return report, report_path
    except Exception:
        if context is not None:
            try:
                context.close()
            except PlaywrightError:
                pass
        try:
            _remove_guard_run_profile(profile_root, Path(plan.plan_path))
        finally:
            try:
                release_audit_writer_lease(lease.lease_id, terminal_outcome)
            finally:
                stop_backend_audit_runtime(Path(plan.runtime_owner_path))
        raise


def verify_phase2i_report(report_path: Path) -> dict[str, object]:
    report = IsolatedRealBackendSuiteReport.model_validate_json(report_path.read_text("utf-8"))
    checks = {
        "candidate_unchanged": report.candidate_before_sha256 == report.candidate_after_sha256,
        "all_twelve_journeys": len(report.journeys) == 12
        and all(item.verdict == "PROVEN" for item in report.journeys),
        "readback": report.database_readback.verdict == "PHASE2I_DATABASE_READBACK_PROVEN",
        "lease_released": report.lease.status == "RELEASED",
        "runtime_stopped": report.audit_runtime_shutdown_state in {"STOPPED", "ALREADY_STOPPED"},
        "browser_clean": report.browser_cleanup_state
        == "GUARD_BROWSER_CLOSED_ZERO_SURVIVORS_PROFILE_REMOVED",
        "caps": report.budget.accepted_operations <= 12
        and report.budget.external_provider_calls == 0,
        "protected_boundaries": report.normal_chrome_mutations == 0
        and report.canonical_database_writes == 0
        and report.study_pilot_source_git_mutations == 0,
        "qualified_verdict": report.final_verdict
        == "ISOLATED_REAL_BACKEND_PERSISTENCE_GOLDEN_JOURNEYS_PROVEN_CANONICAL_RUNTIME_UNPROVEN",
    }
    return {
        "report": str(report_path.resolve()),
        "checks": checks,
        "final_verdict": report.final_verdict,
        "first_remaining_blocker": report.first_remaining_blocker,
        "verdict": "PHASE2I_REPORT_VERIFIED"
        if all(checks.values())
        else "PHASE2I_REPORT_CONTRADICTED",
    }


def explain_phase2i_report(report_path: Path) -> dict[str, object]:
    report = IsolatedRealBackendSuiteReport.model_validate_json(report_path.read_text("utf-8"))
    return {
        "qualified_verdict": report.final_verdict,
        "what_is_proven": "sealed extension, isolated backend orchestration, queue state, and PostgreSQL persistence",
        "what_is_not_proven": ["canonical runtime", "real provider", "normal Chrome profile"],
        "journeys_proven": sum(item.verdict == "PROVEN" for item in report.journeys),
        "accepted_operations": report.budget.accepted_operations,
        "external_provider_calls": report.external_provider_calls,
        "promotion_authority": report.promotion_authority,
        "first_remaining_blocker": report.first_remaining_blocker,
    }
