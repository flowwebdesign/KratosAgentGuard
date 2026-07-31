# Kratos Agent Guard

Kratos Agent Guard is an independent, read-only control plane for proving
repository, build, runtime, and loaded-client identities without assuming they
share a repository.

## Quick start

```powershell
uv sync --extra dev
uv run kratos-guard bootstrap-check
uv run kratos-guard self-identity
uv run kratos-guard validate-config
uv run kratos-guard inspect --target C:\path\to\target --profile itzako
uv run kratos-guard source-manifest --target C:\path\to\target --profile itzako
uv run kratos-guard discover-artifacts --target C:\path\to\target --profile itzako
uv run kratos-guard inspect-runtime --profile itzako
uv run kratos-guard gate --target C:\path\to\target --profile itzako --level source
uv run kratos-guard key initialise
uv run kratos-guard key export-public
uv run kratos-guard build-plan --target C:\path\to\target --profile itzako --component extension
uv run kratos-guard build-sealed-candidate --target C:\path\to\target --profile itzako --component extension
```

Inspection does not grant permission to modify a target. Phase 1 adapters expose
read-only observations only.

Phase 2A gates are qualified. Source authority cannot satisfy build, runtime, or
loaded-client gates without independently evidenced provenance links.

## Standalone operational mode

The v1 standalone product operates without a configured product target. It
stores private state below the operating system's per-user data directory and
writes evidence only below its configured evidence root.

```powershell
uv run --frozen kratos-guard standalone init
uv run --frozen kratos-guard standalone folder add --path C:\path\to\observe --label source
uv run --frozen kratos-guard standalone run --iterations 1
uv run --frozen kratos-guard standalone status
uv run --frozen kratos-guard standalone health
uv run --frozen kratos-guard key rotate --reason scheduled-rotation
uv run --frozen kratos-guard standalone evidence checkpoint
uv run --frozen kratos-guard standalone evidence export --destination <evidence-root>\exports\evidence.zip
uv run --frozen kratos-guard standalone evidence verify --bundle <evidence-root>\exports\evidence.zip --expected-trust-anchor-key-id <pinned-first-signer-key-id>
uv run --frozen kratos-guard standalone evidence import --bundle C:\path\to\verified-evidence.zip --expected-trust-anchor-key-id <pinned-first-signer-key-id>
uv run --frozen kratos-guard standalone service-template --kind windows --output .\Register-KratosAgentGuardTask.ps1
```

Omit `--iterations` to run continuously under an operator-selected supervisor.
Systemd and Windows Task Scheduler templates are available under `packaging/`
and through `standalone service-template`; they are never installed
automatically. Review the generated template before enabling it.

The standalone controls include:

- a signed, hash-linked JSONL evidence ledger;
- dual-signed multi-key rotation continuity and explicit historical revocation;
- short-lived, signed runtime challenges with replay rejection;
- a Guard-owned synthetic producer for exercising the protocol end to end;
- passive, bounded folder snapshots and drift monitoring;
- explicit signed ledger checkpoints;
- portable, independently verifiable and importable evidence bundles.

Bundle verification and import require the first ledger signer key ID obtained
through a separate trusted channel. A bundle without that external pin is
reported as self-consistent but untrusted; signatures inside a bundle cannot
authenticate the wholesale replacement of that same bundle.

Release wheels and source archives are built twice with a fixed source epoch;
publication stops unless the two builds are byte-identical. Each GitHub release
includes SHA-256 checksums, an SPDX 2.3 dependency SBOM, and GitHub artifact
attestations.

Legacy standalone commands remain available for compatibility:

```powershell
uv run --frozen kratos-guard key initialise
uv run --frozen kratos-guard key export-public
uv run --frozen kratos-guard ledger append --event-type guard.initialised --subject standalone
uv run --frozen kratos-guard standalone-status
uv run --frozen kratos-guard attestation issue --subject guard-fixture --output evidence\standalone\example\challenge.json
uv run --frozen kratos-guard attestation synthetic-produce --challenge-path evidence\standalone\example\challenge.json --artifact-root C:\path\to\fixture --output-directory evidence\standalone\example\synthetic
uv run --frozen kratos-guard attestation verify --challenge-path evidence\standalone\example\challenge.json --statement-path evidence\standalone\example\synthetic\runtime-statement.json --guard-trust-key <guard-public-key> --producer-trust-key evidence\standalone\example\synthetic\producer-trust.pub.json
uv run --frozen kratos-guard monitor snapshot --root C:\path\to\fixture --output evidence\standalone\example\snapshot.json
uv run --frozen kratos-guard monitor watch --root C:\path\to\fixture --iterations 10
uv run --frozen kratos-guard ledger verify --trust-key <guard-public-key>
```

`attestation synthetic-produce` creates an ephemeral producer key and persists
only its public trust record. A successful synthetic verification proves the
challenge, signature, freshness, artifact identity, and replay controls. It
also consumes that challenge exactly once, regardless of later statement IDs
or producer keys. It does **not** prove which extension or service worker is
loaded in a user's
normal browser profile. That state remains `UNPROVEN_SYNTHETIC_SCOPE` until an
external runtime independently implements the protocol and returns a signed
statement.

Every command that observes a folder rejects evidence output inside that
folder. Standalone commands do not discover, start, stop, or modify browsers,
services, databases, providers, or product repositories.

`standalone-status` fails closed unless the Guard identity is clean and proven,
the private signing key is safely stored, and the ledger is cryptographically
verified. It never treats a merely present ledger as ready. The native key
store works on Windows and Linux; CI exercises the complete standalone CLI
lifecycle on both platforms.

## Phase 2D passive current-profile inspection

Use an exact sealed candidate; there is no implicit `latest` selection:

```powershell
uv run kratos-guard inspect-browser-processes
uv run kratos-guard discover-browser-profiles
uv run kratos-guard inspect-current-extension --profile itzako --candidate <candidate>
uv run kratos-guard compare-current-extension --profile itzako --candidate <candidate>
uv run kratos-guard promotion-readiness --profile itzako --candidate <candidate>
uv run kratos-guard gate --profile itzako --level current-runtime-attestation --candidate <candidate>
```

These commands are metadata-only. They do not launch or control Chrome, enable
remote debugging, read sensitive browser databases, or execute promotion.

## Phase 2E operational baseline

Phase 2E seals the exact configured extension into a Guard-owned rollback
baseline and designs—but never executes—a future promotion:

```powershell
uv run kratos-guard inspect-configured-source --profile itzako
uv run kratos-guard test-extension-id-stability --profile itzako
uv run kratos-guard seal-current-baseline --profile itzako
uv run kratos-guard verify-current-baseline --baseline <exact-baseline>
uv run kratos-guard canary-current-baseline --baseline <exact-baseline>
uv run kratos-guard classify-reference-candidate --baseline <exact-baseline> --candidate <exact-candidate>
uv run kratos-guard design-promotion --baseline <exact-baseline> --candidate-contract <exact-contract>
```

There is no implicit `latest` baseline and no command that promotes the
normal-profile extension.

## Phase 2F isolated lineage reconciliation

Phase 2F maps the configured operational bytes, reconstructs them only in a
Guard-owned separate-object-database clone, and seals a compatibility-only
successor. Every workspace, baseline, and candidate argument is exact; no
command selects the latest result implicitly:

```powershell
uv run kratos-guard map-configured-extension-source --profile itzako
uv run kratos-guard select-reconciliation-base --profile itzako
uv run kratos-guard create-isolated-reconciliation --profile itzako
uv run kratos-guard verify-baseline-equivalence --reconciliation <exact-workspace>
uv run kratos-guard seal-reconciliation-lineage --reconciliation <exact-workspace>
uv run kratos-guard build-compat-successor --reconciliation <exact-workspace>
uv run kratos-guard verify-compat-successor --candidate <exact-candidate>
uv run kratos-guard compare-successor-baseline --baseline <exact-baseline> --candidate <exact-candidate>
uv run kratos-guard explain-report <phase2f-report>
```

The compatibility successor changes only version and provenance identity
metadata. It performs no normal-profile promotion and leaves behavioural
readiness explicitly unproven.

## Phase 2G first behavioural successor

Phase 2G imports the exact Phase 2F lineage into one independent, remote-free
development repository and permits one bounded fix:
`WRONG_LANGUAGE_AUTOMATIC_EXPLANATION_RECOVERY`.

```powershell
uv run kratos-guard import-successor-bundle --bundle <exact-bundle> --destination "C:\Users\floww\Documents\Itzako Extension Successor"
uv run kratos-guard analyse-behavioural-impact --repository "C:\Users\floww\Documents\Itzako Extension Successor" --fix wrong-language-automatic-recovery
uv run kratos-guard run-offline-golden-journeys --candidate <exact-candidate> --suite itzako-extension
uv run kratos-guard verify-behavioural-successor --base-candidate <phase2f-candidate> --candidate <phase2g-candidate>
uv run kratos-guard bundle-behavioural-lineage --repository "C:\Users\floww\Documents\Itzako Extension Successor"
uv run kratos-guard explain-report <phase2g-report>
```

The offline journeys intercept fixture traffic and make no real backend or
provider calls. A passing suite proves only the isolated fixture boundary; it
does not authorise normal-profile promotion.

## Phase 2H capped real-backend journeys

Phase 2H binds a sealed behavioural candidate to an observed backend contract,
synthetic identity, deterministic provider seam, read-only persistence
readback, and immutable operation budget:

```powershell
uv run kratos-guard inspect-backend-contract --profile itzako
uv run kratos-guard classify-protected-target-drift --baseline <exact-baseline> --current <exact-witness>
uv run kratos-guard verify-synthetic-audit-identity --profile itzako
uv run kratos-guard verify-provider-test-seam --profile itzako
uv run kratos-guard verify-database-readback --profile itzako
uv run kratos-guard plan-real-backend-journeys --candidate <exact-candidate>
uv run kratos-guard run-real-backend-journeys --candidate <exact-candidate> --plan <exact-plan>
uv run kratos-guard verify-real-backend-report --report <exact-report>
uv run kratos-guard explain-report <phase2h-report>
```

Planning never selects a latest candidate. Dispatch remains fail-closed when a
synthetic identity, isolated provider scenario seam, read-only database
boundary, budget, or writer authority is missing. Phase 2H adds no promotion
command and never uses the normal Chrome profile.

## Phase 2I isolated backend audit authority

Phase 2I provisions an independent backend successor, dedicated PostgreSQL
database, least-privilege roles, one synthetic identity, deterministic provider
scenarios, and an exclusive audit writer lease. The sealed extension remains
byte-identical; only Guard Chromium translates its canonical local origin to the
isolated runtime:

```powershell
uv run kratos-guard provision-backend-audit-authority --source-commit <exact-commit> --destination <exact-repository>
uv run kratos-guard verify-backend-audit-database
uv run kratos-guard verify-phase2i-synthetic-audit-identity
uv run kratos-guard verify-audit-provider-scenarios --repository <exact-repository>
uv run kratos-guard acquire-audit-writer-lease --candidate <exact-candidate-id> --run-marker <exact-marker> --backend-build-id <exact-build>
uv run kratos-guard start-backend-audit-runtime --attestation <exact-attestation> --lineage-attestation <exact-lineage-attestation> --runtime-directory <exact-directory>
uv run kratos-guard plan-isolated-real-backend-journeys --candidate <exact-candidate> --attestation <exact-attestation> --lineage-attestation <exact-lineage-attestation> --runtime-owner <exact-owner> --backend-repository <exact-repository> --synthetic-user-id <exact-user>
uv run kratos-guard run-isolated-real-backend-journeys --candidate <exact-candidate> --lease <exact-lease> --plan <exact-plan>
uv run kratos-guard verify-phase2i-report --report <exact-report>
uv run kratos-guard explain-report <exact-report>
```

Every candidate, build, owner, lease, plan, and report is selected explicitly.
The qualified success verdict preserves canonical runtime, real provider, normal
Chrome, and promotion as separate unproven boundaries.
