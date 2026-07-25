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
