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
