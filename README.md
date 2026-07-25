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
```

Inspection does not grant permission to modify a target. Phase 1 adapters expose
read-only observations only.
