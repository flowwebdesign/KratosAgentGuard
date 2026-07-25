# Baseline-equivalent builds

The operational extension is static source-as-runtime with explicitly mapped
generated identity files. Guard overlays only mapped extension bytes into the
isolated clone and creates a deterministic path-ordered manifest.

The reconciliation cannot proceed unless file count, path set, individual
hashes, and aggregate payload equal the Phase 2E baseline. The build-input
record states no network, no dependencies, and no credentials. A patch manifest
records each changed path and before/after hash.
