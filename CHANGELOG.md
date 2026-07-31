# Changelog

## 1.0.0

- Added native Windows and Linux standalone installation paths.
- Added strict per-user configuration and explicit monitored-folder registry.
- Added durable read-only monitoring with ownership locks, heartbeat state,
  restart diagnosis, signed cross-run baselines, bounded scans, and clean
  shutdown records.
- Added signed multi-key rotation continuity and historical-key revocation.
- Added portable evidence bundles with manifest, path, size, hash, signature,
  ledger-chain, and externally pinned trust-anchor verification.
- Added fail-closed standalone readiness and health reporting.
- Added adversarial lifecycle tests, installed-wheel smoke tests, SBOM and
  checksum generation, and cross-platform release automation.
- Preserved legacy standalone commands and v1 ledger entry compatibility.

The v1 release does not infer external targets, control normal browser
profiles, mutate product repositories, call providers, or perform remediation.
