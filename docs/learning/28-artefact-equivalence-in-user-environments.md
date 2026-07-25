# 28. Artefact equivalence in user environments

## Established technical concept
Equivalence requires deterministic bytes or a trusted signed claim over those bytes.
## Plain-language explanation
Matching names and versions do not prove two extension builds are identical.
## Why AI coding agents struggle
Human-readable labels look authoritative but are mutable.
## Itzako example
Guard compares the configured payload manifest or packaged attestation to the sealed candidate.
## Guard implementation
Name, version, worker, source HEAD, payload hash, attestation hash, signature, and trust are separate.
## Trade-offs
Exact comparison costs more I/O than comparing manifest labels.
## Failure modes
Treating version 1.1.17 or commit `950e204` as sufficient identity.
## Practical exercise
Change one static file without changing version and observe the payload mismatch.
## Transfer
Use content identity for deployed frontend bundles and model artefacts.
## Key takeaway
Labels describe artefacts; hashes and attestations identify them.
