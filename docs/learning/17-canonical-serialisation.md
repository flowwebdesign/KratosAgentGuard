# Canonical Serialisation

## Established technical concept
Signatures require one deterministic byte representation of structured data.
## Plain-language explanation
Different whitespace or key order must not change the meaning being signed.
## Why AI coding agents struggle
Agents sign convenient JSON output without defining ordering or excluded fields.
## Itzako example
The attestation sorts keys, removes whitespace, and excludes signature and integrity fields.
## Kratos Agent Guard implementation
`canonicalise_attestation_payload` defines the exact Ed25519 message bytes.
## Trade-offs
Schema changes require versioning and compatibility policy.
## Failure modes
Signing pretty JSON, locale-dependent values, absolute paths or the signature itself.
## Practical exercise
Reorder model fields and confirm canonical bytes remain equal.
## Transfer
Canonicalise Deal Sniper evidence envelopes.
## Key takeaway
Cryptographic meaning starts with deterministic bytes.
