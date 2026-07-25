# Attestation and Trust Roots

## Established technical concept
An attestation is useful only when its integrity and issuer trust are established.

## Plain-language explanation
A sealed statement can show it was not changed, but you must still trust who signed it.

## Why AI coding agents struggle
Schema validity and checksum integrity are often mistaken for truth.

## Itzako example
The future loaded-client envelope can be integrity-checked, but Phase 2A has no
trusted Chrome collector signature.

## Kratos Agent Guard implementation
Imports validate schema and canonical integrity while explicitly withholding trust.

## Trade-offs
Signatures require key ownership, rotation, and verification policy.

## Failure modes
Self-asserted evidence, unsigned envelopes, or unprotected keys.

## Practical exercise
Tamper with an envelope after calculating its integrity hash.

## Transfer
Use signed attestations for Kratos Forge generated packages.

## Key takeaway
Integrity protects a statement; a trust root gives it authority.
