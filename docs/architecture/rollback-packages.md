# Rollback packages

The deterministic rollback ZIP contains only original payload entries and
excludes Guard delivery attestation. Verification reconstructs the payload
manifest from archive bytes and rejects missing or extra paths.
