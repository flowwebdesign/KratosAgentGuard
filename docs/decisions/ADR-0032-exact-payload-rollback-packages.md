# ADR-0032: Exact-payload rollback packages

## Decision
Rollback restores original payload bytes, excluding delivery evidence.
## Consequence
Attestation cannot silently redefine the operational baseline.
