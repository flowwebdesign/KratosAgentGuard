# ADR-0051: Independent database readback

## Decision

Require transaction-enforced read-only PostgreSQL evidence for full success.

## Consequences

API success alone cannot certify lessons, operations, revisions, or provider-attempt counts.
