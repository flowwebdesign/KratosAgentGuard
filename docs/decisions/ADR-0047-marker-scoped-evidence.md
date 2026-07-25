# ADR-0047: Marker-scoped evidence instead of global quiescence

## Decision

Attribute Phase 2H records through synthetic owner and `KAG-2H-*` marker filters.

## Consequences

Real-user concurrency may continue. Global count deltas cannot prove Guard causation.
