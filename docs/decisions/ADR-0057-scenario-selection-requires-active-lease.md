# ADR-0057: Scenario selection requires an active lease

## Decision

Deterministic provider scenarios require an exact active lease matching the run marker, candidate, backend build, database, and synthetic subject.

## Consequences

Missing, mismatched, expired, or released authority fails closed; scenario state cannot leak across runs or normal traffic.
