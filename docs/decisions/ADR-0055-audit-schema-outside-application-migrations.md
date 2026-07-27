# ADR-0055: Audit schema outside application migrations

## Decision

Synthetic identities, writer leases, scenario runs, and events live in `kag_audit`, outside the application migration sequence.

## Consequences

The public schema remains at normal head 017; audit control does not invent product migration 018 or change normal schema semantics.
