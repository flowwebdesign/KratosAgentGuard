# ADR-0054: Dedicated audit database

## Decision

All Phase 2I product and control records use `studypilot_kag_audit`; `studypilot_dev` is prohibited.

## Consequences

Real migrations and persistence can be exercised with least-privilege roles while canonical database writes remain zero.
