# ADR-0042: No backend expansion without a new authority gate

## Decision

Extension work stops if a new backend or persistence contract is required.
## Consequence

Existing routes may be reused; backend mutation cannot be inferred.
