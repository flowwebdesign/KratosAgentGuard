# ADR-0052: No automatic cleanup of synthetic evidence

## Decision

Retain marked synthetic records unless an existing cleanup contract is proven before dispatch.

## Consequences

Guard records retained IDs and never broadens deletion authority after a run.
