# ADR-0049: Existing deterministic provider seam only

## Decision

Use only a pre-existing, run-isolated provider scenario seam.

## Consequences

Missing wrong-language scenario controls block dispatch; Guard does not patch or restart the backend.
