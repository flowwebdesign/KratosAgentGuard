# ADR-0056: Synthetic token audience and scope

## Decision

The Phase 2I token requires audience `itzako-kag-audit`, scope `audit:golden-journeys`, subject `kag-phase2i`, and tenant `kag-audit`.

## Consequences

Normal or production tokens cannot activate audit behaviour. Evidence reports a fingerprint only; the DPAPI-protected token remains local.
