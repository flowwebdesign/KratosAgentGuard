# ADR-0004: Read-Only Itzako Adapter First

- Status: Accepted
- Decision: Phase 1 exposes only bounded read-only Itzako observations.
- Context: inspection authority does not imply mutation authority.
- Consequence: no target writes, restarts, browser changes, datastore writes, or
  provider calls are available.
