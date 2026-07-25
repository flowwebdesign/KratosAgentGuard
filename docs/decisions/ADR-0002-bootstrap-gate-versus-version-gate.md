# ADR-0002: Bootstrap Gate Versus Version Gate

- Status: Accepted
- Decision: use lifecycle-specific bootstrap semantics before the initial commit.
- Context: unborn HEAD and missing Git metadata are expected before initialisation.
- Consequence: the gate blocks unsafe ownership and authority, not expected absence.
