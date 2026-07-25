# ADR-0017: Isolated browser profiles

Status: Accepted.

Use a fresh Guard-owned profile for every extension canary. Never reuse, copy, or inspect a normal browser profile. This protects user state and makes the canary reproducible, at the cost of not proving current-user loading.
