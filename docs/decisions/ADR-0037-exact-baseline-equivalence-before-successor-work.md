# ADR-0037: Exact baseline equivalence before successor work

## Context
A successor built from merely similar source would preserve the original
lineage ambiguity.

## Decision
Require exact file paths, file hashes, aggregate payload, manifest contract,
version, worker, and isolated extension identity before creating a successor.

## Consequence
Any mismatch blocks successor work rather than being hidden in its delta.
