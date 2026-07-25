# Lesson 43: One-fix development lanes

## Established concept

One lane owns one behavioural contract and one bounded runtime delta.
## Plain-language explanation

Fix one observed failure without using the opportunity to redesign nearby code.
## Why AI agents struggle

Related cleanup looks efficient but makes causality and rollback ambiguous.
## Itzako example

Phase 2G changes only wrong-language automatic explanation recovery.
## Guard implementation

An authority descriptor names the sole fix, branch, base commit, and prohibited scopes.
## Trade-offs

Progress is narrower, but evidence and rollback are attributable.
## Failure modes

Permission expansion, backend edits, UI refactors, or several retry policies.
## Practical exercise

List every changed runtime path and map it to one acceptance criterion.
## Transfer

Use the lane for payment recovery, migrations, and security patches.
## Key takeaway

Small authority produces strong proof.
