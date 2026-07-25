# ADR-0039: Local bundle before target-remote branch

## Context
The clean lineage needs durable recovery without mutating Study Pilot remotes.

## Decision
Create and verify a signed local Git bundle. Do not push reconciliation or
successor refs to a Study Pilot remote in Phase 2F.

## Consequence
Recovery remains portable while remote branch authority stays `NONE`.
