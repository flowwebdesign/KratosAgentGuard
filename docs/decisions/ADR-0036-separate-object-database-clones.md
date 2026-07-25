# ADR-0036: Separate-object-database clones

## Context
Linked worktrees and ordinary local clones may share refs, objects, alternates,
or hardlinks with the target.

## Decision
Use a Guard-owned `--no-local --no-hardlinks` clone and verify common-directory
inequality, absent alternates, absent hardlinks, and disabled push.

## Consequence
Local reconciliation Git mutations remain inside Guard `.work`.
