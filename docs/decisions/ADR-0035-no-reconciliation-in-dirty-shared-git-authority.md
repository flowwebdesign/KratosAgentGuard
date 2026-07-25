# ADR-0035: No reconciliation in dirty shared Git authority

## Context
The configured extension is inside an extensively dirty shared Study Pilot Git
authority.

## Decision
Treat the target as read-only evidence. Reconciliation branches, commits, and
builds are prohibited in its worktree and common directory.

## Consequence
Unrelated user work is preserved, and reconstruction cannot acquire false
authority from a convenient dirty tree.
