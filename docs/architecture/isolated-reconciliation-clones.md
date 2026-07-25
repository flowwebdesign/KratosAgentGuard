# Isolated reconciliation clones

Reconciliation occurs only beneath ignored `.work/successor-reconciliation`.
Guard uses a no-local, no-hardlink clone and verifies a distinct Git common
directory, no object alternates, no linked-worktree relationship, and no shared
object file identity. The fetch remote may retain the local source path for
read-only history. The push URL is deliberately invalid.

All reconciliation branches, commits, bundles, candidates, and browser profiles
remain Guard-owned. The original Study Pilot worktree and Git common directory
are witnesses, never writers.
