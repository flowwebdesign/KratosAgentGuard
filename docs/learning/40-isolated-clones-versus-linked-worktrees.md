# Lesson 40: Isolated clones versus linked worktrees

## Established technical concept
A linked worktree shares a Git common directory and object authority; an
isolated clone can use a separate object database and independent refs.

## Plain-language explanation
A new checkout is not automatically a new safety boundary. If it shares the
same Git machinery, creating a branch still mutates the original repository's
authority.

## Why AI coding agents struggle
Agents often see a different filesystem path and assume isolation, overlooking
`.git` indirection, alternates, shared refs, and hardlinked object files.

## Itzako example
Phase 2F prohibits new Study Pilot worktrees and branches in the existing
common directory. Guard uses `git clone --no-local --no-hardlinks`, then
disables the push URL.

## Guard implementation
`IsolatedCloneIdentity` records repository root, Git directory, Git common
directory, target inequality, linked-worktree state, alternates, hardlinked
object count, fetch remote, push remote, and clean state.

## Trade-offs
The clone consumes more disk and clone time. In return, local reconciliation
branches and commits cannot alter the target Git common directory.

## Failure modes
Using `git worktree add`, local clone hardlinks, object alternates, leaving a
writable push destination, or assuming a separate `.git` path is sufficient.

## Practical exercise
Compare `git rev-parse --git-common-dir` for a linked worktree and a no-local
clone. Inject a hardlink and make the safety check reject it.

## Transfer to another project
Use separate-object clones for forensic recovery, untrusted patch review, and
release reconstruction around shared developer worktrees.

## Key takeaway
Isolation must cover objects, refs, remotes, and process scope—not just paths.
