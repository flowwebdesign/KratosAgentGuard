# Bootstrap Authority

## Established engineering concept

Bootstrap gates evaluate whether a new authority can safely be created; version
gates evaluate an authority that already exists.

## Plain-language explanation

A new repository cannot have a commit before its first commit. That absence is
expected, not a defect.

## Previous misunderstanding

The earlier run required branch, HEAD, and Git common-directory proof before
initialisation.

## Itzako example

Itzako Git history is irrelevant to creating the independent guard repository.

## Protection implemented

`BootstrapFacts` permits missing HEAD and Git metadata while still blocking
wrong remotes, target containment, and unexplained files.

## Trade-offs

Bootstrap logic is a separate path that must be retired once normal repository
authority exists.

## Common failure modes

Blocking an empty remote, initialising inside another worktree, or overwriting
unexplained local files.

## Practical exercise

Evaluate the bootstrap gate with an empty directory, then add `mystery.txt` and
observe the ownership blocker.

## Transfer

Use the pattern for new infrastructure repositories and isolated migration
workspaces.

## Takeaway

Judge absence according to lifecycle stage.
