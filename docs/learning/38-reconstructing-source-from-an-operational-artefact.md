# Lesson 38: Reconstructing source from an operational artefact

## Established technical concept
Artefact-led reconstruction starts from verified runtime bytes and builds a
traceable committed lineage without rewriting the original evidence.

## Plain-language explanation
When the shipped copy is the clearest truth, preserve it, choose a defensible
historical base, and explain every byte needed to reach the shipped result.

## Why AI coding agents struggle
An agent may edit the dirty repository in place, assume the newest commit is
correct, or copy unrelated changes because they are nearby.

## Itzako example
The configured `1.1.17` payload is exact and sealed, while its containing Study
Pilot worktree is extensively dirty. Guard reconstructs only
`Study_master/extension` inside an isolated clone.

## Guard implementation
Base candidates include ancestry, tree identity, exact-file counts, overlap,
changed/missing/extra paths, manifest-key compatibility, worker compatibility,
and contradictions. A patch manifest records each authorised before/after
hash.

## Trade-offs
The reconstructed commit may not recover historical authorship. It does provide
a clean, auditable starting point whose relationship to the operational bytes
is explicit.

## Failure modes
Selecting by folder name, copying the whole dirty worktree, losing the manifest
key, or omitting untracked files whose runtime role is proven.

## Practical exercise
Given a release folder and twenty commits, identify the best base using both
ancestry and byte-level overlap, then write a path-by-path patch manifest.

## Transfer to another project
This works for emergency release recovery, vendor drops, and legacy deployments
whose build pipeline is incomplete.

## Key takeaway
Reconstruction is a chain of evidence from a chosen base to exact operational
bytes, not a guess about which directory looks newest.
