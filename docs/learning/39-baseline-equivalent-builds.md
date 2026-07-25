# Lesson 39: Baseline-equivalent builds

## Established technical concept
A baseline-equivalent build reproduces an artefact's full path set and
individual hashes, not merely its version or visible behaviour.

## Plain-language explanation
Two packages are equivalent only when every expected file is present and every
byte matches.

## Why AI coding agents struggle
Passing tests, matching versions, and similar screenshots are tempting
shortcuts. None establishes exact reproduction.

## Itzako example
The reconciliation must reproduce payload
`709a5749bf2bc3653cce8c92ae0538b6d0961154ecfba9e3181a7c9d78804147`,
including version `1.1.17`, `serviceWorker.js`, public key, permissions, and
content-script declarations.

## Guard implementation
The static source-as-runtime procedure copies only mapped extension bytes,
sorts paths deterministically, records every file digest, and rejects any
manifest-hash difference before a successor branch can be created.

## Trade-offs
Exact equivalence is stricter than functional equivalence and may preserve
awkward metadata. That is intentional: behavioural improvement belongs in a
later, separately reviewed change.

## Failure modes
Ignoring an extra file, normalising line endings, regenerating timestamps, or
excluding a generated runtime identity file from the payload.

## Practical exercise
Build the same fixture twice, compare path sets and digests, then introduce one
newline and observe the equivalence failure.

## Transfer to another project
Use exact equivalence for rollback packages, container layers, signed assets,
and regulated release archives.

## Key takeaway
Baseline equivalence is a byte-level claim with a deterministic manifest.
