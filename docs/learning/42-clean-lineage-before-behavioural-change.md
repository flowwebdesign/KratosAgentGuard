# Lesson 42: Clean lineage before behavioural change

## Established technical concept
Separating provenance reconstruction from behavioural modification reduces the
number of variables in each proof.

## Plain-language explanation
First prove where the current product came from. Then fix it in a new change
whose effects can be reviewed on their own.

## Why AI coding agents struggle
Agents optimise for visible progress and may combine cleanup, reconstruction,
versioning, and bug fixes into one diff.

## Itzako example
Phase 2F ends with a clean `1.1.17` reconciliation commit and an identity-stable
`1.1.18` compatibility candidate. Its explicit remaining blocker is
`BEHAVIOURAL_SUCCESSOR_CHANGE_NOT_IMPLEMENTED`.

## Guard implementation
The reconciliation and successor use separate local branches and commits. A
signed Git bundle preserves the clean base, while promotion authority remains
`NONE`.

## Trade-offs
This creates an extra phase and candidate. It makes later behavioural evidence
attributable to the actual fix rather than to source cleanup.

## Failure modes
Bundling a fix into the reconstruction commit, treating isolated runtime as
learner readiness, pushing recovery refs automatically, or promoting before
golden journeys.

## Practical exercise
Split a mixed patch into a byte-equivalent baseline commit and a one-purpose
behavioural commit. Define separate proof requirements for each.

## Transfer to another project
The pattern applies to database migrations, infrastructure drift recovery,
firmware repair, and supply-chain provenance remediation.

## Key takeaway
Clean provenance is the foundation for an honest behavioural change.
