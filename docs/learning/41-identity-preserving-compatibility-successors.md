# Lesson 41: Identity-preserving compatibility successors

## Established technical concept
A compatibility successor changes release identity metadata while preserving
the public key and all product contracts.

## Plain-language explanation
Before fixing behaviour, create one newer package that is intentionally the
same product under the same extension identity.

## Why AI coding agents struggle
Version bumps invite opportunistic refactors. Small permission, worker, match
pattern, storage, or message changes can silently turn compatibility work into a
product release.

## Itzako example
The `1.1.18` compatibility candidate may change only `manifest.json`,
`buildInfo.js`, and `BUILD_IDENTITY.json`, plus packaged Guard attestation. The
key-derived ID must remain `mofhgdnkngbpbcihjkhoelogkjolaidn`.

## Guard implementation
`CompatibilitySuccessorDelta` records actual, permitted, and unexpected paths.
It independently compares key, worker, permissions, host permissions, content
scripts, and behaviour-file equality.

## Trade-offs
The candidate deliberately does not solve the behavioural bug. It separates
lineage risk from product-change risk so the next review has a stable base.

## Failure modes
Changing the manifest key, expanding hosts, renaming messages, modifying
storage schema, or treating a matching version as continuity proof.

## Practical exercise
Bump a fixture version and identity stamp, then make one permission expansion
and confirm that static compatibility fails.

## Transfer to another project
Use compatibility successors for package-manager migrations, signing-key
continuity checks, or release-pipeline replacement.

## Key takeaway
A compatibility successor proves continuity by constraining change, not by
claiming new behaviour.
