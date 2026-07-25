# ADR-0040: Extension-ID continuity as a release invariant

## Context
Changing a Chrome extension's manifest public key changes its identity and
breaks continuity with the configured client.

## Decision
Require byte-identical key material and empirical isolated ID
`mofhgdnkngbpbcihjkhoelogkjolaidn` for baseline and successor runtime proofs.

## Consequence
A valid signature or version bump cannot compensate for an ID mismatch.
