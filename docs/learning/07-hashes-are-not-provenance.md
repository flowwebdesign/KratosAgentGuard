# Hashes Are Not Provenance

## Established technical concept
Cryptographic hashes identify bytes; provenance establishes an evidenced chain
of custody and production.

## Plain-language explanation
Two matching fingerprints show two byte sets match, not who created or deployed them.

## Why AI coding agents struggle
Agents optimise for convenient correlations and often promote filenames,
versions, or hashes into causal claims.

## Itzako example
The extension artefact can be hashed, but no sealed metadata links that hash to
the current dirty source manifest.

## Kratos Agent Guard implementation
`ProvenanceLink` requires both exact source hash and HEAD for source-build proof.

## Trade-offs
Strict proof leaves more results `UNPROVEN`.

## Failure modes
Trusting directory names, timestamps, short commits, or versions.

## Practical exercise
Change an artefact filename without changing bytes and compare identity versus provenance.

## Transfer
Apply this to Kratos Forge export packages.

## Key takeaway
A hash answers “what bytes,” not “how they got here.”
