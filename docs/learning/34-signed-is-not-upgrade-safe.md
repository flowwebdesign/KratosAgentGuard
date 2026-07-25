# 34. Signed software is not automatically upgrade-safe

## Established concept
A signature proves issuer and integrity, not compatibility or promotion authority.
## Plain-language explanation
Authentic software can still be the wrong lineage or break stored data.
## Why AI agents struggle
Cryptographic PASS results appear globally authoritative.
## Itzako example
The older sealed candidate is signed but differs in payload, worker, and ID continuity.
## Guard implementation
Promotion classification separately checks lineage and compatibility.
## Trade-offs
More evidence is required before using an otherwise valid candidate.
## Failure modes
Promoting on signature alone or silently downgrading.
## Practical exercise
List compatibility facts absent from a signature.
## Transfer
Apply this to container images and signed mobile packages.
## Key takeaway
Authenticity is necessary evidence, never complete upgrade proof.
