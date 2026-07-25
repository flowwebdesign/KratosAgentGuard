# Verifier Versus Target

## Established engineering concept

An assurance tool must have an identity and authority boundary independent of
the system it inspects.

## Plain-language explanation

The guard is the measuring instrument; Itzako is the thing being measured.
They need not come from the same repository.

## Previous misunderstanding

The earlier run tried to match an Itzako extension build to the new guard
repository and treated the expected mismatch as a blocker.

## Itzako example

`extension-1.1.17-8e9f11feeaa6f684` is prior target context, never the verifier's
package or Git identity.

## Protection implemented

Separate strict `VerifierIdentity` and target identity models prevent accidental
field reuse.

## Trade-offs

Separation creates more explicit evidence fields but prevents false authority
claims.

## Common failure modes

Shared build fields, inferred repository links, and treating target availability
as verifier authority.

## Practical exercise

Inspect a second repository and compare the two repository roots in the JSON
report.

## Transfer

The same split applies to security scanners, deployment auditors, and backup
verifiers.

## Takeaway

Never identify the measuring instrument by the identity of its subject.
