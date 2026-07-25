# Lesson 52: Idempotency and canonical persistence

## Established concept

Repeated requests may occur, but canonical state must remain singular.

## Plain-language explanation

Two clicks should not create two lessons or two current explanations.

## Why AI agents struggle

Request success is easy to count; canonical persistence requires following identities and revisions.

## Itzako example

Duplicate Phase 2H triggers must resolve to at most one accepted operation and artefact transition.

## Guard implementation

Budgets cap duplicate attempts while operation evidence records exact IDs, states, lessons, and artefacts.

## Trade-offs

Idempotency adds keys and readback work but prevents costly duplicate side effects.

## Failure modes

New keys per retry, orphaned running operations, or multiple current revisions.

## Practical exercise

Submit one idempotency key twice and verify one canonical operation remains.

## Transfer to another project

Apply the pattern to orders, uploads, email sends, and job queues.

## Key takeaway

Count canonical transitions, not merely HTTP responses.
