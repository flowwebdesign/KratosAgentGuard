# Lesson 49: Concurrency isolation versus global quiescence

## Established concept

Prove one marked namespace without requiring every other user to stop.

## Plain-language explanation

Follow records owned by one synthetic subject and marker while treating global count changes as context.

## Why AI agents struggle

Agents often subtract global before/after totals and incorrectly attribute unrelated concurrent activity.

## Itzako example

Phase 2H follows only `KAG-2H-*` sources, lessons, operations, and artefacts.

## Guard implementation

`ConcurrentActivityEvidence` separates marker-scoped counts from global contextual counts.

## Trade-offs

Marker isolation requires strong identifiers but avoids disruptive database quiescence.

## Failure modes

Missing owner filters, reused markers, clock-only attribution, or global-count subtraction.

## Practical exercise

Add unrelated rows during a synthetic run and prove they do not enter marker-scoped evidence.

## Transfer to another project

Use namespace isolation for payment sandboxes, webhook tests, and multi-tenant migrations.

## Key takeaway

Strong attribution is better than stopping the world.
