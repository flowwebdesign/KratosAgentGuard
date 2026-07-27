# Lesson 58: Audit schemas and exclusive writer leases

## Established concept

Audit control state belongs outside the application migration stream and every write window needs an exclusive owner.

## Plain-language explanation

Keep synthetic leases and scenario ledgers in their own schema, then allow one bounded writer at a time.

## Why AI agents struggle

Agents may add test tables to product migrations or assume process ownership is equivalent to database write ownership.

## Itzako example

Migration 017 remains the application head while `kag_audit.writer_leases`, scenario tables, and identity records live in `kag_audit`.

## Guard implementation

Lease acquisition checks zero active leases and an exact activity baseline; release records a terminal outcome and expiry fails closed.

## Trade-offs

Exclusive leases reduce concurrency but make attribution and cleanup much clearer.

## Failure modes

Multiple writers, stale active leases, an unbounded TTL, product-schema drift, or readback using a write-capable role.

## Practical exercise

Attempt a second lease and a write through the read-only role; both should fail.

## Transfer to another project

Use this pattern for migration rehearsals, replay systems, and regulated test data.

## Key takeaway

Separate control data and exclusive write authority make audit evidence attributable.
