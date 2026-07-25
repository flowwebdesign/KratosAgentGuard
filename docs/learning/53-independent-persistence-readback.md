# Lesson 53: Independent persistence readback

## Established concept

Verify persisted state through a separate read-only channel.

## Plain-language explanation

Do not ask the same write response to certify its own database effects.

## Why AI agents struggle

API JSON feels authoritative even when a transaction later rolls back or writes unexpected rows.

## Itzako example

Phase 2H forces PostgreSQL transactions read-only before inspecting operations, lessons, and artefacts.

## Guard implementation

`DatabaseReadbackEvidence` records database identity, migration head, schema contract hash, counts, and enforcement.

## Trade-offs

Readback requires database access discipline and credential redaction.

## Failure modes

Write-capable inspection transactions, stale replicas, broad queries, or credential leakage.

## Practical exercise

Prove `transaction_read_only=on` and compare one marked operation with its API identity.

## Transfer to another project

Use independent readback for inventory, ledgers, audit logs, and migrations.

## Key takeaway

Persistence is proven by readback, not intent.
