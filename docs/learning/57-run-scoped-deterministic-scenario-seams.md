# Lesson 57: Run-scoped deterministic scenario seams

## Established concept

Deterministic failure scenarios must be isolated by both run and operation identity.

## Plain-language explanation

The same named scenario should produce a fixed sequence for one operation without sharing a mutable global counter with another run.

## Why AI agents struggle

Convenient global mocks create order-dependent tests and can accidentally affect normal traffic.

## Itzako example

`wrong_then_correct` returns German then English; `wrong_then_wrong` returns German twice and never permits a third attempt.

## Guard implementation

Scenario headers are injected only in Guard Chromium and require audit mode, synthetic claims, an exact marker, and an active matching lease.

## Trade-offs

The seam is more complex than a static fake response but produces repeatable concurrency-safe evidence.

## Failure modes

Global counters, missing marker checks, provider fallback, unbounded retries, or scenario use by normal users.

## Practical exercise

Run two operations with the same scenario under different markers and prove their attempt sequences do not interact.

## Transfer to another project

Use scoped scenarios for payment declines, retry queues, and timeout recovery.

## Key takeaway

Determinism needs an explicit scope, not merely predictable sample data.
