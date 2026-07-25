# Lesson 47: Bounded retries, idempotency, and duplicate prevention

## Established concept

Retry allowance belongs to an operation flow and must preserve identity.
## Plain-language explanation

Try one repair automatically, then stop visibly and let the learner decide.
## Why AI agents struggle

Recursive helpers can accidentally reset counters and create duplicate requests.
## Itzako example

The first mismatch permits one existing regeneration transition; a second mismatch is retryable failure.
## Guard implementation

The policy carries retry count, lesson identity, operation identity, terminal state, and request count.
## Trade-offs

One attempt may not repair every output, but it bounds cost and duplication.
## Failure modes

Infinite recursion, global counters, duplicate lessons, or hidden failure.
## Practical exercise

Prove two mismatches create one repair request and no third request.
## Transfer

Apply to payments, queues, and conflict resolution.
## Key takeaway

Bound retries by identity and make exhaustion visible.
