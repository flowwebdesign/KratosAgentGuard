# Lesson 44: Change-impact analysis before behavioural edits

## Established concept

Trace entries, state transitions, requests, identities, persistence, and render boundaries before editing.
## Plain-language explanation

Find every route through the behaviour before choosing the smallest safe interception point.
## Why AI agents struggle

The first matching function may cover manual flow but miss restore or regeneration.
## Itzako example

The language guard already rejected display; only automatic bounded recovery was missing.
## Guard implementation

`BehaviouralChangeImpact` records paths, functions, states, operations, risks, and proof scope.
## Trade-offs

Analysis delays editing but prevents silent cross-component expansion.
## Failure modes

New messages, duplicate state machines, or backend changes without authority.
## Practical exercise

Draw automatic, manual, regenerate, and restore paths to their common render guard.
## Transfer

Apply this to retries, caching, authentication, and data migrations.
## Key takeaway

The best edit point is found by tracing the whole contract.
