# Independent Verification of AI Agents

## Established engineering concept

Independent controls should observe an agent without inheriting its mutation
authority.

## Plain-language explanation

The checker should be able to say what it saw without being able to “fix” the
subject during inspection.

## Previous misunderstanding

Bootstrap analysis crossed verifier and target boundaries before either was
independently modelled.

## Itzako example

Phase 1 may inspect filesystem and passive runtime signals but cannot change
Itzako files, processes, browser state, databases, or providers.

## Protection implemented

Read-only Git allowlists, bounded observations, before/after target snapshots,
and a target-write counter enforce the lane.

## Trade-offs

Read-only inspection cannot answer every runtime question and may require later
owner-mediated evidence.

## Common failure modes

Auto-remediation, hidden provider calls, process restarts, and credential
inspection.

## Practical exercise

Attempt to invoke a non-allowlisted Git subcommand through the adapter and
observe the policy rejection.

## Transfer

Use the same pattern for CI agents, coding assistants, and production operators.

## Takeaway

An independent verifier observes first and has no implicit repair permission.
