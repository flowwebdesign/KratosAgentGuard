# Lesson 54: External drift observation and attribution

## Established concept

Observation and attribution are different claims.

## Plain-language explanation

You may prove bytes changed without knowing who changed them.

## Why AI agents struggle

The current task is a tempting but unsupported explanation for any nearby drift.

## Itzako example

Phase 2G observed Study Pilot changes while issuing zero Study Pilot mutation commands.

## Guard implementation

Each changed path receives a runtime classification while attribution remains `UNPROVEN`.

## Trade-offs

Fail-closed attribution is less narratively satisfying but forensically sound.

## Failure modes

Blame from timing alone, broad history audits, cleanup, or ignoring runtime overlap.

## Practical exercise

Classify changed paths against process cwd, mounts, configured extension path, and reload mode.

## Transfer to another project

Use this method for CI drift, shared staging environments, and incident response.

## Key takeaway

Say what changed; prove who changed it separately.
