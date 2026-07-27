# Lesson 55: Isolated audit environments versus canonical runtime

## Established concept

An isolated audit environment can prove product behaviour without acquiring authority over the canonical runtime.

## Plain-language explanation

Run real application code against a separate database, identity, ports, and process, then label the result for that boundary only.

## Why AI agents struggle

Agents often confuse realistic execution with production equivalence and silently broaden mutation authority.

## Itzako example

Phase 2I ran the sealed extension against backend port 18000 and `studypilot_kag_audit` while port 8000 and `studypilot_dev` remained protected.

## Guard implementation

Guard binds a signed backend build, exact database, synthetic subject, runtime owner file, and scoped lease before browser dispatch.

## Trade-offs

Isolation adds provisioning work and cannot prove canonical deployment or normal-profile behaviour.

## Failure modes

Reusing canonical secrets, sharing a database, claiming production proof, or stopping the wrong process.

## Practical exercise

List every resource in a test run and mark it isolated, canonical read-only, or prohibited.

## Transfer to another project

Use the same split for staging payment tests, migration rehearsals, and destructive data workflows.

## Key takeaway

Real code in an isolated environment is strong evidence, but only for the isolated environment.
