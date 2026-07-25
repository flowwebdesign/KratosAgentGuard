# Qualified Evidence and Partial Passes

## Established technical concept
Verdicts must name the exact claim and scope they satisfy.

## Plain-language explanation
Passing source identity does not pass build, runtime, or loaded-client identity.

## Why AI coding agents struggle
Single green labels compress uncertainty and encourage overclaiming.

## Itzako example
Source authority can pass while the full chain remains incomplete.

## Kratos Agent Guard implementation
Gate IDs, scopes, blockers, uncertainties, exit codes, and first failing
boundaries keep partial results explicit.

## Trade-offs
Automation must choose the correct gate level.

## Failure modes
An unqualified `PASS`, treating health as behaviour, or hiding first failure.

## Practical exercise
Compare source and runtime gate exit codes on the same report.

## Transfer
Use qualified release gates across all KratosLab projects.

## Key takeaway
A useful pass always says exactly what passed.
