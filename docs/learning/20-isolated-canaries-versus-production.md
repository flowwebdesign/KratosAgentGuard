# Isolated canaries versus production

## Established technical concept
Evidence is valid only within the environment and identity scope observed.

## Plain-language explanation
A fresh test browser answers “can this candidate load?” rather than “is my everyday browser using it?”

## Why AI coding agents struggle
Successful test environments tempt agents to overstate production or user-profile readiness.

## Concrete Itzako example
The canary uses a new Guard-owned profile and never modifies or reads the normal Chrome profile.

Google Chrome process success did not prove that the chosen browser supported unpacked extension side-loading. The branded-Chrome canary failed before exercising the candidate runtime.

## Kratos Agent Guard implementation
Isolated and current-user loaded-client states are modelled separately; canary proof cannot satisfy the latter gate.

## Trade-offs
Isolation protects user state but cannot prove promotion.

## Failure modes
Reusing User Data, attaching to an existing PID, or copying cookies destroys the proof boundary.

## Practical exercise
Write two verdicts for one passing canary: isolated runtime and current user runtime.

## Transfer to another KratosLab project
Treat a staging deployment as evidence distinct from production.

## Key takeaway
Canary success is scoped capability evidence, not deployment evidence.
