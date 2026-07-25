# Network isolation during verification

## Established technical concept
Verification should minimise side effects and record attempted boundary crossings.

## Plain-language explanation
The canary may inspect itself but must not talk to Itzako, providers, or third parties.

## Why AI coding agents struggle
Extensions can make background calls invisible to a blank page and a passing UI check.

## Concrete Itzako example
Chrome uses a black-hole proxy while Playwright aborts and records HTTP, HTTPS, and WebSocket requests.

## Kratos Agent Guard implementation
The report distinguishes browser-level blocking from kernel-level isolation and counts product/provider operations.

## Trade-offs
Browser interception cannot prove packets were blocked at the operating-system boundary.

## Failure modes
Any non-allowlisted request fails the canary even when successfully blocked.

## Practical exercise
Trigger a fixture HTTP request and verify it is recorded and denied.

## Transfer to another KratosLab project
Use deny-by-default provider adapters during model or search evaluation.

## Key takeaway
Blocked attempts are still policy violations and must remain visible.
