# 30. Promotion readiness and rollback authority

## Established technical concept
Planning a mutation and possessing authority to execute it are separate capabilities.
## Plain-language explanation
A safe replacement plan is not permission to replace the user’s extension.
## Why AI coding agents struggle
Goal-oriented agents can treat a detailed plan as implied approval.
## Itzako example
Phase 2D records backup, ID stability, approval, attestation, rollback, and golden journeys only.
## Guard implementation
PromotionReadinessPlan has no execution method and reports blockers explicitly.
## Trade-offs
Promotion requires another phase and human approval.
## Failure modes
Reloading the extension, restarting Chrome, or overwriting the current path.
## Practical exercise
Write preconditions and rollback checks for a transactional extension promotion.
## Transfer
Use the same separation for database migrations and production deployments.
## Key takeaway
Readiness evidence narrows risk; it never grants mutation authority.
