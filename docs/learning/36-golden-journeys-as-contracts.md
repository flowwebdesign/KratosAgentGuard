# 36. Golden journeys as product contracts

## Established concept
End-to-end journeys specify observable product behaviour across boundaries.
## Plain-language explanation
Tests must cover what the learner does, what persists, and what reload restores.
## Why AI agents struggle
Unit success hides network, persistence, identity, and UI failures.
## Itzako example
Twelve Coursera, YouTube, language, auth, backend, and duplicate journeys are defined.
## Guard implementation
Each journey declares operations, costs, writes, visible output, readback, and rollback.
## Trade-offs
Permanent journeys require maintained fixtures and controlled provider budgets.
## Failure modes
Checking only HTTP success or one screenshot.
## Practical exercise
Write the reload/readback clause for a regeneration journey.
## Transfer
Use golden journeys for dashboard onboarding and billing.
## Key takeaway
A journey contract binds technical success to user-visible truth.
