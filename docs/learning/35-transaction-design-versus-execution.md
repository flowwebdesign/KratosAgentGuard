# 35. Transaction design versus transaction execution

## Established concept
A state machine can specify mutation safely without granting authority to run it.
## Plain-language explanation
Phase 2E writes the checklist, not the replacement.
## Why AI agents struggle
Detailed plans can be mistaken for permission.
## Itzako example
The design requires approval, closed Chrome, backups, attestation, journeys, and rollback.
## Guard implementation
`ExtensionPromotionTransaction.execution_method_present` is always false.
## Trade-offs
A separate authorised phase is required.
## Failure modes
Running atomic rename steps while merely designing them.
## Practical exercise
Mark every state that needs new human authority.
## Transfer
Separate database migration planning from production execution.
## Key takeaway
Design reduces risk; authority controls action.
