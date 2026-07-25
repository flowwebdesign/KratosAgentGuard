# 31. Operational baseline versus known-good baseline

## Established concept
Operational use and behavioural correctness are independent claims.
## Plain-language explanation
The installed extension is what Chrome uses, not necessarily a proven-good product.
## Why AI agents struggle
Agents often convert “currently used” into “approved”.
## Itzako example
Version 1.1.17 is the configured rollback baseline while behaviour remains UNPROVEN.
## Guard implementation
`OperationalBaselineIdentity` separates payload, runtime, and behavioural states.
## Trade-offs
Rollback preserves the current state even when its product quality is incomplete.
## Failure modes
Labelling a configured artefact `KNOWN_GOOD` without golden journeys.
## Practical exercise
Classify configuration, runtime, and behavioural evidence independently.
## Transfer
Use the distinction for deployed services and database snapshots.
## Key takeaway
Operational continuity is not behavioural certification.
