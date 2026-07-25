# Time of Check and Time of Use

## Established technical concept
Evidence can become stale between observation and action.

## Plain-language explanation
A file checked before inspection may change before the report is written.

## Why AI coding agents struggle
Agents often treat earlier evidence as permanently valid.

## Itzako example
The source tree is already dirty and may be active, so Phase 2A compares bounded
before and after witnesses.

## Kratos Agent Guard implementation
`MutationWitness` hashes Git state and real sentinel bytes at both boundaries.

## Trade-offs
User-space witnesses are bounded and cannot prevent writes.

## Failure modes
Repairing detected change, assigning blame, or claiming kernel-level prevention.

## Practical exercise
Edit an untracked file between witness captures.

## Transfer
Use witnesses around KratosLab release evidence collection.

## Key takeaway
Evidence needs a time boundary and change witness.
