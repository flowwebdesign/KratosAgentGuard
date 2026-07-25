# Partial Observability

## Established engineering concept

Evidence proves only the boundary directly observed.

## Plain-language explanation

A reachable port shows that something accepted a connection; it does not reveal
which source or build produced it.

## Previous misunderstanding

The diagnostic snapshot mixed a restored explanation state with unrun capture
and generation checks.

## Itzako example

Ports 3000, 8000, and 3011 are hypotheses. A connection does not prove Itzako
source, behaviour, or user-visible correctness.

## Protection implemented

Every identity link carries an explicit evidence state, and reachability remains
an observation rather than a proof of identity.

## Trade-offs

Reports contain more `UNPROVEN` states and fewer convenient conclusions.

## Common failure modes

Treating HTTP 200, a log line, or a screenshot as end-to-end proof.

## Practical exercise

Run an unrelated service on an expected port and inspect the resulting report.

## Transfer

Apply this discipline to health checks, monitoring, and incident response.

## Takeaway

Availability is not identity.
