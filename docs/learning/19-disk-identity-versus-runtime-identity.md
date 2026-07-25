# Disk identity versus runtime identity

## Established technical concept
Bytes on disk and bytes selected by a running process are different evidence subjects.

## Plain-language explanation
A labelled folder is a candidate; it becomes runtime evidence only when the browser loads it and reports its identity.

## Why AI coding agents struggle
Agents often substitute a successful hash or build for proof that a runtime selected those bytes.

## Concrete Itzako example
The signed Itzako extension candidate can verify on disk while the normal Chrome profile still runs another build.

## Kratos Agent Guard implementation
Guard records the exact load path, browser command line, extension origin, and service-worker attestation readback.

## Trade-offs
Runtime observation adds browser automation and lifecycle complexity.

## Failure modes
Process launch without a worker, filesystem-only readback, or a mismatched candidate ID remains unproven or contradicted.

## Practical exercise
Compare a candidate hash with the hash returned by an extension-origin fetch.

## Transfer to another KratosLab project
Use the same separation for a container image on disk versus the digest running in a container.

## Key takeaway
Disk identity is necessary but never automatically runtime identity.
