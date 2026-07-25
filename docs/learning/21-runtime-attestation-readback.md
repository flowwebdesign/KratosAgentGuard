# Runtime attestation readback

## Established technical concept
Runtime attestation binds a running component to signed build claims through in-context readback.

## Plain-language explanation
The extension must fetch its own signed receipt; rereading the file from Windows proves nothing new.

## Why AI coding agents struggle
Filesystem access is easier and can look equivalent in logs despite lacking runtime selection proof.

## Concrete Itzako example
The Manifest V3 worker calls `chrome.runtime.getURL` and fetches `kratos-build-attestation.json`.

## Kratos Agent Guard implementation
Guard hashes returned bytes, parses claims, recalculates canonical integrity, and verifies Ed25519 trust independently.

## Trade-offs
The worker must activate safely and expose a packaged attestation.

## Failure modes
Wrong origin, altered bytes, candidate ID drift, payload drift, or untrusted key returns contradicted.

## Practical exercise
Alter one returned claim and observe which verification boundary fails first.

## Transfer to another KratosLab project
Have a service expose a signed build descriptor from its running process.

## Key takeaway
Readback proves what the runtime can return from its own packaged origin.
