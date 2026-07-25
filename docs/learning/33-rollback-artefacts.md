# 33. Rollback artefacts and restoration proof

## Established concept
A backup is useful only when its restored content is independently verifiable.
## Plain-language explanation
Hash the archive and prove it recreates the original payload exactly.
## Why AI agents struggle
Creating an archive is easier than testing its restoration identity.
## Itzako example
The rollback ZIP excludes delivery attestation bytes and restores payload `709a...`.
## Guard implementation
Deterministic archive entries are reconstructed into a bounded payload manifest.
## Trade-offs
Detached evidence adds storage but avoids contaminating original identity.
## Failure modes
Extra files, missing files, or restoring the attested delivery layer.
## Practical exercise
Add one archive entry and observe verification fail.
## Transfer
Apply restoration proof to migrations and deployment bundles.
## Key takeaway
Rollback is a verified state transition, not merely a file copy.
