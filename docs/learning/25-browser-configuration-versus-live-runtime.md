# 25. Browser configuration versus live runtime

## Established technical concept
Persisted configuration and a running process are different evidence scopes.
## Plain-language explanation
A browser can remember an extension without currently running its worker.
## Why AI coding agents struggle
Agents often collapse nearby facts into one stronger claim.
## Itzako example
`Preferences` can identify Study Copilot but cannot prove its MV3 worker is active.
## Guard implementation
Configured identity and runtime-attestation verdicts are separate fields and gates.
## Trade-offs
Fail-closed reporting is less convenient but prevents false loaded-client claims.
## Failure modes
Treating an extension directory, enabled flag, or canary as live normal-profile proof.
## Practical exercise
Classify a manifest, worker URL, and runtime attestation by proof scope.
## Transfer
Apply the same distinction to deployed API configuration versus a serving revision.
## Key takeaway
Configuration answers “what should load”; runtime evidence answers “what is loaded”.
