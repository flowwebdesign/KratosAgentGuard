# 26. Privacy-bounded profile inspection

## Established technical concept
Data minimisation limits collection to fields necessary for a declared purpose.
## Plain-language explanation
Read only the few browser metadata files needed to identify the extension.
## Why AI coding agents struggle
Broad filesystem discovery is easy and over-collects private state.
## Itzako example
Guard copies Local State, Preferences, Secure Preferences, and static extension metadata only.
## Guard implementation
An allowlist excludes History, Cookies, Login Data, storage, sessions, caches, and page content.
## Trade-offs
Some identity questions remain unproven without private data, by design.
## Failure modes
Copying a whole profile or persisting unrelated extension settings.
## Practical exercise
Design the smallest field allowlist needed to select a profile.
## Transfer
Use bounded configuration reads when inspecting dashboard or provider credentials.
## Key takeaway
Evidence is stronger when its collection boundary is explicit and minimal.
