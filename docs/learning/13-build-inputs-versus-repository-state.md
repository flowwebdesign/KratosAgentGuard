# Build Inputs Versus Repository State

## Established technical concept
Build provenance covers exact component inputs, not merely a repository commit.
## Plain-language explanation
A monorepo contains more bytes than one extension build consumes.
## Why AI coding agents struggle
Agents often use HEAD as a shortcut for dirty working-tree and component state.
## Itzako example
The extension input is `Study_master/extension`, not the backend or dashboard.
## Kratos Agent Guard implementation
`BuildInputManifest` lists every copied component byte and configuration hash.
## Trade-offs
Input discovery must be maintained when component structure changes.
## Failure modes
Copying secrets, unrelated components, caches or historical output.
## Practical exercise
Add an unrelated dashboard file and confirm the component hash is unchanged.
## Transfer
Use component manifests for Kratos Forge export builders.
## Key takeaway
Attest what the build consumed, not everything nearby.
