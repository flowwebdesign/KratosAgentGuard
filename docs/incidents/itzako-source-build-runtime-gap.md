# Itzako Source-Build-Runtime Gap

The current source repository can be identified independently, but its dirty
working bytes are not sealed into the extension candidate. `buildInfo.js`
contains a short historical commit and version, while no observed manifest
contains both the current source-manifest hash and exact HEAD. Processes can be
mapped to ports, but no runtime evidence links them to exact artefact bytes.
Configured and live extension identity remain unproven.

The first missing boundary is a sealed build attestation containing source HEAD,
source-manifest hash, artefact-manifest hash, build ID, and integrity protection.
Phase 2B should emit that attestation during builds and expose the resulting
identity through a read-only runtime endpoint.
