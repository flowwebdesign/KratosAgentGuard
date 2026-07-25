# Compatibility-successor constraints

The compatibility successor starts at the reconciliation commit. Its source
delta is limited to the manifest version and executable identity metadata:
`manifest.json`, `buildInfo.js`, and `BUILD_IDENTITY.json`.

Static comparison requires equality for the public key, Manifest V3, worker,
permissions, host permissions, content scripts, external connections, commands,
web-accessible resources, and every product-behaviour file. The sealed delivery
adds the Guard attestation without changing source behaviour. Promotion remains
outside this component.
