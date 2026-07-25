# Build Attestation

The signed statement contains portable logical identities for source HEAD,
repository and component manifests, controlled build policy, payload identity,
builder identity and limitations. Canonical JSON excludes `signature` and
`integrity_sha256`; Ed25519 signs that stable payload. Verification reports
schema, integrity, signature, signer trust, source, input and artefact claims
separately.
