# ADR-0011: Component-Scoped Build-Input Manifests

- Status: Accepted
- Decision: attest exactly the component bytes copied, not only repository state.
- Consequence: unrelated monorepo components and sensitive files are excluded.
