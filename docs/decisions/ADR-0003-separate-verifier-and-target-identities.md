# ADR-0003: Separate Verifier and Target Identities

- Status: Accepted
- Decision: model verifier, target source, build, runtime, and loaded client separately.
- Context: each can drift independently.
- Consequence: links require evidence and default to `UNPROVEN`.
