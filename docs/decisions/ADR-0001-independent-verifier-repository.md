# ADR-0001: Independent Verifier Repository

- Status: Accepted
- Decision: Kratos Agent Guard has its own Git and package authority.
- Context: Itzako is an external target, not a source dependency.
- Consequence: target repositories and builds are never required to match the
  verifier repository.
