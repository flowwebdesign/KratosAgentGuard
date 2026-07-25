# ADR-0014: Guard-Owned Candidate Workspaces

- Status: Accepted
- Decision: snapshot and build only below the verifier's ignored `.work` root.
- Consequence: target builds, caches, dependencies and outputs remain zero.
