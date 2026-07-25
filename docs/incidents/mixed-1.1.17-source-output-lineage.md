# Incident: Mixed `1.1.17` source/output lineage

## Summary
The normal-profile Itzako extension was configured from an exact operational
`1.1.17` directory whose containing Study Pilot worktree had extensive tracked
and untracked changes. The operational bytes were sealable, but a clean
source-to-build lineage was not established.

## Impact
The extension identity, payload, rollback package, signature, and isolated
runtime could be proven independently. Those proofs did not establish that a
successor could be rebuilt safely from the dirty shared repository.

## Evidence boundary
The configured payload was
`709a5749bf2bc3653cce8c92ae0538b6d0961154ecfba9e3181a7c9d78804147`,
version `1.1.17`, worker `serviceWorker.js`, and key-derived ID
`mofhgdnkngbpbcihjkhoelogkjolaidn`. Source authority remained partial because
direct runtime files, generated identity output, and build metadata coexisted.

## Contributing conditions

- The configured path was inside a dirty shared Git common directory.
- Some operational files differed from or were absent in committed history.
- A reference candidate belonged to a different lineage and was not promotion
  eligible.
- Normal-profile mutation was not authorised.

## Corrective action
Phase 2F maps every payload file, selects a byte-supported historical base,
creates a separate-object-database Guard clone, reconstructs an exact committed
`1.1.17` baseline, preserves it in a signed verified bundle, and builds a
compatibility-only `1.1.18` candidate.

## Preserved boundaries
The configured extension, Study Pilot worktree and Git common directory, normal
Chrome, datastores, providers, and known external Chrome-for-Testing residue
remain unchanged. Promotion authority is `NONE`.

## Remaining action
The first remaining blocker after a successful compatibility successor is
`BEHAVIOURAL_SUCCESSOR_CHANGE_NOT_IMPLEMENTED`. A later phase must implement and
prove the real behavioural correction against this clean lineage.
