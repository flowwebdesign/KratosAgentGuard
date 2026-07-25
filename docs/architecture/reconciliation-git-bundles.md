# Reconciliation Git bundles

After exact baseline equivalence, Guard commits the local reconciliation branch
and creates a deterministic-scope Git bundle under the run workspace. Bundle
verification must succeed and its branch tip must equal the recorded
reconciliation commit.

A signed Ed25519 lineage envelope binds the branch, commit, parent, tree,
reproduced payload, selected base, bundle hash, and bundle tip. The bundle is a
durable recovery artefact; it grants no remote-push or promotion authority.
