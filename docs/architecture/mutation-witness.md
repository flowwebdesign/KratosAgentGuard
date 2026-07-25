# Mutation Witness

The witness compares porcelain-v2 status, tracked diff, staged diff, conflicted
paths, untracked-path manifests, configured sentinel hashes, and root metadata.
Existing dirty state is allowed when unchanged. A difference yields
`TARGET_CHANGED_DURING_INSPECTION`; the guard does not assign blame or repair
state. Coverage is bounded and is not kernel-level write prevention.
