# Provenance Chain

Kratos Agent Guard models source bytes, artefact bytes, runtime identity, and
loaded-client identity separately. Exact hashes identify bytes but do not prove
who produced or loaded them. A source-to-build pass requires matching source
HEAD and source-manifest hash. A build-to-runtime pass requires an immutable
artefact or image identity linked to the running process or container.
