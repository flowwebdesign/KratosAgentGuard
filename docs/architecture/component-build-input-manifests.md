# Component Build-Input Manifests

The extension input manifest is narrower than repository identity. It records
every copied file and hash, current target HEAD and dirty/staged state,
repository-manifest reference, component configuration hashes, exclusions and
the mutation-witness reference. Secret-like files, keys, databases, logs,
caches, dependencies and unrelated components are excluded.
