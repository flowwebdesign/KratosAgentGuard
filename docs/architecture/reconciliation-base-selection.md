# Reconciliation-base selection

Guard surveys bounded extension history from the observed branch. Every
candidate records ancestry, extension tree hash, path overlap, exact hashes,
changed/missing/extra paths, Manifest V3 compatibility, public-key
compatibility, worker compatibility, rationale, and contradictions.

Selection uses the newest ancestry candidate among the best byte-level matches
that preserves the public key and manifest contract. Directory naming and a
single numeric score cannot establish authority.
