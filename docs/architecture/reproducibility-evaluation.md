# Reproducibility Evaluation

Two isolated builds from the same snapshot are compared by payload manifest.
Attestations are excluded from payload identity, preventing signature time and
candidate ID from creating circular or false nondeterminism. Equal payloads
prove observed reproducibility; different paths are reported without modifying
the target or repairing outputs.
