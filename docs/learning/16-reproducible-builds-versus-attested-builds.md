# Reproducible Builds Versus Attested Builds

## Established technical concept
Attestation records one observed build; reproducibility compares independent builds.
## Plain-language explanation
A signed build can be genuine even if repeating it produces different bytes.
## Why AI coding agents struggle
Agents use “signed” and “reproducible” as interchangeable quality labels.
## Itzako example
Two static-copy candidates are compared by payload hashes excluding attestations.
## Kratos Agent Guard implementation
`ReproducibilityResult` reports equality or exact differing paths independently.
## Trade-offs
Double builds cost time and storage.
## Failure modes
Including timestamps or signatures in the payload comparison.
## Practical exercise
Insert a timestamp fixture and inspect the first nondeterministic boundary.
## Transfer
Compare repeated KratosLab website release bundles.
## Key takeaway
Provenance says what happened; reproducibility says whether it happens identically again.
