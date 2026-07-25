# Source-to-artefact mapping

Phase 2F hashes every operational payload file and assigns one explicit role:
direct runtime source, static asset, generated output, build metadata, delivery
attestation, or unknown. Execution-critical unknowns and generated outputs
without a committed generator fail closed.

Generated claims bind output paths to claimed inputs, generator configuration,
dependency inputs, deterministic-reproduction state, evidence references, and
uncertainty. The mapping describes operational provenance; it does not invent
historical authorship.
