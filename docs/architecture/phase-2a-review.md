# Phase 2A Threat Review

## Verified implementation facts

Phase 1 accepted arbitrary output paths, used an immediate-child metadata
snapshot, stored raw command output, redacted only a narrow set of tokens,
reported an unqualified source pass, and mapped ports without owning-process
identity. It did not model canonical path containment, deterministic manifests,
artefact provenance, configured versus loaded clients, or evidence import trust.

## Observed runtime facts

At the Phase 2A baseline, the verifier was clean at `f5b9cdc6`, the target was
dirty at `b7529f00`, and listeners existed on 3000, 8000, and 3011. These facts
do not establish source-build-runtime equivalence.

## Inferences

The extension directory is a candidate artefact because it contains a manifest
and static build-info file. Its name and version are not proof that a build
process produced it.

## Limitations

User-space mutation witnesses are bounded, Docker access may be unavailable,
Chrome live state is not inspected, and health responses are not behavioural
proof.

## Changes implemented

Phase 2A adds protected output roots, a Git-plus-sentinel witness, bounded
redacted command evidence, deterministic manifests, static artefact parsers,
psutil runtime ownership, strict Docker commands, allowlisted HTTP observation,
qualified gates, and integrity-checked loaded-client evidence import.
