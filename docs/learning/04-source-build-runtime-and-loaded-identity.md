# Source, Build, Runtime, and Loaded Identity

## Established engineering concept

Source, artefact, executing runtime, and loaded client are distinct identities
connected only by evidence.

## Plain-language explanation

Code can be built, copied, launched, and loaded at different times; each step can
drift.

## Previous misunderstanding

The loaded extension identifier was incorrectly treated as if it must identify
the verifier repository.

## Itzako example

The extension build string is target loaded-client context. Its source and build
links remain unproven until independently observed.

## Protection implemented

Four target models record source, build, runtime, and loaded-client states and
links independently.

## Trade-offs

Full proof requires manifests, process evidence, and loaded-client evidence
rather than one identifier.

## Common failure modes

Assuming source equals runtime, assuming a port identifies a build, or trusting
prior loaded-client context as current.

## Practical exercise

Create a report with a known source HEAD but no build manifest and inspect which
states remain unproven.

## Transfer

Use the model for containers, desktop apps, browser extensions, and firmware.

## Takeaway

Record identity transitions; never assume them.
