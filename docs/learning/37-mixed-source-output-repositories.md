# Lesson 37: Mixed source/output repositories

## Established technical concept
Source trees can contain authored code, generated runtime files, metadata, and
untracked delivery output at the same time. Git membership does not prove a
file's role.

## Plain-language explanation
A folder can be both a workshop and a shipping box. Before rebuilding it, label
each item by what it is and how it was produced.

## Why AI coding agents struggle
Agents often infer authority from names such as `src`, `dist`, or `canonical`.
Those are hints, not evidence, especially in a dirty shared worktree.

## Itzako example
The operational `1.1.17` extension contains direct JavaScript, static HTML and
images, `buildInfo.js`, `BUILD_IDENTITY.json`, and freeze metadata. The last
three cannot all be treated as ordinary authored source.

## Guard implementation
`SourceArtifactMapping` records a classification, digest, size, execution
criticality, evidence references, and uncertainty for every payload file.
Generated claims also name the generator and inputs.

## Trade-offs
Classification costs time and may block work when provenance is incomplete. It
prevents a faster but unauditable copy from becoming false source authority.

## Failure modes
Filename-only classification, ignoring untracked runtime files, treating
generated stamps as authored code, and allowing an execution-critical
`UNKNOWN`.

## Practical exercise
Take a build directory and classify every file. For each generated output,
identify the exact generator and frozen inputs.

## Transfer to another project
Apply the same method to compiled frontends, generated API clients, firmware
images, or database migration bundles.

## Key takeaway
Map file roles before claiming that an operational artefact is reproducible
source.
