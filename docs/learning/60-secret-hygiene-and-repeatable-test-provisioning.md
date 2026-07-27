# Lesson 60: Secret hygiene and repeatable test provisioning

## Established concept

Repeatable provisioning should persist secret identities without exposing secret values.

## Plain-language explanation

Store credentials in an operating-system-protected store, pass them only to scoped processes, and report fingerprints for comparison.

## Why AI agents struggle

Debugging pressure makes printing environment variables or embedding credentials in fixtures tempting.

## Itzako example

Guard retains PostgreSQL credentials and the synthetic token under a Phase 2I DPAPI namespace while evidence records only token and contract hashes.

## Guard implementation

Provisioning is idempotent around one database and identity; commands load secrets just in time and redact them from models and runtime identity endpoints.

## Trade-offs

Machine-bound secret protection limits portability and requires explicit reprovisioning on another host.

## Failure modes

Committing tokens, printing subprocess environments, returning secrets from diagnostics, or creating a new identity on every retry.

## Practical exercise

Re-run identity verification and prove the fingerprint is stable while the raw token never appears in logs or reports.

## Transfer to another project

Apply the pattern to database passwords, signing keys, and CI service credentials.

## Key takeaway

Repeatability comes from stable secret references and fingerprints, not visible secret values.
