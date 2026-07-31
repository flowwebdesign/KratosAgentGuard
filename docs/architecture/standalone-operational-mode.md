# Standalone operational mode

## v1 product contract

Kratos Agent Guard v1 is a local, per-user, read-only verifier for explicitly
registered folders and signed runtime statements. It is complete when the
installed wheel can initialise, register, monitor, report health, rotate trust,
export evidence, and independently verify that evidence on Windows and Linux.

The v1 command contract is:

- `standalone init`
- `standalone folder add|list|remove`
- `standalone run`
- `standalone status`
- `standalone health`
- `standalone service-template`
- `standalone evidence checkpoint|export|verify|import`
- `key inspect|rotate|revoke|export-bundle`

Successful commands return exit code `0`. Drift comparisons return `2`.
Trust, readiness, verification, configuration, and authority blockers return
`3`. Invalid command-line input uses Typer's standard usage exit code.

Existing top-level commands remain compatible. New schemas are additive:
`configuration.v1`, `key-rotation.v1`, `key-revocation.v1`,
`monitor-health.v1`, and `evidence-bundle.v1`. Existing
`evidence-ledger-entry.v1` records require no rewrite.

## Purpose

Standalone mode makes Kratos Agent Guard useful before any product integration
exists. The Guard can establish its own trust root, retain tamper-evident
evidence, observe explicitly supplied folders without writing to them, and
prove its runtime-attestation protocol against a synthetic producer it owns.

It does not select or infer a product target. A target path enters scope only
when an operator explicitly supplies it to a monitoring command.

## Trust boundaries

The verifier and producer remain separate identities:

1. The Guard signs a short-lived challenge with its established Ed25519 key.
2. A producer returns the exact challenge identifier and nonce, plus build and
   artifact identities, in its own signed statement.
3. Verification requires explicit Guard and producer public-key files.
4. The first successful statement atomically consumes an exclusive,
   challenge-keyed replay marker in Guard-owned evidence storage.

The bundled synthetic producer generates an ephemeral Ed25519 private key. The
private key remains in memory and is never persisted; only the public trust
record is written. Its scope is always `GUARD_OWNED_SYNTHETIC`.

## Evidence ledger

Each JSONL entry contains a monotonic sequence, the previous entry hash, a
Guard signing-key identity, a signature over canonical unsigned fields, and an
integrity hash over the signed entry. Appends use an exclusive writer lock and
flush the entry to stable storage before releasing the lock.

Verification checks the complete sequence, every link, every entry hash, every
signature, and the exact trusted signer identity. Append also re-verifies every
existing entry against the established local signing key before extending the
chain. Missing, malformed, tampered, reordered, or untrusted evidence fails
closed.

Historical public keys live in the protected local trust bundle. A transition
to a new signing key is accepted only when both the outgoing and incoming keys
sign the same rotation record. Portable verification requires the public keys
and rotation records included in the evidence bundle. Revoked signers fail
closed, including historical entries.

Evidence export never includes private keys. A bundle manifest binds every
member name, size, and SHA-256 digest. Verification rejects absolute paths,
parent traversal, duplicate or undeclared members, oversized archives,
malformed archives, missing members, digest changes, untrusted transitions,
revoked keys, and invalid ledger chains.

Independent verification and import also require
`--expected-trust-anchor-key-id`, pinned through a channel separate from the
bundle. This value must match the first ledger signer. Without that external
pin the bundle can prove only internal self-consistency, not authenticity
against wholesale substitution, and verification fails closed.

`standalone evidence checkpoint` appends a signed statement binding the current
ledger head. Import verifies the complete portable bundle before copying it
into Guard-owned evidence storage and refuses duplicate imports. Export,
checkpoint, and import are explicit retention operations; no automatic
retention policy deletes or rewrites evidence.

Writer locks contain a random ownership token, process identity, and UTC
creation time. Cleanup removes only the caller's own token. A well-formed lock
older than five minutes may be recovered only when its recorded process no
longer exists; live, recent, malformed, or changing locks remain fail-closed.

## Fail-closed status

The installed `standalone status` command returns success only when all of
these are true:

- strict per-user configuration loads successfully;
- at least one monitored folder is explicitly registered;
- the signing key has a proven restrictive storage boundary;
- the complete multi-key evidence ledger verifies;
- monitor health is running or stopped cleanly.

The legacy `standalone-status` command returns success only when all of these
repository-checkout controls are true:

- the Guard repository identity is proven and the working tree is clean;
- the local signing key has a proven restrictive storage boundary;
- the evidence ledger exists and every link and signature verifies against an
  explicit or current exported public trust key.

The status output includes the verified entry count, head hash, trust path, and
exact blockers. A merely present ledger is never reported as ready. A
configured folder is recorded as `CONFIGURED_UNINSPECTED`; status does not read
it. Runtime attestation remains `PROTOCOL_AVAILABLE_UNATTESTED` until separately
exercised, and the normal loaded-user runtime remains `UNPROVEN`.

## Passive folder monitoring

Folder snapshots hash regular files in deterministic relative-path order. The
walker does not follow symbolic links and excludes common repository, virtual
environment, cache, and build-output directories. File-count and file-size
limits, including an aggregate byte ceiling, bound the operation.

The installed path policy rejects any monitored folder that contains, or is
contained by, the Guard's configuration, keys, trust records, ledger, or other
Guard-owned state. This prevents monitoring from causing writes inside the
observed target. Legacy checkout commands separately reject evidence output
inside the observed root or its Git common directory.

`monitor watch` is intentionally bounded by an iteration count. It records a
signed start event and signed drift events but never changes the observed
folder.

The installed `standalone run` command uses the same bounded walker with strict
per-user configuration. It owns an exclusive process lock, records start and
stop events, writes heartbeats atomically, diagnoses stale or corrupt state,
and never follows symlinks. Each folder baseline is signed and persisted so
drift that occurs between clean scheduled runs is detected; a corrupt,
substituted, or revoked baseline fails closed. Omit `--iterations` for
continuous operation or use a positive value for bounded proof and scheduled
operation.

## Threat model and non-goals

The Guard defends against evidence tampering, replay, key substitution,
untrusted key transitions, revoked historical signers, concurrent writers,
stale or malformed locks, archive traversal, output containment violations,
and silent configuration ambiguity.

The v1 boundary assumes the current operating-system user and kernel are not
compromised. Private keys rely on Windows ACLs or POSIX permissions and are not
separately encrypted. The Guard is not a remediation agent, browser controller,
provider client, database writer, hosted service, or product deployment tool.
Registered folders remain external read-only observation targets.

## Backup, upgrade, and removal

Back up the complete per-user `KratosAgentGuard` or `kratos-agent-guard`
directory while the monitor is stopped. Keep configuration, ledger, trust
records, and private keys together. Public evidence bundles are independently
portable but cannot restore the private signing identity.

Upgrading from 0.10 retains existing ledger entries. Run `standalone init` to
create v1 configuration and export the current public key into the new trust
bundle. Removal is intentionally manual: stop the supervisor, uninstall the
Python package, then preserve or explicitly archive the per-user data
directory. No command silently deletes keys or evidence.

Generate a reviewed supervisor definition with `standalone service-template`.
The Linux template uses systemd hardening and a per-user writable data path.
The Windows template registers a per-user scheduled task only when the operator
explicitly runs the generated PowerShell script.

Release artifacts are built twice against the same Git source timestamp and
must be byte-identical. The release carries `SHA256SUMS`, an SPDX 2.3
dependency SBOM, and GitHub artifact attestations. Verify a downloaded file
with its checksum and, when the GitHub CLI is available:

```text
gh attestation verify <artifact> --repo flowwebdesign/KratosAgentGuard
```

## Claims and limitations

A passing synthetic attestation establishes only that the Guard's protocol and
verification logic work for a Guard-owned fixture. It cannot establish:

- the current normal-browser profile;
- the extension or service-worker bytes loaded there;
- product repository, backend, database, or provider state;
- authorization to mutate or promote any target.

Those remain external proof boundaries. Even a valid external response proves
only the scope bound into that producer's trust contract. Until loaded-profile
ownership and runtime binding are independently verified,
`current_user_loaded_runtime_state` remains `UNPROVEN`,
`UNPROVEN_EXTERNAL_ATTESTATION_SCOPE`, or `UNPROVEN_SYNTHETIC_SCOPE`.

Each signed challenge is consumable exactly once. Re-signing a new statement
with a new statement ID or producer key cannot reuse an already consumed
challenge.
