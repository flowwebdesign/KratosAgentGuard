# Standalone operational mode

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
4. A successful statement consumes an exclusive replay marker in Guard-owned
   evidence storage.

The bundled synthetic producer generates an ephemeral Ed25519 private key. The
private key remains in memory and is never persisted; only the public trust
record is written. Its scope is always `GUARD_OWNED_SYNTHETIC`.

## Evidence ledger

Each JSONL entry contains a monotonic sequence, the previous entry hash, a
Guard signing-key identity, a signature over canonical unsigned fields, and an
integrity hash over the signed entry. Appends use an exclusive writer lock and
flush the entry to stable storage before releasing the lock.

Verification checks the complete sequence, every link, every entry hash, every
signature, and the exact trusted signer identity. Missing, malformed, tampered,
reordered, or untrusted evidence fails closed.

## Passive folder monitoring

Folder snapshots hash regular files in deterministic relative-path order. The
walker does not follow symbolic links and excludes common repository, virtual
environment, cache, and build-output directories. File-count and file-size
limits bound the operation.

The path policy resolves both the observed root and evidence destination. It
rejects any destination inside the observed root or its Git common directory;
evidence must remain under the Guard repository.

`monitor watch` is intentionally bounded by an iteration count. It records a
signed start event and signed drift events but never changes the observed
folder.

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
