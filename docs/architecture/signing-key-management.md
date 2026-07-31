# Signing-Key Management

Private Ed25519 keys live in the operating system's native per-user data
directory:

- Windows: `%LOCALAPPDATA%\KratosAgentGuard\keys`
- Linux with XDG: `$XDG_DATA_HOME/kratos-agent-guard/keys`
- Linux fallback: `~/.local/share/kratos-agent-guard/keys`
- macOS: `~/Library/Application Support/KratosAgentGuard/keys`

Linux rejects a relative `XDG_DATA_HOME`. Initialisation applies a restrictive
Windows ACL or POSIX `0700` directory and `0600` private-key mode, refuses
unsafe storage, and never overwrites an existing key.

Rotation is explicit and requires a reason. Only raw public-key material,
fingerprint and key ID may enter a Guard-authorised public trust directory.
`key export-public --trust-directory <path>` permits an isolated Guard-owned
trust directory for CI and testing; it does not permit output outside the Guard
repository. A valid signature proves key possession; claim verification
remains independent.

v1 rotation writes the new private key only after creating a dual-signed
transition record. The outgoing and incoming keys sign identical canonical
bytes. Ledger verification accepts a signer change only when that transition
and both public keys are present and valid.

The replaced private key is not retained; historical verification requires
only its public key. An interrupted pre-commit temporary key is discarded
before a later rotation while the still-active key remains authoritative.

Revocation applies to historical keys after rotation. The active key cannot be
revoked directly; rotate it first, then revoke the retired identity. Revoked
signers deliberately make affected evidence fail closed. `key export-bundle`
exports public keys, rotation records, and revocation records but never private
material.
