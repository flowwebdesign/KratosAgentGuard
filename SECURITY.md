# Security policy

## Supported version

Security fixes are applied to the latest `1.x` release. Older development
versions are not supported after v1.0.0.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include
private keys, credentials, browser data, product data, or unredacted evidence
in a public issue.

Reports should identify the affected version, operating system, command,
expected trust boundary, reproducible steps, and whether key or evidence
material may have been exposed.

## Security boundaries

Kratos Agent Guard is a local verifier. It writes only to its configured
per-user state and evidence roots. Registered folders are read-only observation
targets. The Guard does not authorise product changes, provider calls, browser
control, database writes, or automatic remediation.

Private Ed25519 keys are protected by the current user's Windows ACL or POSIX
permissions. They are not encrypted independently at rest. Compromise of the
user account or operating system is outside the v1 threat boundary.

Revoking a historical signing key deliberately causes evidence signed by that
key to fail closed. Keep exported evidence and trust bundles together.

Portable evidence is authentic only when verification receives the first
ledger signer key ID through a separate trusted channel. A key ID copied from
the same untrusted bundle proves self-consistency, not origin.
