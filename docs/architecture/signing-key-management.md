# Signing-Key Management

Private Ed25519 keys live only under `%LOCALAPPDATA%\KratosAgentGuard\keys`.
Initialisation refuses unsafe ACLs and never overwrites an existing key.
Rotation is explicit and requires a reason. Only raw public-key material,
fingerprint and key ID may enter `trust/keys`. A valid signature proves key
possession; claim verification remains independent.
