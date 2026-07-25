# Digital Signatures and Trust Roots

## Established technical concept
A signature proves possession of a private key; trust policy identifies authorised signers.
## Plain-language explanation
Anyone can sign, but only approved public keys establish your trust root.
## Why AI coding agents struggle
Agents collapse signature validity, signer trust and claim truth into one Boolean.
## Itzako example
The local Ed25519 key signs the candidate, while each source and artefact claim is rechecked.
## Kratos Agent Guard implementation
Private keys stay in restrictive LocalAppData storage; public keys live in `trust/keys`.
## Trade-offs
Key rotation, backup and revocation require operational discipline.
## Failure modes
Unsafe ACLs, silent replacement, unknown signers or private keys in Git.
## Practical exercise
Verify the attestation with a different public key.
## Transfer
Use trust roots for Kratos Forge package attestations.
## Key takeaway
Valid signature, trusted signer and supported claims are separate proofs.
