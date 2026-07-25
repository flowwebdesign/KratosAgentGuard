# ADR-0018: Runtime attestation readback

Status: Accepted.

Require the extension runtime to fetch its packaged attestation from its own origin. Filesystem-only reads are insufficient. This adds activation complexity but links loaded runtime identity to signed build claims.
