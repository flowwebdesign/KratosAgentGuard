# Runtime attestation readback

The Manifest V3 service worker evaluates `chrome.runtime.getURL("kratos-build-attestation.json")`, fetches those bytes from its `chrome-extension://` origin, and calculates SHA-256 with Web Crypto. Guard then compares the returned bytes and claims with the on-disk sealed candidate and independently verifies canonical integrity, Ed25519 signature, and trusted signer.

A filesystem read is not accepted as runtime readback. Any candidate ID, payload hash, key ID, integrity, signature, or byte mismatch is contradictory evidence.
