# Synthetic token and tenant isolation

The only Phase 2I identity is classification `SYNTHETIC_AUDIT_IDENTITY`, subject `kag-phase2i`, tenant `kag-audit`, audience `itzako-kag-audit`, and scope `audit:golden-journeys`.

The token is valid only in audit mode and only against the isolated database. It has no normal-user association, email delivery, billing, invitation, production membership, or normal-browser session. Guard stores the token using Windows DPAPI and exposes only its SHA-256 fingerprint.

The sealed extension receives the token through its existing storage and runtime-identity contracts inside a fresh Guard-owned profile. The logged-out journey removes only that isolated token and proves zero writes.
