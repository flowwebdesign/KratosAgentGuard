# Itzako build-to-runtime gap

Phase 2B proved a signed, reproducible source-to-build chain but intentionally stopped before runtime. The missing boundary was evidence that a browser selected those exact artefact bytes and that the loaded extension could return its packaged attestation.

Phase 2C addresses only that gap in a Guard-owned isolated browser. It does not replace the normal Itzako extension, inspect the user profile, promote the candidate, or prove learner behaviour. The first required evidence after a successful canary remains an authorised non-mutating current-runtime attestation readback.

The first implementation used branded Google Chrome 150. The browser process and executable were proven, but branded Chrome did not exercise the unpacked candidate. That evidence is reclassified as `BROWSER_SIDELOAD_CAPABILITY_UNSUPPORTED`, not an extension or candidate failure. The corrective run uses the Playwright-pinned Chromium revision with a persistent context.
