# Isolated extension canary

Guard resolves the Chromium revision pinned by the locked Playwright package and installs it below `.work/playwright-browsers`. It launches that exact executable with Playwright's persistent-context API and `channel="chromium"`. Its user-data directory is created below `.work/browser-canaries/<run>/profile`; the exact sealed extension path is passed through `--load-extension` and `--disable-extensions-except`. The only starting page is `about:blank`.

The run records a whole-candidate digest at planning and compares it immediately before launch and after shutdown. Existing browser PIDs are enumerated passively and are never adopted or terminated. Runtime success requires the manifest-declared extension worker and extension-origin attestation readback, not merely process creation.

Branded Google Chrome and Microsoft Edge are discovery evidence only. They are rejected as canary engines because their product capability is distinct from the pinned Chromium engine capability.
