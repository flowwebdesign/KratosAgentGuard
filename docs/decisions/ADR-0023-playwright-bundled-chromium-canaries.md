# ADR-0023: Playwright-bundled Chromium canaries

Status: Accepted.

Extension canaries use the Chromium revision pinned by the project's locked Playwright version. The browser is installed below Guard `.work`, resolved through `playwright.chromium.executable_path`, and launched with `launch_persistent_context(channel="chromium")`.

Branded Google Chrome and Microsoft Edge are never used as extension-canary engines. Their executable identity can be observed, but process creation does not prove command-line unpacked-extension capability. Browser capability is evaluated before candidate runtime identity.
