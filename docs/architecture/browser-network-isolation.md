# Browser network isolation

The canary uses defence in depth: a loopback black-hole proxy and Playwright context routing that aborts HTTP, HTTPS, and WebSocket requests. Extension-owned and browser-internal URLs remain available for inspection. Attempts are recorded and fail the canary.

This establishes `BROWSER_LEVEL_NETWORK_BLOCKING_PROVEN` only. It is not kernel-level network isolation.
