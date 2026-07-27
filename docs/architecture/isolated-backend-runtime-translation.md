# Isolated backend runtime translation

The sealed 1.1.19 extension remains byte-identical and continues to address `http://127.0.0.1:8000`. Only the Guard-owned Playwright context translates that socket destination to `http://127.0.0.1:18000`.

Translation preserves method, body hash, path, query, ordinary headers, and original `Host` authority. Guard adds run, scenario, lease, operation, and original-origin headers only inside the isolated harness. Other external HTTP(S) requests are blocked; Coursera and YouTube pages are deterministic local fixtures.

Bundled Chromium uses a fresh Guard-owned profile. Guard records every translation, closes the browser, proves zero surviving owned processes, removes only the contained profile, releases the lease, and stops only the attested audit runtime. Normal Chrome and the canonical backend are never controlled.
