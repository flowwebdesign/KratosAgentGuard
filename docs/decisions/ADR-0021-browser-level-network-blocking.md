# ADR-0021: Browser-level network blocking

Status: Accepted.

Use a black-hole proxy plus browser-context interception, record all observed attempts, and fail on any external attempt. Describe this narrowly as browser-level blocking, never kernel-level isolation.
