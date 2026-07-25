# ADR-0020: Browser process ownership

Status: Accepted.

Guard may close only the browser root process it launches and its proven descendants. It must never adopt or terminate an existing browser PID.
