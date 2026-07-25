# ADR-0007: Passive Process Inspection

- Status: Accepted
- Decision: use psutil and strict read-only Docker commands.
- Consequence: process ownership can be proven without signals, restarts, execs,
  environment capture, or target mutation.
