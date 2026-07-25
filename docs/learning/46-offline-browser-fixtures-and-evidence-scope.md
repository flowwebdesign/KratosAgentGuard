# Lesson 46: Offline browser fixtures and evidence scope

## Established concept

Intercepted browser fixtures prove deterministic client behaviour without claiming production integration.
## Plain-language explanation

Exercise the real browser shape with controlled pages and responses, then label the boundary honestly.
## Why AI agents struggle

A green browser test is often overstated as real-backend readiness.
## Itzako example

Coursera and YouTube URL shapes are fulfilled locally while the sealed extension is loaded.
## Guard implementation

The harness records fixture requests, journey results, and zero external network attempts.
## Trade-offs

Fixtures are reproducible but cannot prove hosted identity, latency, or provider behaviour.
## Failure modes

Leaking external requests or collapsing fixture proof into production proof.
## Practical exercise

Block all network and account for every intercepted request.
## Transfer

Use fixtures for OAuth callbacks, webhooks, and third-party embeds.
## Key takeaway

Offline proof is valuable precisely when its scope stays explicit.
