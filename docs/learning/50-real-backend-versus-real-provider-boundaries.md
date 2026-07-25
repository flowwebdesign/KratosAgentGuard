# Lesson 50: Real backend versus real provider boundaries

## Established concept

A real API and database can be exercised while external generation remains disabled.

## Plain-language explanation

Backend persistence proof does not require spending money or contacting a provider.

## Why AI agents struggle

Agents collapse “real backend” and “real provider” into one green integration label.

## Itzako example

The locked backend uses PostgreSQL with deterministic fake generation and explicitly disables paid providers.

## Guard implementation

Reports expose backend, provider seam, external-call, cost, and normal-profile states independently.

## Trade-offs

Zero-provider proof cannot establish hosted model quality, but it safely proves routing and persistence.

## Failure modes

Hidden provider fallback, missing ledger checks, or claiming real-provider proof from fake output.

## Practical exercise

Prove a persisted fake-provider artefact while asserting zero external calls and zero cost.

## Transfer to another project

Separate storage integration from Stripe, email, search, or AI-provider integration.

## Key takeaway

Real infrastructure does not imply every dependency was real.
