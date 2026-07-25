# Controlled Builds and Untrusted Scripts

## Established technical concept
Build scripts are executable supply-chain inputs requiring explicit policy.
## Plain-language explanation
Installing dependencies can run hidden scripts with your normal environment.
## Why AI coding agents struggle
Agents treat package scripts as trusted instructions and optimise for a green build.
## Itzako example
The static extension needs no npm install, so lifecycle scripts and network are denied.
## Kratos Agent Guard implementation
The copied snapshot uses node syntax checks and deterministic internal copying.
## Trade-offs
Complex future bundling will require a separately reviewed frozen dependency plan.
## Failure modes
Running npm in the target, passing secrets, or permitting post-install hooks.
## Practical exercise
Add a postinstall script to a fixture and verify policy still denies it.
## Transfer
Apply minimal build environments to Deal Sniper workers.
## Key takeaway
A build command is untrusted code until policy proves otherwise.
