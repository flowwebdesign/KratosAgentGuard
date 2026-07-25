# Browser process and extension identity

## Established technical concept
Parentage, executable bytes, command line, profile, and extension target together establish process identity.

## Plain-language explanation
Knowing a browser opened is weaker than knowing which browser, profile, and extension path it used.

## Why AI coding agents struggle
PID and page-load success are commonly treated as sufficient identity.

Browser product and browser engine are separate evidence. A proven branded Chrome process can still lack the side-load capability required by the canary.

## Concrete Itzako example
Guard launches the exact Playwright-pinned Chromium executable with a persistent context, sealed artefact path, and fresh profile.

## Kratos Agent Guard implementation
It records parent PID, owned descendants, observed command line, executable hash, worker URL, and extension ID.

## Trade-offs
Browser subprocess trees vary across versions and operating systems.

## Failure modes
Hash drift, missing command flags, adopted PIDs, or absent extension targets block proof.

## Practical exercise
List which observations prove process creation and which prove extension loading.

## Transfer to another KratosLab project
Record executable and argument identity for worker or CLI canaries.

## Key takeaway
Process identity and loaded-component identity are linked but separate claims.
