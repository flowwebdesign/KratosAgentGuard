# Process and Container Identity

## Established technical concept
Runtime identity includes the owning process or immutable container image, not
only network reachability.

## Plain-language explanation
A port says where something listens; the PID and executable say what owns it.

## Why AI coding agents struggle
Health checks are easy to obtain and tempting to overinterpret.

## Itzako example
Ports 3000, 8000, and 3011 map to processes, yet no exact artefact link exists.

## Kratos Agent Guard implementation
psutil collects passive process data and Docker commands are strictly allowlisted.

## Trade-offs
Permissions may hide executable or working-directory details.

## Failure modes
Using image tags as digests or executing commands inside containers.

## Practical exercise
Map a temporary listening socket to its PID.

## Transfer
Apply passive identity checks to Kratos Forge containers.

## Key takeaway
Reachability locates a service; provenance identifies its bytes.
