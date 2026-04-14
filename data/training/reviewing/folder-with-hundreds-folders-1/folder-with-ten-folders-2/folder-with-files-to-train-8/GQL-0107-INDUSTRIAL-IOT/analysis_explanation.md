# Analysis Explanation
**System analysed:** ManuControl Robotics Fleet — GQL-0107 (Industrial IoT / Manufacturing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 9.1: Single GraphQL endpoint, no per-operation tenant isolation.
2. HAR: `updateResource(id: "R-2107", input: {status: "approved", ownerId: "attacker-4b769e8f"})` from `tenant-4b76` returns `tenant-9e8f` data: `CONFIDENTIAL-4b769e8f`, `x-request-id: req-4b769e8f`.
3. Industrial IoT: unauthorized mutation of robotics fleet resource creates operational safety risk.

## Consistency Guard
Attacker: `tenant-4b76`. Victim: `tenant-9e8f`. Resource: `R-2107`. Sensitive: `CONFIDENTIAL-4b769e8f`. Input ownerId: `attacker-4b769e8f`. Request: `req-4b769e8f`. All from this folder only.
