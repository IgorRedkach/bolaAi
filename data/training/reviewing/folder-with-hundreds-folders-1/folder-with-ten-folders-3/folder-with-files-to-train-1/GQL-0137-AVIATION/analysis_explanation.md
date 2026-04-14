# Analysis Explanation
**System analysed:** AeroOps Flight Management — GQL-0137 (Aviation / Flight Ops)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.6: `listResources` accepts client-supplied `tenantId` — write BOLA.
2. HAR: `tenant-46d3` passes `tenantId: "tenant-f020"` → `CONFIDENTIAL-46d3f020`, `req-46d3f020`.
3. Aviation: flight plans, crew, NOTAM — safety-critical operational data.

## Consistency Guard
Attacker: `tenant-46d3`. Victim: `tenant-f020`. Sensitive: `CONFIDENTIAL-46d3f020`. ownerId: `other-user-46d3f020`. Request: `req-46d3f020`. All from this folder only.
