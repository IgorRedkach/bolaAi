# Analysis Explanation
**System analysed:** PowerGrid Customer Billing API — GQL-0114 (Energy / Utilities / Smart Grid)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.5: API accepts `tenantId` as filter; resolver trusts client value (not JWT), enabling cross-tenant meter access.
2. HAR: `tenant-9e2c` mutates `M-2114` with `ownerId: "attacker-9e2c14b8"` → `tenant-14b8` data: `CONFIDENTIAL-9e2c14b8`, `req-9e2c14b8`.
3. Energy/Smart Grid: billing records, energy consumption patterns — utility fraud and grid disruption risk.

## Consistency Guard
Attacker: `tenant-9e2c`. Victim: `tenant-14b8`. Resource: `M-2114`. Sensitive: `CONFIDENTIAL-9e2c14b8`. ownerId input: `attacker-9e2c14b8`. Request: `req-9e2c14b8`. All from this folder only.
