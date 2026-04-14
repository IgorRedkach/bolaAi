# Analysis Explanation
**System analysed:** AquaGrid Meter Management — GQL-0189 (Water Utilities / Smart Grid Infrastructure)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-189: `getResource`/`bulkResourceLookup` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 3.3: Insecure Design — semantic ambiguity; over-broad bulk endpoint allows cross-tenant meter access.
3. HAR: `tenant-a855` queries `bulkResourceLookup(ids: ["R-2189", "R-1189", "R-3189"])` → `tenant-f398` meter record: `CONFIDENTIAL-a855f398`, `req-a855f398`.
4. Water Utilities domain: meter calibration, consumption records, infrastructure topology — national infrastructure risk.

## Consistency Guard
Attacker: `tenant-a855`. Victim: `tenant-f398`. Resource: `R-2189`. Sensitive: `CONFIDENTIAL-a855f398`. ownerId: `other-user-a855f398`. Request: `req-a855f398`. All from this folder only.
