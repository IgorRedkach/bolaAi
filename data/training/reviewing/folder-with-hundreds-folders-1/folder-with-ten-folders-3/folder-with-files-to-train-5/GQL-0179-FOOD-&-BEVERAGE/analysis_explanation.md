# Analysis Explanation
**System analysed:** TraceOrigin Supply API — GQL-0179 (Food & Beverage / Supply Chain)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-179: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.3: BOLA — bulk/list endpoints return data across tenant boundaries.
3. HAR: `tenant-3d4e` queries `getResource(id: "R-2179")` → `tenant-3a41` supply chain record: `CONFIDENTIAL-3d4e3a41`, `req-3d4e3a41`.
4. Food & Beverage domain: traceability records, supplier contracts, recall data — competitive and regulatory exposure.

## Consistency Guard
Attacker: `tenant-3d4e`. Victim: `tenant-3a41`. Resource: `R-2179`. Sensitive: `CONFIDENTIAL-3d4e3a41`. ownerId: `other-user-3d4e3a41`. Request: `req-3d4e3a41`. All from this folder only.
