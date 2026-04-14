# Analysis Explanation
**System analysed:** StayPro Property API — GQL-0180 (Hospitality / Property Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-180: `getResource`/`bulkResourceLookup` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 1.5: BOLA — multi-tenant/cross-tenant access via bulk lookup.
3. HAR: `tenant-567f` queries `bulkResourceLookup(ids: ["R-2180", "R-1180", "R-3180"])` → `tenant-c870` property record: `CONFIDENTIAL-567fc870`, `req-567fc870`.
4. Hospitality domain: booking data, guest profiles, room rate configs — competitive and privacy breach.

## Consistency Guard
Attacker: `tenant-567f`. Victim: `tenant-c870`. Resource: `R-2180`. Sensitive: `CONFIDENTIAL-567fc870`. ownerId: `other-user-567fc870`. Request: `req-567fc870`. All from this folder only.
