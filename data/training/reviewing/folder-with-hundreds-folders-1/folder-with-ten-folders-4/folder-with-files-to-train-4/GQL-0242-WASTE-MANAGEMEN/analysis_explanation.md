# Analysis Explanation
**System analysed:** CleanRoute IoT Platform — GQL-0242 (Waste Management / Smart Bins)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-242: `bulkResourceLookup` lacks per-ID `tenantId` check.
2. §5.0 Pattern 10.5: Single-User — draft/non-published resource access; even unpublished/draft IoT resources are queryable cross-tenant.
3. HAR: `tenant-b60d` calls `bulkResourceLookup(ids: ["R-2242","R-1242","R-3242"])` → `tenant-a96a` IoT data: `CONFIDENTIAL-b60da96a`, `req-b60da96a`.
4. Waste Management/IoT domain: route schedules, sensor configs, collection plans — competitor intelligence and route disruption risk.

## Consistency Guard
Attacker: `tenant-b60d`. Victim: `tenant-a96a`. Resources: `R-2242`, `R-1242`, `R-3242`. Sensitive: `CONFIDENTIAL-b60da96a`. ownerId: `other-user-b60da96a`. Request: `req-b60da96a`. All from this folder only.
