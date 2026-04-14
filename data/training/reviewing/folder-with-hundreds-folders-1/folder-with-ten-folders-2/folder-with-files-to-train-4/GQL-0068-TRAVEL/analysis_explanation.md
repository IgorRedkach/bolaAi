# Analysis Explanation
**System analysed:** SkyPort Global Distribution — GQL-0068 (Travel / Distribution)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.2 (related/linked resources — BOLA). Bulk lookup traverses linked resources without tenantId boundary.
2. §4.0 RISK-GQL-068: `getResource` fetches by ID only — no tenantId match.
3. HAR: `bulkResourceLookup(["R-2068","R-1068","R-3068"])` from `tenant-61f1`. Response `tenant-60f9`: `CONFIDENTIAL-61f160f9`. `x-request-id: req-61f160f9`.
4. Pattern 1.2 angle: `getResourceWithChildren` also present in schema — linked traversal is a secondary vector.

## Consistency Guard
Tenant IDs: `tenant-61f1`, `tenant-60f9`. Resources: `R-2068`, `R-1068`, `R-3068`. ownerId: `other-user-61f160f9`. Leaked: `CONFIDENTIAL-61f160f9`. Request: `req-61f160f9`. All from this folder only.
