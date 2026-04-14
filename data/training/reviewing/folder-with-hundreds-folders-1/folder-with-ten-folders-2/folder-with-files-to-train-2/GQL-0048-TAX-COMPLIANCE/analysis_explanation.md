# Analysis Explanation

**System analysed:** TaxGrid Compliance API — GQL-0048 (Tax Compliance / RegTech)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 1.5 (multi-tenant/cross-tenant). Explicit: "Token from `tenant-f137` passes `tenantId: 'tenant-8db9'` to access cross-tenant data." This names the exact tenant IDs.
2. **Read §4.0** — RISK-GQL-048 + bulkResourceLookup no per-ID filter.
3. **Read HAR** — `getResource(id: "R-2048")` from `tenant-f137`. Response `tenant-8db9`: `CONFIDENTIAL-f1378db9`. `x-request-id: req-f1378db9`.
4. **Pattern 1.5 interpretation** — The "multi-tenant" pattern is that the client-supplied `tenantId` is trusted over the JWT. Both `getResource` (HAR) and `listResources(tenantId: ...)` are attack vectors.

## Consistency Guard
- Tenant IDs: `tenant-f137`, `tenant-8db9`. Resource: `R-2048`. ownerId: `other-user-f1378db9`. Leaked: `CONFIDENTIAL-f1378db9`. Request ID: `req-f1378db9`. All from this folder only.
