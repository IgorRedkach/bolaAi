# Analysis Explanation

**System analysed:** ParkIQ Management API — GQL-0050 (Parking / Smart City)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 1.7 (nested resources without parent authorization). The `Intersection`/`nodeId` resolver lacks tenant enforcement.
2. **Read §3.0** — Domain-specific type: `Intersection` with `nodeId`, `listIntersections(tenantId: ID)`, `bulkIntersectionLookup`.
3. **Read §4.0** — RISK-GQL-050: `getIntersection` fetches by `nodeId` only. Cache keyed by `nodeId` only (§2.0).
4. **Read HAR** — `listIntersections(tenantId: "tenant-f5d9")` from `tenant-7b28`. Response: `CONFIDENTIAL-7b28f5d9`. `x-request-id: req-7b28f5d9`.

## Consistency Guard
- Tenant IDs: `tenant-7b28`, `tenant-f5d9`. ownerId: `other-user-7b28f5d9`. Leaked: `CONFIDENTIAL-7b28f5d9`. Request ID: `req-7b28f5d9`. All from this folder only.
