# Analysis Explanation
**System analysed:** MetroPulse Traffic Orchestration — GQL-0104 (Smart City / Traffic)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 5.2 (resolver/graph traversal injection). `listIntersections(tenantId:)` enables graph-level traversal across traffic management boundaries.
2. HAR: `listIntersections(tenantId: "tenant-e7c5")` from `tenant-e25b`. Response `getIntersection` from `tenant-e7c5`: `CONFIDENTIAL-e25be7c5`. `x-request-id: req-e25be7c5`.
3. Domain: `Intersection`/`nodeId`/`getIntersection`/`listIntersections` — confirmed by HAR response body.
4. Public safety: traffic control data exposure enables adversarial signal timing manipulation.

## Consistency Guard
Tenant IDs: `tenant-e25b`, `tenant-e7c5`. ownerId: `other-user-e25be7c5`. Leaked: `CONFIDENTIAL-e25be7c5`. Request: `req-e25be7c5`. All from this folder only.
