# Analysis Explanation
**System analysed:** HarvestIQ IoT Platform — GQL-0072 (Agriculture / AgriTech IoT)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.7 (nested resources without parent authorization). Child IoT items accessible without parent tenantId check.
2. HAR: `listResources(tenantId: "tenant-82f1")` from `tenant-27b6`. Response `tenant-82f1`: `CONFIDENTIAL-27b682f1`. `x-request-id: req-27b682f1`.
3. Schema §3.0: `getResourceWithChildren` returns `items: [Item!]` — nested traversal vector.
4. Pattern 1.7: authorization not re-checked at nested (child) levels after parent is fetched.

## Consistency Guard
Tenant IDs: `tenant-27b6`, `tenant-82f1`. ownerId: `other-user-27b682f1`. Leaked: `CONFIDENTIAL-27b682f1`. Request: `req-27b682f1`. All from this folder only.
