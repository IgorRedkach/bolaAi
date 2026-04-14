# Analysis Explanation
**System analysed:** ShopGrid Marketplace API — GQL-0103 (E-Commerce)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 5.1 (authorization-bypass injection). Client-supplied `tenantId` interpolated as authorization filter.
2. HAR: `listOrders(tenantId: "tenant-a32d")` from `tenant-ed5f`. Response `getOrder` from `tenant-a32d`: `CONFIDENTIAL-ed5fa32d`. `x-request-id: req-ed5fa32d`.
3. Domain: `Order`/`orderId`/`getOrder`/`listOrders` — confirmed by HAR response body.

## Consistency Guard
Tenant IDs: `tenant-ed5f`, `tenant-a32d`. ownerId: `other-user-ed5fa32d`. Leaked: `CONFIDENTIAL-ed5fa32d`. Request: `req-ed5fa32d`. All from this folder only.
