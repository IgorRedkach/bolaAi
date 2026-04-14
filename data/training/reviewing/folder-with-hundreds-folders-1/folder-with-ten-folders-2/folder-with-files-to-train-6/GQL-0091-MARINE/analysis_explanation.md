# Analysis Explanation
**System analysed:** HarborFlow Port API — GQL-0091 (Marine / Port Operations)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.3 (bulk/list endpoints — BOLA). `listShipments(tenantId:)` trusts client-supplied argument.
2. HAR: `listShipments(tenantId: "tenant-f744")` from `tenant-a61d`. Response `getShipment` from `tenant-f744`: `CONFIDENTIAL-a61df744`. `x-request-id: req-a61df744`.
3. Key observation: domain objects are `Shipment`/`shipmentId` with `listShipments`/`getShipment` resolvers — confirmed by HAR response body. Not generic `Resource`.

## Consistency Guard
Tenant IDs: `tenant-a61d`, `tenant-f744`. ownerId: `other-user-a61df744`. Leaked: `CONFIDENTIAL-a61df744`. Request: `req-a61df744`. All from this folder only.
