# Analysis Explanation
**System analysed:** HarborFlow Port API — GQL-0141 (Marine / Port Logistics)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.10: Cross-service identity propagation drift — `listShipments` trusts client-supplied tenantId.
2. HAR: `tenant-78bd` passes `tenantId: "tenant-b825"` → `CONFIDENTIAL-78bdb825`, `req-78bdb825`.
3. Marine/Port: cargo manifests, hazmat, customs — international trade and safety compliance.

## Consistency Guard
Attacker: `tenant-78bd`. Victim: `tenant-b825`. Sensitive: `CONFIDENTIAL-78bdb825`. ownerId: `other-user-78bdb825`. Request: `req-78bdb825`. All from this folder only.
