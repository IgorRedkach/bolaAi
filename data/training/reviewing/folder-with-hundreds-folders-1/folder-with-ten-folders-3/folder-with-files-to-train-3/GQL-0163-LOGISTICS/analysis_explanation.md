# Analysis Explanation
**System analysed:** FreightLens Tracking API — GQL-0163 (Logistics / Supply Chain)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.10: Cross-service identity drift — `listShipments` trusts client-supplied tenantId.
2. HAR: `tenant-e796` passes `tenantId: "tenant-c3aa"` → `CONFIDENTIAL-e796c3aa`, `req-e796c3aa`.
3. Logistics: freight manifests, shipment routes — supply chain intelligence.

## Consistency Guard
Attacker: `tenant-e796`. Victim: `tenant-c3aa`. Sensitive: `CONFIDENTIAL-e796c3aa`. ownerId: `other-user-e796c3aa`. Request: `req-e796c3aa`. All from this folder only.
