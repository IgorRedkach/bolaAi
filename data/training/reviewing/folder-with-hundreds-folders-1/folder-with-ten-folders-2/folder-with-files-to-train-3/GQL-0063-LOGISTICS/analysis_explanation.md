# Analysis Explanation
**System analysed:** FreightLens Tracking API — GQL-0063 (Logistics / Supply Chain)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 9.1 (GraphQL single endpoint vulnerabilities). All operations share one endpoint; per-operation authorization missing.
2. §4.0 RISK-GQL-063: `getShipment` resolver fetches by `shipmentId` only — no tenantId match.
3. Domain types: `Shipment`, `shipmentId`, `getShipment`, `bulkShipmentLookup` (from schema §3.0 and HAR).
4. HAR: `getShipment(id: "S-2063")` from `tenant-68a3`. Response `tenant-bfb2`: `CONFIDENTIAL-68a3bfb2`. `x-request-id: req-68a3bfb2`.
5. Single-endpoint pattern means `updateShipment` is also reachable at same URL — Step 3 demonstrates unauthorized mutation exposure.

## Consistency Guard
Tenant IDs: `tenant-68a3`, `tenant-bfb2`. Shipment: `S-2063`. ownerId: `other-user-68a3bfb2`. Leaked: `CONFIDENTIAL-68a3bfb2`. Request: `req-68a3bfb2`. All from this folder only.
