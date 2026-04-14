# Analysis Explanation
**Folder:** GQL-0263-LOGISTICS | **Context source:** This folder's context.txt only.
- System: FreightLens Tracking API, Logistics/Supply Chain
- Host: `api.freightlens-tracking.example.com`
- JWT: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG`
- x-request-id `req-cb3fba22` is a response header (not sent in request)
- HAR request operation: `bulkShipmentLookup(ids: ["S-2263","S-1263","S-3263"])` — response key: `getShipment` (INCONSISTENCY in context.txt; both faithfully documented)
- Victim tenantId: `tenant-ba22`, ownerId: `other-user-cb3fba22`, sensitiveField: `CONFIDENTIAL-cb3fba22`
- Pattern 10.2: attacker extends own session scope by supplying shipment IDs outside their tenant
- Redis cache is keyed by `shipmentId` only → no tenant isolation in cache layer
**Consistency Guard:** All values from this folder's context.txt only.
