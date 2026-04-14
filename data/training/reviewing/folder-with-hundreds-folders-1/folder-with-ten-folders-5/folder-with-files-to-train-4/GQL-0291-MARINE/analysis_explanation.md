# Analysis Explanation
**Folder:** GQL-0291-MARINE | **Context source:** This folder's context.txt only.
- System: HarborFlow Port API, Marine/Port Logistics
- Host: `api.harborflow-port-api.example.com`
- Attacker tenant: `tenant-162a`, victim tenant: `tenant-aed4`
- HAR request operation: `listShipments(tenantId: "tenant-aed4")` — read exploiting client-supplied tenantId
- **Inconsistency in context.txt:** §5.0 Pattern 1.6 refers to write-side `updateShipment`, but HAR shows read-side `listShipments`. Response key is `getShipment` (inconsistent with request `listShipments`). HAR is authoritative for exploit demonstration.
- Response: `ownerId: other-user-162aaed4`, `sensitiveField: CONFIDENTIAL-162aaed4`
- `x-request-id: req-162aaed4` is a server-assigned response header, not a request header
- Redis keyed by `shipmentId` only — no tenant dimension (§2.0 cache note)
- Pattern 1.6: Write BOLA without ownership check (`updateShipment`); HAR demonstrates read-side bypass via `listShipments` with client-controlled tenantId
**Consistency Guard:** All values from this folder's context.txt only.
