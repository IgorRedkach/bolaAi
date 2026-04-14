# Analysis Explanation
**Folder:** GQL-0313-LOGISTICS | **Context source:** This folder's context.txt only.
- System: FreightLens Tracking API (GraphQL), Logistics/Supply Chain
- Host: `api.freightlens-tracking.example.com`
- Attacker tenant: `tenant-9347`, victim tenant: `tenant-0553`
- HAR mutation: `updateShipment(id: "S-2313", input: {status: "approved", ownerId: "attacker-93470553"})`, response key: `getShipment` — **INCONSISTENCY**: HAR uses `updateShipment` mutation but response key is `getShipment`. HAR operation is authoritative.
- Response: `ownerId: "other-user-93470553"`, `sensitiveField: "CONFIDENTIAL-93470553"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `shipmentId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-93470553` is a response header (not a request header)
- Pattern 1.6: Write operations without ownership check (BOLA) — `updateShipment` accepts arbitrary `shipmentId` without ownership verification; attacker can corrupt another tenant's shipment state (status = "approved") and reassign ownership; §5.0 explicitly: "A write-level BOLA allows state corruption across tenants"
- §4.0 RISK-GQL-313: `getShipment` fetches by `shipmentId` only; `bulkShipmentLookup` lacks per-ID filtering
**Consistency Guard:** All values from this folder's context.txt only.
