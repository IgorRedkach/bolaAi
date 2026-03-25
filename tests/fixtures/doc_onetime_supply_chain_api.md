# Supply Chain Visibility API — v3 (internal)

## Auth
Bearer token required. Scopes: `shipments.read`, `shipments.write`.

## Endpoints (no per-resource authorization described)
- **GET /api/v3/shipments/{shipmentId}** — Full shipment record (origin, destination, contents ref).
- **GET /api/v3/warehouses/{warehouseId}/inventory** — Inventory snapshot for a warehouse.
- **POST /api/v3/shipments/bulk** — Body: `{ "shipmentIds": ["s1", "s2"] }` returns details for listed IDs.
- **PATCH /api/v3/shipments/{shipmentId}/status** — Update status (in_transit, delivered). Requires `shipments.write`.

## Notes
Tenants are regional; documentation does not state that callers are restricted to their tenant’s shipments or warehouses.
