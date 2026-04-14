## System

- System: FreightLens Tracking API v5.9.8
- Domain: LOGISTICS / SUPPLY CHAIN
- Example ID: GQL-0013
- Risk ID: RISK-GQL-013

## Findings

### 1. BOLA on `getShipment` — Missing `tenant_id` Filter (RISK-GQL-013)

**Primary HAR attack**: The HAR shows `getShipment(id: "S-2013")` from JWT `tenant-de82` returning a shipment belonging to `tenant-c094`. Section 4.0 (RISK-GQL-013) confirms: `getShipment` fetches by `shipmentId` without verifying the fetched object's `tenantId` against the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-de82`. Request: `getShipment(id: "S-2013")`. Response: HTTP 200 OK with `"tenantId": "tenant-c094"`, `"sensitiveField": "CONFIDENTIAL-de82c094"`, `"internalNotes": "Internal data exposed"` — a cross-tenant shipment record including internal logistics notes returned to an unauthorized caller.

**Logistics/supply chain impact**: `Shipment` objects include `waypoints: [Waypoint!]` and `data.sensitiveField` which in a freight tracking platform contains GPS route data, carrier contracts, and customs manifests. Cross-tenant access enables competitor route intelligence gathering and supply chain espionage.

### 2. Pattern 3.3 — Semantic Ambiguity on Over-Broad Endpoints

Section 5.0 describes Pattern 3.3 (Insecure Design — Semantic Ambiguity): `getShipment` and `listShipments` are over-broad endpoints that accept any `shipmentId` or `tenantId` without enforcing semantic scope to the authenticated user's tenant. The endpoints are designed to be flexible query surfaces but the implementation lacks per-call tenancy enforcement. `getShipmentWithChildren` further amplifies this by loading the entire nested object graph (`waypoints`) in a single call.

### 3. BOLA on `bulkShipmentLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkShipmentLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `shipmentId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `getShipment(id: "S-2013")` with `tenant-de82` JWT → HTTP 200 → `tenantId: tenant-c094` with `sensitiveField`.
- **Section 5.0**: Pattern 3.3 — over-broad endpoints without semantic tenancy scope.
- **Section 4.0 (RISK-GQL-013)**: `getShipment` lacks tenant check.
- **Section 4.0**: `bulkShipmentLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `shipmentId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getShipment(id: "S-1013") { shipmentId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-de82"`.

**Step 2 — Cross-tenant single shipment read (primary HAR attack):**

```graphql
query { getShipment(id: "S-2013") { shipmentId tenantId ownerId data { sensitiveField internalNotes } waypoints { lat lng } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-c094"` and full shipment including waypoints/GPS data.

**Step 3 — Over-broad endpoint: `listShipments` without tenant scope (Pattern 3.3):**

```graphql
query { listShipments(tenantId: "tenant-c094") { shipmentId tenantId status data { sensitiveField } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns only records for JWT's `tenantId`.  
Expected vulnerable: HTTP 200 with full shipment list for target tenant.

**Step 4 — Full object graph via `getShipmentWithChildren` (Pattern 3.3 amplified):**

```graphql
query { getShipmentWithChildren(id: "S-2013") { shipmentId tenantId waypoints { sequence lat lng eta } data { sensitiveField internalNotes auditLog { event timestamp } } } }
```

**Step 5 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkShipmentLookup(ids: ["S-2013", "S-3013", "S-4013"]) { shipmentId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getShipment`** (RISK-GQL-013): narrow semantic scope to authenticated user's tenant.
- **Ignore client-supplied `tenantId` in `listShipments`**: over-broad endpoint must be scoped by JWT.
- **Scope `getShipmentWithChildren` identically**: nested graph fetches must carry the same tenant filter.
- **Filter `bulkShipmentLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
