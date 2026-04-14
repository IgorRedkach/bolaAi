# Expected Response

## System
- Domain: Logistics / Supply Chain
- System: FreightLens Tracking API
- Example ID: GQL-0113

## Priority Findings

### Finding 1: Logistics — Bulk Shipment Endpoint Exposes Cross-Tenant Tracking Data (Pattern 1.3)
**Severity:** High
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §5.0 (Pattern 1.3 — bulk or list endpoints): The `bulkShipmentLookup` resolver accepts an arbitrary array of shipment IDs without validating that each belongs to the caller's tenant. An attacker from `tenant-6b23` submitted `updateShipment(id: "S-2113", input: {status: "approved", ownerId: "attacker-6b23551e"})` against a shipment belonging to `tenant-551e`, receiving cross-tenant freight data including `CONFIDENTIAL-6b23551e`. In Logistics / Supply Chain, this exposes confidential shipping manifests, freight contents, and route information.

**Evidence from HAR:**
- Request: `POST https://api.freightlens-tracking.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-6b23`
- Mutation: `updateShipment(id: "S-2113", input: {status: "approved", ownerId: "attacker-6b23551e"}) { shipmentId status }`
- Response `200 OK`: `tenantId: "tenant-551e"`, `ownerId: "other-user-6b23551e"`, `sensitiveField: "CONFIDENTIAL-6b23551e"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-6b23551e`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.3 | bulkShipmentLookup accepts arbitrary IDs |
| HAR request | x-tenant-id | Attacker tenant-6b23 |
| HAR request | input.ownerId | attacker-6b23551e (client-injected) |
| HAR response | tenantId | Cross-tenant tenant-551e data returned |

## Steps to Reproduce

### Step 1 — updateShipment cross-tenant (HAR)
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6b23" \
  -d '{"query": "mutation { updateShipment(id: \"S-2113\", input: {status: \"approved\", ownerId: \"attacker-6b23551e\"}) { shipmentId status } }"}'
```
**Vulnerable:** `tenant-551e` shipment mutated. **Secure:** FORBIDDEN.

## Remediation
1. `updateShipment` resolver: `WHERE shipment_id=$id AND tenant_id=$jwt.tenantId`.
2. Filter `bulkShipmentLookup` results: `WHERE shipment_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
3. Strip `ownerId` from `ShipmentInput`.
4. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
