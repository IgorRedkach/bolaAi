# Expected Response

## System
- Domain: Logistics / Supply Chain
- System: FreightLens Tracking API
- Example ID: GQL-0163

## Priority Findings

### Finding 1: Logistics — Cross-Service Identity Drift Exposes Cross-Tenant Shipment Data (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Propagation Drift

**Summary:**
Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): The identity context drifts between logistics microservices, causing `listShipments` to trust client-supplied `tenantId`. An attacker from `tenant-e796` passed `tenantId: "tenant-c3aa"` and received shipment tracking data belonging to `tenant-c3aa`, including `CONFIDENTIAL-e796c3aa`. In Logistics / Supply Chain, this exposes freight manifests, shipment routes, and supply chain partner data.

**Evidence from HAR:**
- Request: `POST https://api.freightlens-tracking.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e796`
- Query: `listShipments(tenantId: "tenant-c3aa") { shipmentId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-c3aa"`, `ownerId: "other-user-e796c3aa"`, `sensitiveField: "CONFIDENTIAL-e796c3aa"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e796c3aa`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.10 | Cross-service identity drift |
| HAR request | tenantId argument | tenant-c3aa (victim, client-supplied) |
| HAR response | tenantId | tenant-c3aa shipment data returned |
| HAR response | sensitiveField | CONFIDENTIAL-e796c3aa |

## Steps to Reproduce

### Step 1 — listShipments with drifted identity (HAR)
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e796" \
  -d '{"query": "query { listShipments(tenantId: \"tenant-c3aa\") { shipmentId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-c3aa` shipment data returned. **Secure:** Only `tenant-e796` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg; propagate identity from JWT through all service calls.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
