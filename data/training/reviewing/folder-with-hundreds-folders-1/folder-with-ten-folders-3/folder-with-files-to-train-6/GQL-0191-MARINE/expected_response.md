# Expected Response

## System
- **Domain:** Marine / Port Operations
- **System:** HarborFlow Port API
- **Example ID:** GQL-0191

## Priority Findings

### Finding 1: Marine Port — Authorization-Bypass Injection via listShipments Exposes Cross-Tenant Shipment Data (Pattern 5.1)
**Severity:** High
**Category:** Injection / Authorization-Bypass Injection

**Summary:**
Per §4.0 (RISK-GQL-191): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 5.1 — authorization-bypass injection): the `listShipments` resolver accepts a caller-supplied `tenantId` argument that is injected into the authorization logic, bypassing the JWT-based tenant check and allowing cross-tenant shipment data access. An attacker from `tenant-804f` queried `listShipments(tenantId: "tenant-06b0")` and received shipment records belonging to `tenant-06b0`, including `CONFIDENTIAL-804f06b0`. In Marine / Port Operations, unauthorized access to cargo manifests, vessel schedules, and customs declarations poses a national security and trade compliance risk.

**Evidence from HAR:**
- Request: `POST https://api.harborflow-port-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-804f`
- Query: `listShipments(tenantId: "tenant-06b0") { shipmentId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-06b0"`, `ownerId: "other-user-804f06b0"`, `sensitiveField: "CONFIDENTIAL-804f06b0"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-804f06b0`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-191 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection via tenantId argument |
| HAR query | tenantId: "tenant-06b0" | Injected cross-tenant shipment filter |
| HAR response | tenantId | tenant-06b0 returned to tenant-804f |
| HAR response | sensitiveField | CONFIDENTIAL-804f06b0 |
| HAR header | x-request-id | req-804f06b0 |

## Steps to Reproduce

### Step 1 — listShipments authorization-bypass injection (HAR)
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-804f" \
  -d '{"query": "query { listShipments(tenantId: \"tenant-06b0\") { shipmentId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-06b0` cargo manifests including `CONFIDENTIAL-804f06b0`. **Secure:** FORBIDDEN — `tenantId` sourced from JWT; only `tenant-804f` shipments returned.

## Remediation
1. Never accept `tenantId` from client arguments; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Sanitize and validate all input arguments used in authorization logic.
3. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
