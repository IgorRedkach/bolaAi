# Expected Response

## System
- **Domain:** Agriculture / Precision Farming IoT
- **System:** HarvestIQ IoT Platform
- **Example ID:** GQL-0222

## Priority Findings

### Finding 1: Agriculture IoT — BOLA via listResources Linked Resource Exposes Cross-Tenant Farm Sensor Data (Pattern 1.2)
**Severity:** High
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §4.0 (RISK-GQL-222): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.2 — related or linked resources): the `listResources` endpoint traverses linked IoT sensor nodes belonging to other tenants when a caller-supplied `tenantId` bypasses JWT ownership checks. An attacker from `tenant-497c` queried `listResources(tenantId: "tenant-2ba9")` and received farm sensor data belonging to `tenant-2ba9`, including `CONFIDENTIAL-497c2ba9`. In Agriculture / Precision Farming, unauthorized access to sensor data, crop yield records, and irrigation configurations enables agricultural espionage.

**Evidence from HAR:**
- Request: `POST https://api.harvestiq-iot-platfo.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-497c`
- Query: `listResources(tenantId: "tenant-2ba9") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-2ba9"`, `ownerId: "other-user-497c2ba9"`, `sensitiveField: "CONFIDENTIAL-497c2ba9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-497c2ba9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-222 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.2 | Related/linked resource traversal without ownership check |
| HAR query | tenantId: "tenant-2ba9" | Injected cross-tenant farm sensor filter |
| HAR response | tenantId | tenant-2ba9 returned to tenant-497c |
| HAR response | sensitiveField | CONFIDENTIAL-497c2ba9 |
| HAR header | x-request-id | req-497c2ba9 |

## Steps to Reproduce

### Step 1 — listResources linked resource BOLA agriculture (HAR)
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-497c" \
  -d '{"query": "query { listResources(tenantId: \"tenant-2ba9\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-2ba9` farm sensor data including `CONFIDENTIAL-497c2ba9`. **Secure:** FORBIDDEN — `tenantId` from JWT only.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Validate all linked IoT sensor nodes share the caller's `tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
