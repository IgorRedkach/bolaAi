# Expected Response

## System
- Domain: Agriculture / Precision Farming
- System: HarvestIQ IoT Platform
- Example ID: GQL-0172

## Priority Findings

### Finding 1: Agriculture IoT — Operational PII Leakage via getResource (Pattern 7.1)
**Severity:** Critical
**Category:** Logging Failures / Operational PII Leakage

**Summary:**
Per §5.0 (Pattern 7.1 — operational PII/PHI leakage): The `getResource` resolver exposes IoT operational data cross-tenant without tenancy enforcement. An attacker from `tenant-5ff5` queried `getResource(id: "R-2172")` and received precision farming data belonging to `tenant-41bd`, including `CONFIDENTIAL-5ff541bd`. In Agriculture / Precision Farming, this exposes soil sensor readings, crop yield projections, irrigation schedules, and proprietary farming techniques.

**Evidence from HAR:**
- Request: `POST https://api.harvestiq-iot-platfo.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-5ff5`
- Query: `getResource(id: "R-2172") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-41bd"`, `ownerId: "other-user-5ff541bd"`, `sensitiveField: "CONFIDENTIAL-5ff541bd"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5ff541bd`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 7.1 | Operational PII leakage, no tenancy |
| HAR request | x-tenant-id | Attacker tenant-5ff5 |
| HAR response | tenantId | Cross-tenant farm data tenant-41bd |
| HAR response | sensitiveField | CONFIDENTIAL-5ff541bd |

## Steps to Reproduce

### Step 1 — getResource operational leak (HAR)
```bash
curl -s -X POST https://api.harvestiq-iot-platfo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5ff5" \
  -d '{"query": "query { getResource(id: \"R-2172\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-41bd` farm data returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Mask `internalNotes`; restrict operational IoT telemetry to owning tenant.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
