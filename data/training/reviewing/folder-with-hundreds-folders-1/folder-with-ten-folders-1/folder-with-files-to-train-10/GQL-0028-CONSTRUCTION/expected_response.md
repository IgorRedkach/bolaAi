# Expected Response

## System
- **Name:** BuildCore BIM Collaboration
- **Domain:** Construction / BIM Platform
- **Example ID:** GQL-0028
- **Architecture:** REST + IFC + GraphQL

---

## Priority Findings

### Finding 1 — GraphQL BOLA: Cross-Tenant Bulk Resource Access Without Parent Authorization (Pattern 1.7 — Nested resources without parent authorization)
**Severity:** Critical
**Affected endpoint:** `POST https://api.buildcore-bim-collab.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 (RISK-GQL-028), Section 5.0 (Pattern 1.7), HAR trace

**Summary:**
The `bulkResourceLookup` mutation (Section 4.0) accepts an arbitrary array of `resourceId` values without verifying that each requested object belongs to the authenticated user's tenant. In the context of Pattern 1.7, the `bulkResourceLookup` fetches nested/child resource data (`data { sensitiveField }`) associated with parent resource IDs from any tenant — without first verifying the caller has authorization on the parent object (`tenant_id` check).

Section 4.0 (RISK-GQL-028) confirms the underlying cause: resolvers fetch by `resourceId` only, with no `tenantId` predicate check from the JWT.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-0301` — attacker's tenant
- Request mutation: `bulkResourceLookup(ids: ["R-2028", "R-1028", "R-3028"])` — mixed IDs including cross-tenant resource `R-2028`
- Response: `200 OK`, `x-request-id: req-030111f3`
- Response body: `tenantId: "tenant-11f3"` — cross-tenant resource data returned to `tenant-0301` caller
- Response body: `sensitiveField: "CONFIDENTIAL-030111f3"`, `internalNotes: "Internal data exposed"` — sensitive BIM data disclosed

---

### Finding 2 — Single Resource Cross-Tenant Access via `getResource` (Pattern 1.7 base case)
**Severity:** Critical
**Affected endpoint:** `POST https://api.buildcore-bim-collab.example.com/graphql` (query `getResource`)
**Referenced in context:** Section 4.0 (RISK-GQL-028 — `getResource` resolver does not verify `tenantId`)

**Summary:**
The `getResource` resolver (RISK-GQL-028) has the same missing `tenantId` predicate as the bulk mutation, confirmed by Section 4.0. Any attacker from `tenant-0301` can query `getResource(id: "R-2028")` and receive `tenant-11f3`'s nested resource data.

---

## Evidence Map

| Artifact location | Finding 1 (Bulk BOLA) | Finding 2 (Single BOLA) |
|---|---|---|
| Section 4.0 / RISK-GQL-028 | bulkResourceLookup lacks per-ID ownership filtering | getResource fetches by resourceId only, no tenantId check |
| Section 5.0 | Pattern 1.7 — no parent authorization check | Same root cause |
| HAR operation | `bulkResourceLookup(ids: ["R-2028", "R-1028", "R-3028"])` | — |
| HAR x-tenant-id | `tenant-0301` (attacker) | — |
| HAR response tenantId | `tenant-11f3` — cross-tenant confirmed | — |
| HAR response data | `sensitiveField: "CONFIDENTIAL-030111f3"`, `internalNotes` | — |

---

## Steps to Reproduce

### Finding 1 — Bulk cross-tenant access (exact HAR replay)

**Step 1 — Establish attacker baseline (own tenant)**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0301" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-1028\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Expected baseline:** Returns `tenantId: "tenant-0301"` — attacker's own object.

**Step 2 — Bulk lookup with cross-tenant IDs (exact HAR replay)**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0301" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2028\", \"R-1028\", \"R-3028\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body includes entries with `tenantId: "tenant-11f3"` — cross-tenant data returned
- `sensitiveField: "CONFIDENTIAL-030111f3"` — sensitive BIM data from another tenant disclosed

**Secure outcome:**
- Only the object with `tenantId: "tenant-0301"` is returned; entries for other tenants are filtered out or return null

### Finding 2 — Single resource cross-tenant access

**Step 3 — Single resource query**
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-0301" \
  -d '{"query": "query { getResource(id: \"R-2028\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome (per RISK-GQL-028):** Returns `tenantId: "tenant-11f3"` — cross-tenant data returned.
**Secure outcome:**
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getResource": null } }
```

---

## Remediation

1. **Resolver-level tenant predicate (Finding 1 + 2):** All resolvers that fetch by `resourceId` must add `AND tenant_id = $jwtTenantId` to the database query. The `tenantId` must come from the validated JWT, not from any client-supplied parameter.

2. **Bulk operation tenant filter (Finding 1):** `bulkResourceLookup` must filter the result set post-database-fetch (or via SQL `WHERE tenant_id = ANY($tenantIds)` with `$tenantIds = {jwt.tenantId}`) to ensure only the caller's own objects are returned.

3. **Cache key includes tenant dimension:** Update the Redis cache key from `resourceId` to `resourceId:tenantId` to prevent cross-tenant cache hits (per Section 2.0 note).
