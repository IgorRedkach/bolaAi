# Expected Response

## System
- **Name:** StayPro Property API
- **Domain:** Hospitality / Hotel PMS
- **Example ID:** GQL-0030
- **Architecture:** REST + OTA standards + GraphQL

---

## Priority Findings

### Finding 1 — GraphQL BOLA: Cross-Tenant Listing via Client-Supplied `tenantId` Argument (Pattern 1.9 — Batch/bulk lookup endpoints)
**Severity:** Critical
**Affected endpoint:** `POST https://api.staypro-property-api.example.com/graphql` (query `listResources`)
**Referenced in context:** Section 4.0 (RISK-GQL-030), Section 5.0 (Pattern 1.9), HAR trace

**Summary:**
The `listResources` GraphQL query accepts a `tenantId` filter argument (Section 3.0 schema: `listResources(tenantId: ID, status: String): [Resource!]`). The resolver uses the client-supplied `tenantId` argument to filter results rather than extracting the `tenantId` from the authenticated user's JWT. This allows any authenticated user to list all resources belonging to any tenant by simply passing the victim's `tenantId` as an argument.

Section 4.0 (RISK-GQL-030) confirms the underlying issue: the resolver does not verify that the fetched object's `tenantId` matches the JWT's `tenantId`.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-3271` — attacker's tenant
- Request query: `listResources(tenantId: "tenant-ab6e")` — victim's `tenantId` passed as argument
- Response: `200 OK`, `x-request-id: req-3271ab6e`
- Response body: `tenantId: "tenant-ab6e"` — victim's property management data returned
- Response body: `sensitiveField: "CONFIDENTIAL-3271ab6e"`, `internalNotes: "Internal data exposed"` — hotel PMS data from another tenant

---

### Finding 2 — `bulkResourceLookup` Lacks Per-ID Ownership Filter (Pattern 1.9 secondary)
**Severity:** Critical
**Affected endpoint:** `POST https://api.staypro-property-api.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 and Section 5.0

**Summary:**
Section 4.0 explicitly states `bulkResourceLookup` accepts arbitrary IDs without per-ID ownership filtering, providing a second bulk enumeration vector in addition to the `listResources` argument injection.

---

## Evidence Map

| Artifact location | Finding 1 (listResources argument) | Finding 2 (bulkResourceLookup) |
|---|---|---|
| Section 3.0 schema | `listResources(tenantId: ID, ...)` — client-controlled argument | `bulkResourceLookup(ids: [ID!]!)` — unrestricted |
| Section 4.0 | RISK-GQL-030 — no tenantId check from JWT | bulkResourceLookup unfiltered |
| Section 5.0 | Pattern 1.9 — single request enumerates cross-tenant objects | — |
| HAR query | `listResources(tenantId: "tenant-ab6e")` — victim tenant supplied | — |
| HAR x-tenant-id | `tenant-3271` (attacker, different from query arg) | — |
| HAR response | `tenantId: "tenant-ab6e"`, sensitiveField | — |

---

## Steps to Reproduce

### Finding 1 — Cross-tenant listing via tenantId argument (exact HAR replay)

**Step 1 — Establish attacker baseline**
```bash
curl -s -X POST https://api.staypro-property-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3271" \
  -d '{"query": "query { listResources(tenantId: \"tenant-3271\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Expected baseline:** Returns resources where `tenantId: "tenant-3271"` — attacker's own hotel PMS data.

**Step 2 — Substitute victim tenantId (exact HAR replay)**
```bash
curl -s -X POST https://api.staypro-property-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3271" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-ab6e\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- All returned objects have `tenantId: "tenant-ab6e"` — victim hotel's complete PMS record set returned to the attacker
- `sensitiveField: "CONFIDENTIAL-3271ab6e"`, `internalNotes: "Internal data exposed"`

**Secure outcome:**
- The `tenantId` argument should be ignored (or validated against the JWT) — the resolver should always filter by `jwt.tenantId` regardless of what `tenantId` value the client supplies
- If a non-matching `tenantId` is supplied, return empty list or `403 Forbidden`

---

## Remediation

1. **Ignore client-supplied tenantId in resolvers:** Never use the `tenantId` argument value from the GraphQL query to scope data. Always use `req.user.tenantId` from the JWT. If a client-supplied `tenantId` does not match `jwt.tenantId`, either ignore it or return `403 Forbidden`.

2. **Resolver-level tenant predicate:** All resolvers must add `AND tenant_id = $jwtTenantId` to database queries — including `listResources`.

3. **Bulk filter by JWT tenant (Finding 2):** `bulkResourceLookup` must filter by `tenant_id = $jwtTenantId` after fetching.

4. **Cache key includes tenant dimension:** Update Redis cache key from `resourceId` to `resourceId:tenantId`.
