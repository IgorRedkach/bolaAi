# Expected Response

## System
- **Name:** WingTech Maintenance Portal
- **Domain:** Aerospace / MRO
- **Example ID:** GQL-0026
- **Architecture:** REST + S1000D + GraphQL

---

## Priority Findings

### Finding 1 — GraphQL BOLA: Cross-Tenant Resource Access via `getResource` Resolver (Pattern 1.5 — Multi-tenant / cross-tenant access)
**Severity:** Critical
**Affected endpoint:** `POST https://api.wingtech-maintenance.example.com/graphql` (query `getResource`)
**Referenced in context:** Section 4.0 (RISK-GQL-026), HAR trace, GraphQL schema

**Summary:**
The `getResource` resolver (Section 4.0, RISK-GQL-026) fetches objects by `resourceId` alone. It does not verify that the fetched object's `tenantId` matches the `tenantId` claim in the authenticated user's JWT. An attacker from `tenant-48ae` can query any `resourceId` including those belonging to `tenant-efd3`.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-48ae` — attacker's tenant
- Request GraphQL query: `getResource(id: "R-2026")` — resource `R-2026` belongs to `tenant-efd3`
- Response: `200 OK`
- Response body: `"tenantId": "tenant-efd3"` — **mismatch: requested by `tenant-48ae`, returned `tenant-efd3`**
- Response body: `"sensitiveField": "CONFIDENTIAL-48aeefd3"`, `"internalNotes": "Internal data exposed"` — sensitive data from another tenant's object returned

---

### Finding 2 — GraphQL BOLA: `bulkResourceLookup` Mutation Has No Per-ID Ownership Filter (Pattern 1.5 extension)
**Severity:** Critical / Mass Enumeration
**Affected endpoint:** `POST https://api.wingtech-maintenance.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 ("The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering")

**Summary:**
Section 4.0 explicitly documents that `bulkResourceLookup` accepts an arbitrary ID array without filtering against the authenticated user's `tenantId`. This allows a single GraphQL mutation to enumerate objects from multiple tenants simultaneously, amplifying the BOLA impact from single-object disclosure to mass cross-tenant data harvest.

---

### Finding 3 — Cache Poisoning Risk: Redis Cache Keyed by `resourceId` Only (Pattern 2.2 — Insecure caching)
**Severity:** High / Cache Poisoning / Cross-Tenant Data Leakage via Cache
**Affected component:** Redis cache layer
**Referenced in context:** Section 2.0 ("Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)")

**Summary:**
The Redis cache stores resource objects by `resourceId` alone (Section 2.0). If an attacker from `tenant-efd3` fetches `R-2026` first, the cache stores the full sensitive object. When a legitimate user from `tenant-efd3` subsequently requests `R-2026`, they may receive the cached response. Conversely, if the attacker from `tenant-48ae` fetches `R-2026`, the cache will store that response — and any subsequent tenant-`efd3` request will receive the cache hit without the server evaluating authorization at all.

---

## Evidence Map

| Artifact location | Finding 1 (BOLA getResource) | Finding 2 (Bulk BOLA) | Finding 3 (Cache) |
|---|---|---|---|
| Section 2.0 | — | — | `Redis cache keyed by resourceId (no user dimension)` |
| Section 4.0 | RISK-GQL-026 — resolver does not check tenantId vs JWT | bulkResourceLookup lacks per-ID filter | — |
| HAR x-tenant-id header | `tenant-48ae` (attacker) | — | — |
| HAR query | `getResource(id: "R-2026")` | — | — |
| HAR response tenantId | `tenant-efd3` — cross-tenant confirmed | — | — |
| HAR response data | sensitiveField + internalNotes from tenant-efd3 | — | — |

---

## Steps to Reproduce

### Finding 1 — Single-resource cross-tenant access

**Step 1 — Establish attacker baseline (own tenant)**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-48ae" \
  -d '{"query": "query { getResource(id: \"R-1026\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected baseline:** Returns `tenantId: "tenant-48ae"` — attacker's own resource.

**Step 2 — Cross-tenant ID substitution (exact HAR replay)**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-48ae" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2026\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response body: `"tenantId": "tenant-efd3"` — belongs to a different tenant
- Response body: `"sensitiveField": "CONFIDENTIAL-48aeefd3"`, `"internalNotes": "Internal data exposed"`
- Request correlation ID: `x-request-id: req-48aeefd3`

**Secure outcome:**
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": { "getResource": null } }
```

### Finding 2 — Bulk cross-tenant enumeration

**Step 3 — Bulk lookup via `bulkResourceLookup` mutation**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-48ae" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2026\", \"R-3026\", \"R-4026\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome (per Section 4.0):** Returns objects from multiple tenants — each item's `tenantId` will differ from the attacker's `tenant-48ae`, confirming bulk cross-tenant enumeration.
**Secure outcome:** Only resources where `tenantId = "tenant-48ae"` are returned; cross-tenant IDs are silently filtered or return null.

---

## Remediation

1. **Resolver-level tenant check (Finding 1):** Add `WHERE resource_id = $id AND tenant_id = $jwtTenantId` to every resolver that fetches by ID. The `tenantId` must be extracted from the JWT claim, never from the client-supplied request body or header.

2. **Bulk operation tenant filter (Finding 2):** In `bulkResourceLookup`, add `WHERE resource_id = ANY($ids) AND tenant_id = $jwtTenantId` — return only objects the calling tenant owns. Never return objects from other tenants regardless of whether the ID was supplied.

3. **Cache key includes user dimension (Finding 3):** Change the Redis cache key from `resourceId` to `resourceId:tenantId` (or `resourceId:userId`) so that responses are scoped per-tenant and cannot bleed across trust boundaries.
