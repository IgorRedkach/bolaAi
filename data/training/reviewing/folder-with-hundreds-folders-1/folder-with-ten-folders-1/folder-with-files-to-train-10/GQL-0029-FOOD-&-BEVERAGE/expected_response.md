# Expected Response

## System
- **Name:** TraceOrigin Supply API
- **Domain:** Food & Beverage / FMCG
- **Example ID:** GQL-0029
- **Architecture:** REST + Blockchain + GraphQL

---

## Priority Findings

### Finding 1 — GraphQL BOLA: Sequential/Predictable Resource IDs Enable Cross-Tenant Enumeration (Pattern 1.8 — Predictable or sequential IDs)
**Severity:** Critical
**Affected endpoint:** `POST https://api.traceorigin-supply-a.example.com/graphql` (mutation `bulkResourceLookup`)
**Referenced in context:** Section 4.0 (RISK-GQL-029), Section 5.0 (Pattern 1.8), HAR trace

**Summary:**
The resource IDs observed in this system follow a predictable sequential format: `R-1029`, `R-2029`, `R-3029`. Pattern 1.8 exploits this predictability — an attacker from `tenant-8f01` can enumerate resource IDs by incrementing a known value, then use `bulkResourceLookup` to probe multiple IDs in a single request.

Section 4.0 (RISK-GQL-029) confirms the underlying BOLA: the resolver fetches by `resourceId` only, with no `tenantId` predicate from the JWT. This means any guessed or enumerated ID across any tenant is accessible.

**Evidence from HAR:**
- Request header `x-tenant-id: tenant-8f01` — attacker's tenant
- Request mutation: `bulkResourceLookup(ids: ["R-2029", "R-1029", "R-3029"])` — IDs are sequential integers in the `R-NNNN` format; range R-1029 to R-3029 covers 2000+ objects across all tenants
- Response: `200 OK`, `x-request-id: req-8f019632`
- Response body: `tenantId: "tenant-9632"` — cross-tenant resource returned to `tenant-8f01`
- Response body: `sensitiveField: "CONFIDENTIAL-8f019632"` — supply chain provenance data from another tenant's object disclosed

---

### Finding 2 — Single Resource Cross-Tenant Access (Pattern 1.8 base access)
**Severity:** Critical
**Affected endpoint:** `POST https://api.traceorigin-supply-a.example.com/graphql` (query `getResource`)
**Referenced in context:** Section 4.0 (RISK-GQL-029)

**Summary:**
As documented in Section 4.0, `getResource` has the same missing authorization check. Once the attacker discovers a predictable resource ID format (e.g., `R-{number}`), they can directly query any individual object from any tenant.

---

## Evidence Map

| Artifact location | Finding 1 (Predictable ID Enumeration) | Finding 2 (Single Access) |
|---|---|---|
| Section 5.0 | Pattern 1.8 — predictable sequential IDs | Same root cause |
| Section 4.0 / RISK-GQL-029 | bulkResourceLookup unfiltered by tenant | getResource no tenantId check |
| HAR IDs | `R-2029`, `R-1029`, `R-3029` — sequential integer format | — |
| HAR x-tenant-id | `tenant-8f01` (attacker) | — |
| HAR response tenantId | `tenant-9632` — cross-tenant confirmed | — |
| HAR response data | `sensitiveField: "CONFIDENTIAL-8f019632"` — supply chain data | — |

---

## Steps to Reproduce

### Finding 1 — ID enumeration via bulk lookup (exact HAR replay)

**Step 1 — Observe ID format**
Authenticate as `tenant-8f01` and query your own resources to confirm the ID format:
```bash
curl -s -X POST https://api.traceorigin-supply-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8f01" \
  -d '{"query": "query { getResource(id: \"R-1029\") { resourceId tenantId } }"}'
```
If `resourceId` values follow `R-{integer}` format, the attacker can increment the integer to enumerate all system objects.

**Step 2 — Bulk cross-tenant enumeration (exact HAR replay)**
```bash
curl -s -X POST https://api.traceorigin-supply-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8f01" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2029\", \"R-1029\", \"R-3029\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome (confirmed by HAR):**
- Response: `200 OK`
- Response includes entry with `tenantId: "tenant-9632"` — different from the attacker's `tenant-8f01`
- `sensitiveField: "CONFIDENTIAL-8f019632"` — cross-tenant supply chain data disclosed
- The predictable ID format means an attacker can enumerate `R-1000` through `R-9999` in batches to harvest all tenants' supply chain provenance data

**Secure outcome:**
- Only entries where `tenantId = "tenant-8f01"` are returned; all cross-tenant results are filtered

---

## Remediation

1. **Replace sequential IDs with UUIDs:** Generate `resourceId` values as UUIDs (e.g., `uuid_generate_v4()`) instead of sequential integers — eliminates predictability and makes enumeration infeasible.

2. **Resolver-level tenant predicate:** All resolvers must add `AND tenant_id = $jwtTenantId` — eliminates BOLA even if IDs are guessed.

3. **Rate-limit bulk operations:** Apply per-account rate limiting on `bulkResourceLookup` (e.g., max 20 IDs per request, max 100 requests/minute per user) to slow enumeration attacks.

4. **Cache key includes tenant dimension:** Update Redis cache key from `resourceId` to `resourceId:tenantId` (per Section 2.0 note).
