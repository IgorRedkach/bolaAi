# Expected Response

## System
- Domain: Water Utilities / Smart Meters
- System: AquaGrid Meter Management
- Example ID: GQL-0039

## Priority Findings

### Finding 1: GraphQL Introspection Enabled in Production — Schema/Relationship Over-Exposure (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration

**Summary:**
Per §5.0, GraphQL introspection is enabled in production on `POST https://api.aquagrid-meter-manag.example.com/graphql`. An attacker can query `__schema` to enumerate all types, fields, and relationship paths — including `sensitiveField`, `internalNotes`, `auditLog`, and nested `items` relationships. This schema disclosure directly aids exploitation by revealing the exact field names and query/mutation signatures needed to construct cross-tenant attacks.

**Root Cause (§5.0):** "GraphQL introspection is enabled in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths that aid exploitation."

---

### Finding 2: Cross-Tenant Meter Record Access via getResource — No Tenant Boundary (BOLA + Pattern 6.1 Escalation)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `getResource(id: "R-2039")` query on `POST /graphql` returns a smart meter record belonging to `tenant-d463` when queried by an attacker from `tenant-6943`. The resolver fetches by `resourceId` only (§4.0 RISK-GQL-039) without asserting that the record's `tenantId` matches the JWT's `tenantId`. Schema introspection (Finding 1) supplies the exact field names needed to construct the exploit.

**Evidence from HAR:**
- Request: `POST https://api.aquagrid-meter-manag.example.com/graphql` (2026-04-13T16:22:34Z, 214 ms)
- JWT `x-tenant-id`: `tenant-6943` — attacker's identity
- Query payload: `getResource(id: "R-2039") { resourceId tenantId ownerId data { sensitiveField internalNotes } }` — cross-tenant ID supplied directly
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-d463` — cross-tenant meter data returned
- Response `ownerId`: `other-user-6943d463`
- Response `sensitiveField`: `CONFIDENTIAL-6943d463`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-6943d463`

**Root Cause (§4.0 RISK-GQL-039):** "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-039 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 6.1 | "introspection is enabled in production — exposes internal type names, field descriptions, sensitive relationship paths" |
| HAR entry | request.postData | `getResource(id: "R-2039")` from `tenant-6943` |
| HAR entry | response.content | `tenantId: "tenant-d463"`, `sensitiveField: "CONFIDENTIAL-6943d463"`, `internalNotes: "Internal data exposed"` |

---

### Finding 3: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Schema introspection (primary misconfiguration)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-6943" \
  -d '{"query": "{ __schema { types { name fields { name description type { name kind } } } } }"}'
```
**Vulnerable outcome:** Full schema returned including `sensitiveField`, `internalNotes`, `auditLog`, `getResource`, `bulkResourceLookup`, and all relationship paths — confirms Pattern 6.1 (introspection enabled in production).
**Secure outcome:** `{"errors": [{"message": "GraphQL introspection not allowed"}]}`.

### Step 2 — Cross-tenant meter record access (HAR attack)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-6943" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2039\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-d463"`, `ownerId: "other-user-6943d463"`, `sensitiveField: "CONFIDENTIAL-6943d463"`, `internalNotes: "Internal data exposed"` — cross-tenant meter data confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-6943" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2039\", \"R-d463-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns meter records from `tenant-d463` in bulk.
**Secure outcome:** Only own-tenant records returned; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "getResource": null }
}
```

## Remediation
1. **Disable GraphQL introspection in production:** Set `introspection: false` in Apollo Server production config. This directly closes the Pattern 6.1 misconfiguration.
2. **Resolver-level tenant guard:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` in the `getResource` resolver (§4.0 RISK-GQL-039).
3. **Remove tenantId from listResources input:** If used, derive tenant scope from JWT only.
4. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
6. **Automated regression tests:** Assert introspection returns an error; assert `tenant-6943` accessing `R-2039` returns FORBIDDEN.
